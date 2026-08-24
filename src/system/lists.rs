//! Domain list fetch, cache, parse, and suffix matching.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::config::ListSetting;
use crate::error::{Result, TunshareError};
use crate::system::run_cmd;

/// Fetch timeout so a hung GitHub doesn't stall sharing start forever.
const CURL_MAX_SECS: &str = "30";

/// Parsed domain names with suffix lookup (`shop.digikala.com` hits `digikala.com`).
#[derive(Debug, Clone, Default)]
pub struct DomainSet {
    names: HashSet<String>,
}

impl DomainSet {
    pub fn new(names: HashSet<String>) -> Self {
        Self { names }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// True if `query` equals or is a subdomain of any entry.
    pub fn contains_suffix(&self, query: &str) -> bool {
        let lowered = query.trim_end_matches('.').trim().to_ascii_lowercase();
        let mut rest = lowered.as_str();
        if rest.is_empty() {
            return false;
        }
        loop {
            if self.names.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, suffix)) if !suffix.is_empty() => rest = suffix,
                _ => return false,
            }
        }
    }
}

/// One list after fetch/parse. Empty `set` is valid (disabled, or fetch failed
/// with no cache).
#[derive(Debug, Clone, Default)]
pub struct LoadedList {
    pub set: DomainSet,
    pub last_fetch: Option<SystemTime>,
    pub used_stale: bool,
    pub errors: Vec<String>,
}

/// Load enabled sources in `setting`. Disabled URLs are skipped.
/// The job's master `enabled` flag is applied later at resolver-set time
/// so the UI can still show counts for off jobs.
///
/// Fetch failure uses the on-disk cache when present; otherwise that source
/// contributes nothing and the error is recorded. Sharing still starts.
pub async fn load_list(setting: &ListSetting, force: bool) -> LoadedList {
    let urls = setting.enabled_urls();
    if urls.is_empty() {
        return LoadedList::default();
    }

    let mut names = HashSet::new();
    let mut last_fetch: Option<SystemTime> = None;
    let mut used_stale = false;
    let mut errors = Vec::new();
    let max_age = Duration::from_secs(u64::from(setting.refresh_interval_hours) * 3600);

    let mut join_set = tokio::task::JoinSet::new();
    for url in urls {
        join_set.spawn(async move {
            let result = load_source(&url, max_age, force).await;
            (url, result)
        });
    }
    while let Some(joined) = join_set.join_next().await {
        let Ok((url, result)) = joined else { continue };
        match result {
            Ok(source) => {
                parse_list_body(&source.body, &mut names);
                last_fetch = Some(
                    last_fetch
                        .map(|t| t.max(source.fetched_at))
                        .unwrap_or(source.fetched_at),
                );
                used_stale |= source.stale;
            }
            Err(error) => {
                errors.push(format!("{url}: {error}"));
            }
        }
    }

    LoadedList {
        set: DomainSet::new(names),
        last_fetch,
        used_stale,
        errors,
    }
}

struct CachedSource {
    body: String,
    fetched_at: SystemTime,
    stale: bool,
}

async fn load_source(url: &str, max_age: Duration, force: bool) -> Result<CachedSource> {
    let path = cache_path(url)?;
    let cached = read_cache(&path);

    if !force {
        if let Some((body, fetched_at)) = cached.as_ref() {
            if fetched_at.elapsed().unwrap_or(Duration::MAX) < max_age {
                return Ok(CachedSource {
                    body: body.clone(),
                    fetched_at: *fetched_at,
                    stale: false,
                });
            }
        }
    }

    match fetch_url(url).await {
        Ok(body) => {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(error) = fs::write(&path, &body) {
                tracing::warn!("[Lists] cache write failed for <{url}>: {error}");
            }
            Ok(CachedSource {
                body,
                fetched_at: SystemTime::now(),
                stale: false,
            })
        }
        Err(error) => {
            if let Some((body, fetched_at)) = cached {
                Ok(CachedSource {
                    body,
                    fetched_at,
                    stale: true,
                })
            } else {
                Err(error)
            }
        }
    }
}

async fn fetch_url(url: &str) -> Result<String> {
    let output = run_cmd("curl", &["-fsSL", "--max-time", CURL_MAX_SECS, url]).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TunshareError::Lists(format!(
            "curl failed: {}",
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn cache_dir() -> Result<PathBuf> {
    dirs::cache_dir()
        .map(|d| d.join("tunshare").join("lists"))
        .ok_or_else(|| TunshareError::Lists("cannot resolve cache directory".into()))
}

fn cache_path(url: &str) -> Result<PathBuf> {
    Ok(cache_dir()?.join(format!("{}.txt", fnv1a_64(url.as_bytes()))))
}

fn fnv1a_64(bytes: &[u8]) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

fn read_cache(path: &PathBuf) -> Option<(String, SystemTime)> {
    let body = fs::read_to_string(path).ok()?;
    let fetched_at = fs::metadata(path).ok()?.modified().ok()?;
    Some((body, fetched_at))
}

/// Parse hosts / `domain:` / bare-name lists into `out`.
pub fn parse_list_body(body: &str, out: &mut HashSet<String>) {
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = parse_list_line(line) {
            out.insert(name);
        }
    }
}

fn parse_list_line(line: &str) -> Option<String> {
    let token = if let Some(rest) = line.strip_prefix("domain:") {
        rest.split_whitespace().next()?
    } else {
        let mut parts = line.split_whitespace();
        let first = parts.next()?;
        if looks_like_ipv4(first) || first == "::1" || first.starts_with("fe80:") {
            parts.next()?
        } else if first.contains('/') || first.contains('=') {
            return None;
        } else {
            first
        }
    };
    normalize_domain(token)
}

fn looks_like_ipv4(s: &str) -> bool {
    let mut dots = 0;
    let mut digits = 0;
    for c in s.chars() {
        if c == '.' {
            dots += 1;
            digits = 0;
        } else if c.is_ascii_digit() {
            digits += 1;
            if digits > 3 {
                return false;
            }
        } else {
            return false;
        }
    }
    dots == 3
}

fn normalize_domain(raw: &str) -> Option<String> {
    let name = raw
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('*')
        .trim_start_matches('.');
    let name = name.to_ascii_lowercase();
    if name.is_empty() || !name.contains('.') {
        return None;
    }
    if is_boilerplate(&name) {
        return None;
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(name)
}

fn is_boilerplate(name: &str) -> bool {
    matches!(
        name,
        "localhost"
            | "localhost.localdomain"
            | "local"
            | "broadcasthost"
            | "ip6-localhost"
            | "ip6-loopback"
            | "ip6-localnet"
            | "ip6-mcastprefix"
            | "ip6-allnodes"
            | "ip6-allrouters"
            | "ip6-allhosts"
            | "0.0.0.0"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hosts_skips_localhost() {
        let mut names = HashSet::new();
        parse_list_body(
            "127.0.0.1 localhost\n0.0.0.0 ads.example.com\n# comment\n0.0.0.0 tracker.io\n",
            &mut names,
        );
        assert!(names.contains("ads.example.com"));
        assert!(names.contains("tracker.io"));
        assert!(!names.contains("localhost"));
    }

    #[test]
    fn parse_domain_prefix_and_bare() {
        let mut names = HashSet::new();
        parse_list_body(
            "domain:digikala.com\nbankmellat.ir\nnot a domain\n",
            &mut names,
        );
        assert!(names.contains("digikala.com"));
        assert!(names.contains("bankmellat.ir"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn suffix_match_walks_labels() {
        let set = DomainSet::new(HashSet::from([
            "digikala.com".into(),
            "ads.google.com".into(),
        ]));
        assert!(set.contains_suffix("shop.digikala.com"));
        assert!(set.contains_suffix("DIGIKALA.COM."));
        assert!(set.contains_suffix("ads.google.com"));
        assert!(!set.contains_suffix("google.com"));
        assert!(!set.contains_suffix("notdigikala.com"));
    }

    #[test]
    fn fnv_is_stable_for_url() {
        assert_eq!(
            fnv1a_64(b"https://example.com/hosts"),
            fnv1a_64(b"https://example.com/hosts")
        );
        assert_ne!(fnv1a_64(b"a"), fnv1a_64(b"b"));
    }
}
