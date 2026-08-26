//! Packet filter (pf) firewall management.
//!
//! Sharing NAT / rdr / filter live in the named anchor `com.tunshare`.
//! MAIN only has the six hook lines so a later `pfctl -Fr` (filters) or
//! a VPN Network Extension rewrite cannot silently drop `route-to` while
//! leaving WAN NAT in place. Health re-merges the hooks.

use crate::error::{Result, TunshareError};
use crate::system::run_cmd;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command as SyncCommand;

const PF_BODY_PATH: &str = "/tmp/tunshare_pf.conf";
const PF_MAIN_PATH: &str = "/tmp/tunshare_pf_main.conf";
const DEFAULT_PF_CONF: &str = "/etc/pf.conf";
/// pf table of allowlisted destination IPs, populated by the resolver
/// before the DNS answer is sent so the first packet already matches.
pub const BYPASS_TABLE: &str = "tunshare_bypass";
pub const ANCHOR_NAME: &str = "com.tunshare";
pub const NATPMP_ANCHOR: &str = "com.tunshare/natpmp";

/// MAIN hooks. Child `/*` is required so nested `com.tunshare/natpmp` runs.
const MAIN_HOOKS: [&str; 6] = [
    "nat-anchor \"com.tunshare\"",
    "nat-anchor \"com.tunshare/*\"",
    "rdr-anchor \"com.tunshare\"",
    "rdr-anchor \"com.tunshare/*\"",
    "anchor \"com.tunshare\"",
    "anchor \"com.tunshare/*\"",
];

/// WAN hop for allowlisted destinations. Traffic to `<tunshare_bypass>`
/// is NAT'd on this iface and `route-to`'d to this gateway.
#[derive(Debug, Clone)]
pub struct BypassConfig {
    pub wan_if: String,
    pub wan_gw: Ipv4Addr,
}

/// What is actually loaded: MAIN hooks plus the `com.tunshare` body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PfContract {
    pub has_main_hooks: bool,
    pub vpn: Option<String>,
    pub lan: Option<String>,
    pub lan_ip: Option<Ipv4Addr>,
    pub wan: Option<String>,
    pub wan_gw: Option<Ipv4Addr>,
    pub has_dns_rdr: bool,
    pub has_bypass_nat: bool,
    pub has_route_to: bool,
}

impl PfContract {
    pub fn sharing_ok(&self) -> bool {
        self.has_main_hooks && self.has_dns_rdr
    }

    pub fn bypass_ok(&self) -> bool {
        self.sharing_ok() && self.has_bypass_nat && self.has_route_to
    }

    pub fn miss_message(&self, bypass_on: bool) -> Option<&'static str> {
        if bypass_on {
            if !self.has_main_hooks {
                return Some("MAIN is missing com.tunshare hooks");
            }
            if !self.has_route_to || !self.has_bypass_nat {
                return Some("WAN bypass is on but pf has no route-to / WAN NAT");
            }
            return None;
        }
        if !self.sharing_ok() {
            return Some("MAIN is missing com.tunshare hooks");
        }
        None
    }
}

/// Manages pf firewall rules for VPN sharing.
pub struct Firewall {
    /// Whether we have active rules loaded.
    rules_loaded: bool,
    /// The config file path we're using (anchor body).
    config_path: String,
}

impl Firewall {
    pub fn new() -> Self {
        Self {
            rules_loaded: false,
            config_path: PF_BODY_PATH.to_string(),
        }
    }

    /// Six MAIN hook lines. Tests and merge share this list.
    pub fn main_hooks() -> &'static [&'static str] {
        &MAIN_HOOKS
    }

    /// Anchor body: scrub, table, NAT, DNS rdr, filter. No MAIN hooks.
    pub fn generate_rules(
        vpn_if: &str,
        lan_if: &str,
        lan_ip: Ipv4Addr,
        mss: u16,
        bypass: Option<&BypassConfig>,
    ) -> String {
        let (wan_macro, table_line, vpn_nat, extra_nat, extra_filter, wan_scrub) = match bypass {
            Some(b) => (
                format!("wan_if = \"{}\"\nwan_gw = \"{}\"\n", b.wan_if, b.wan_gw),
                format!("table <{BYPASS_TABLE}> persist\n"),
                format!(
                    "nat on $ext_if inet from $int_if:network to ! <{BYPASS_TABLE}> -> ($ext_if) static-port"
                ),
                format!(
                    "nat on $wan_if inet from $int_if:network to <{BYPASS_TABLE}> -> ($wan_if) static-port\n"
                ),
                format!(
                    "pass in quick on $int_if route-to ($wan_if $wan_gw) inet from $int_if:network to <{BYPASS_TABLE}> keep state\npass out quick on $wan_if inet from ($wan_if) to any keep state\n"
                ),
                format!(
                    "scrub out on $wan_if inet proto tcp from $int_if:network to any max-mss {mss}\n"
                ),
            ),
            None => (
                String::new(),
                String::new(),
                "nat on $ext_if inet from $int_if:network to any -> ($ext_if) static-port"
                    .to_string(),
                String::new(),
                String::new(),
                String::new(),
            ),
        };

        format!(
            r#"# tunshare anchor body — {ANCHOR_NAME}
# VPN interface: {vpn_if}
# LAN interface: {lan_if}

ext_if = "{vpn_if}"
int_if = "{lan_if}"
{wan_macro}{table_line}
scrub in all no-df
scrub out on $ext_if inet proto tcp from $int_if:network to any max-mss {mss}
{wan_scrub}
{vpn_nat}
{extra_nat}rdr on $int_if inet proto udp from $int_if:network to any port 53 -> {lan_ip}
rdr on $int_if inet proto tcp from $int_if:network to any port 53 -> {lan_ip}

{extra_filter}pass quick on $int_if all keep state
pass out quick on $ext_if inet from ($ext_if) to any keep state
"#
        )
    }

    /// MAIN fragment: skip lo0 plus the six hooks. Idempotent merge uses this
    /// after stripping leftover tunshare lines from a snapshot.
    pub fn generate_main_hooks() -> String {
        let mut out = String::from("set skip on lo0\n");
        for hook in Self::main_hooks() {
            out.push_str(hook);
            out.push('\n');
        }
        out
    }

    pub fn merge_main(existing: &str) -> String {
        if remaining_main_is_empty(existing) {
            return Self::generate_main_hooks();
        }
        merge_main(existing)
    }

    pub fn contract_from_text(main: &str, body: &str) -> PfContract {
        let mut pf = parse_pf(body);
        pf.has_main_hooks = main_hooks_present(main);
        // Body macros win; fall back to MAIN only for hook detection.
        if !pf.has_dns_rdr {
            let from_main = parse_pf(main);
            if pf.lan.is_none() {
                pf.lan = from_main.lan;
            }
            if pf.lan_ip.is_none() {
                pf.lan_ip = from_main.lan_ip;
            }
            pf.has_dns_rdr = from_main.has_dns_rdr;
            pf.has_bypass_nat = pf.has_bypass_nat || from_main.has_bypass_nat;
            pf.has_route_to = pf.has_route_to || from_main.has_route_to;
            if pf.wan.is_none() {
                pf.wan = from_main.wan;
            }
            if pf.wan_gw.is_none() {
                pf.wan_gw = from_main.wan_gw;
            }
            if pf.vpn.is_none() {
                pf.vpn = from_main.vpn;
            }
        }
        pf
    }

    /// Validate an anchor-body file as `com.tunshare`, not MAIN.
    pub async fn validate_rules(config_path: &str) -> Result<()> {
        validate_pfctl(&["-a", ANCHOR_NAME, "-n", "-f", config_path]).await
    }

    /// Load the anchor body and re-merge MAIN hooks.
    ///
    /// `mss` is the IPv4 TCP MSS clamp for the scrub rule. Caller is
    /// expected to derive it from the active upstream's MTU
    /// (`ActiveUpstream::mss_v4()`) so the clamp tracks the tunnel.
    pub async fn load_rules(
        &mut self,
        vpn_if: &str,
        lan_if: &str,
        lan_ip: Ipv4Addr,
        mss: u16,
        bypass: Option<&BypassConfig>,
    ) -> Result<()> {
        restore_contract(vpn_if, lan_if, lan_ip, mss, bypass, &self.config_path).await?;
        self.rules_loaded = true;
        Ok(())
    }

    /// Same as `load_rules` without a `Firewall` handle. Health heal uses
    /// this so we do not steal managers from the session.
    pub async fn restore_contract(
        vpn_if: &str,
        lan_if: &str,
        lan_ip: Ipv4Addr,
        mss: u16,
        bypass: Option<&BypassConfig>,
    ) -> Result<()> {
        restore_contract(vpn_if, lan_if, lan_ip, mss, bypass, PF_BODY_PATH).await
    }

    /// MAIN + `com.tunshare` NAT/filter. Status and debug both need both.
    pub async fn get_current_rules() -> Result<String> {
        let main = snapshot_main_async().await?;
        let body = snapshot_anchor_async().await?;
        Ok(join_blocks(&main, &body))
    }

    pub async fn inspect_live() -> Result<PfContract> {
        let main = snapshot_main_async().await?;
        let body = snapshot_anchor_async().await?;
        Ok(Self::contract_from_text(&main, &body))
    }

    /// Get current pf states (for debugging).
    pub async fn get_current_states() -> Result<String> {
        let output = run_cmd("pfctl", &["-ss"]).await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Check if pf is enabled.
    pub async fn is_enabled() -> Result<bool> {
        let output = run_cmd("pfctl", &["-si"]).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains("Status: Enabled"))
    }

    /// Stop sharing: flush nested then parent, strip MAIN hooks.
    pub async fn cleanup(&mut self) -> Result<()> {
        let config_path = self.config_path.clone();
        tokio::task::spawn_blocking(move || cleanup_sync_impl(&config_path))
            .await
            .map_err(|e| TunshareError::CommandFailed {
                command: "cleanup (spawn_blocking)".into(),
                message: e.to_string(),
            })??;

        self.rules_loaded = false;
        Ok(())
    }

    /// Synchronous cleanup for use in Drop and async wrapper.
    pub fn cleanup_sync(&mut self) {
        let _ = cleanup_sync_impl(&self.config_path);
        self.rules_loaded = false;
    }

    /// Insert IPv4s into the bypass table. No-op on empty. Must complete
    /// before the resolver returns the matching A records.
    pub fn table_add(ips: &[Ipv4Addr]) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let mut args = vec![
            "-a".into(),
            ANCHOR_NAME.into(),
            "-t".to_string(),
            BYPASS_TABLE.to_string(),
            "-T".into(),
            "add".into(),
        ];
        args.extend(ips.iter().map(|ip| ip.to_string()));
        pfctl_table(&args)
    }

    /// Drop IPv4s from the bypass table (TTL eviction).
    pub fn table_delete(ips: &[Ipv4Addr]) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let mut args = vec![
            "-a".into(),
            ANCHOR_NAME.into(),
            "-t".to_string(),
            BYPASS_TABLE.to_string(),
            "-T".into(),
            "delete".into(),
        ];
        args.extend(ips.iter().map(|ip| ip.to_string()));
        pfctl_table(&args)
    }

    /// Flush the bypass table. Best-effort: missing table is not an error.
    /// Heal must not call this.
    pub fn table_flush() {
        let _ = SyncCommand::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-t", BYPASS_TABLE, "-T", "flush"])
            .output();
    }

    /// Addresses currently in `<tunshare_bypass>`. `None` when the table
    /// is missing (bypass rules were never loaded).
    pub fn table_show() -> Result<Option<Vec<Ipv4Addr>>> {
        let output = SyncCommand::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-t", BYPASS_TABLE, "-T", "show"])
            .output()
            .map_err(|error| TunshareError::CommandFailed {
                command: format!("pfctl -t {BYPASS_TABLE} -T show"),
                message: error.to_string(),
            })?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            if stderr.to_ascii_lowercase().contains("does not exist")
                || stderr.to_ascii_lowercase().contains("no such table")
            {
                return Ok(None);
            }
            if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                return Err(TunshareError::PermissionDenied);
            }
            return Err(TunshareError::FirewallError(format!(
                "pfctl -T show failed: {}",
                stderr.trim()
            )));
        }
        let ips = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<Ipv4Addr>().ok())
            .collect();
        Ok(Some(ips))
    }
}

fn pfctl_table(args: &[String]) -> Result<()> {
    let output = SyncCommand::new("pfctl")
        .args(args)
        .output()
        .map_err(|error| TunshareError::CommandFailed {
            command: "pfctl table".into(),
            message: error.to_string(),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TunshareError::FirewallError(format!(
            "pfctl -T failed: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        if self.rules_loaded {
            self.cleanup_sync();
        }
    }
}

async fn restore_contract(
    vpn_if: &str,
    lan_if: &str,
    lan_ip: Ipv4Addr,
    mss: u16,
    bypass: Option<&BypassConfig>,
    body_path: &str,
) -> Result<()> {
    let body = Firewall::generate_rules(vpn_if, lan_if, lan_ip, mss, bypass);
    fs::write(body_path, &body).map_err(TunshareError::Io)?;

    let _ = run_cmd("pfctl", &["-e"]).await;

    Firewall::validate_rules(body_path).await?;
    load_pfctl(&["-a", ANCHOR_NAME, "-f", body_path]).await?;

    let existing = snapshot_main_async().await.unwrap_or_default();
    let merged = Firewall::merge_main(&existing);
    fs::write(PF_MAIN_PATH, &merged).map_err(TunshareError::Io)?;
    validate_pfctl(&["-n", "-f", PF_MAIN_PATH]).await?;
    load_pfctl(&["-f", PF_MAIN_PATH]).await?;
    Ok(())
}

async fn load_pfctl(args: &[&str]) -> Result<()> {
    let output = run_cmd("pfctl", args).await?;
    interpret_pfctl(&output, "Failed to load rules")
}

async fn validate_pfctl(args: &[&str]) -> Result<()> {
    let output = run_cmd("pfctl", args).await?;
    interpret_pfctl(&output, "Rule validation failed")
}

fn interpret_pfctl(output: &std::process::Output, prefix: &str) -> Result<()> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if pfctl_syntax_error(&stderr) || (!output.status.success() && !pfctl_f_warning_only(&stderr)) {
        return Err(TunshareError::FirewallError(format!(
            "{prefix}: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

fn pfctl_syntax_error(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("syntax error")
        || lower.contains("rules not loaded")
        || lower.contains("rules must be in order")
}

fn pfctl_f_warning_only(stderr: &str) -> bool {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return true;
    }
    trimmed.lines().all(|line| {
        let line = line.trim();
        line.is_empty()
            || line.contains("Use of -f option")
            || line.contains("No ALTQ support")
            || line.contains("ALTQ related functions disabled")
            || line.contains("pf enabled")
            || line.contains("rules loaded")
    })
}

async fn snapshot_main_async() -> Result<String> {
    let nat = run_cmd("pfctl", &["-sn"]).await?;
    let filter = run_cmd("pfctl", &["-sr"]).await?;
    Ok(join_blocks(
        &String::from_utf8_lossy(&nat.stdout),
        &String::from_utf8_lossy(&filter.stdout),
    ))
}

async fn snapshot_anchor_async() -> Result<String> {
    let nat = run_cmd("pfctl", &["-a", ANCHOR_NAME, "-sn"]).await?;
    let filter = run_cmd("pfctl", &["-a", ANCHOR_NAME, "-sr"]).await?;
    Ok(join_blocks(
        &String::from_utf8_lossy(&nat.stdout),
        &String::from_utf8_lossy(&filter.stdout),
    ))
}

fn join_blocks(a: &str, b: &str) -> String {
    match (a.trim().is_empty(), b.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => a.to_string(),
        (true, false) => b.to_string(),
        (false, false) => format!("{a}\n{b}"),
    }
}

fn snapshot_main_sync() -> String {
    let nat = SyncCommand::new("pfctl")
        .args(["-sn"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let filter = SyncCommand::new("pfctl")
        .args(["-sr"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    join_blocks(&nat, &filter)
}

fn flush_anchor_sync(name: &str) {
    let _ = SyncCommand::new("pfctl")
        .args(["-a", name, "-F", "all"])
        .output();
}

/// MAIN after stripping leftover tunshare lines, plus skip + hooks.
///
/// Apple pf requires section order: options → normalization → translation →
/// filtering. `pfctl -sr` dumps `scrub-anchor` with filters, so a naive
/// split puts it after `nat-anchor` and `-f` rejects the file at line 10.
fn merge_main(existing: &str) -> String {
    let buckets = bucket_main_lines(existing);
    assemble_main(&buckets, true)
}

/// Same buckets as merge, without tunshare hooks. Stop uses this so we do
/// not re-inject `com.tunshare` while putting Apple `scrub-anchor` first.
fn order_main(existing: &str) -> String {
    let buckets = bucket_main_lines(existing);
    assemble_main(&buckets, false)
}

struct MainBuckets {
    options: String,
    scrub: String,
    queue: String,
    nat: String,
    filter: String,
}

fn bucket_main_lines(existing: &str) -> MainBuckets {
    let mut buckets = MainBuckets {
        options: String::from("set skip on lo0\n"),
        scrub: String::new(),
        queue: String::new(),
        nat: String::new(),
        filter: String::new(),
    };
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_tunshare_main_line(trimmed) {
            continue;
        }
        let dest = match classify_main_line(trimmed) {
            MainSection::Options => &mut buckets.options,
            MainSection::Scrub => &mut buckets.scrub,
            MainSection::Queue => &mut buckets.queue,
            MainSection::Nat => &mut buckets.nat,
            MainSection::Filter => &mut buckets.filter,
        };
        dest.push_str(trimmed);
        dest.push('\n');
    }
    buckets
}

fn assemble_main(buckets: &MainBuckets, inject_hooks: bool) -> String {
    let mut out = buckets.options.clone();
    out.push_str(&buckets.scrub);
    out.push_str(&buckets.queue);
    if inject_hooks {
        for hook in &Firewall::main_hooks()[..4] {
            out.push_str(hook);
            out.push('\n');
        }
    }
    out.push_str(&buckets.nat);
    if inject_hooks {
        for hook in &Firewall::main_hooks()[4..] {
            out.push_str(hook);
            out.push('\n');
        }
    }
    out.push_str(&buckets.filter);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainSection {
    Options,
    Scrub,
    Queue,
    Nat,
    Filter,
}

fn classify_main_line(line: &str) -> MainSection {
    if line.starts_with("set ") {
        MainSection::Options
    } else if line.starts_with("scrub ") || line.starts_with("scrub-anchor ") {
        MainSection::Scrub
    } else if line.starts_with("dummynet")
        || line.starts_with("altq ")
        || line.starts_with("queue ")
    {
        MainSection::Queue
    } else if line.starts_with("nat ")
        || line.starts_with("rdr ")
        || line.starts_with("binat ")
        || line.starts_with("nat-anchor ")
        || line.starts_with("rdr-anchor ")
        || line.starts_with("binat-anchor ")
    {
        MainSection::Nat
    } else {
        MainSection::Filter
    }
}

fn is_tunshare_main_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    if trimmed == "set skip on lo0" {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("com.tunshare") || lower.contains("tunshare_bypass") {
        return true;
    }
    if (trimmed.contains("rdr-anchor")
        || trimmed.contains("nat-anchor")
        || trimmed.starts_with("anchor "))
        && trimmed.contains("natpmp")
    {
        return true;
    }
    let is_dns_rdr =
        lower.contains("rdr") && (lower.contains("port 53") || lower.contains("port = 53"));
    if is_dns_rdr {
        return true;
    }
    if lower.contains("route-to") && lower.contains("keep state") {
        return true;
    }
    false
}

fn main_hooks_present(text: &str) -> bool {
    let lower = text.to_ascii_lowercase().replace('\'', "\"");
    line_has(&lower, "nat-anchor", false)
        && line_has(&lower, "nat-anchor", true)
        && line_has(&lower, "rdr-anchor", false)
        && line_has(&lower, "rdr-anchor", true)
        && filter_hook(&lower, false)
        && filter_hook(&lower, true)
}

fn line_has(lower: &str, kind: &str, child: bool) -> bool {
    lower.lines().any(|line| {
        let line = line.trim();
        if !line.contains(kind) || !line.contains("com.tunshare") {
            return false;
        }
        line.contains('*') == child
    })
}

fn filter_hook(lower: &str, child: bool) -> bool {
    lower.lines().any(|line| {
        let line = line.trim();
        if line.contains("nat-anchor") || line.contains("rdr-anchor") {
            return false;
        }
        if !line.contains("anchor") || !line.contains("com.tunshare") {
            return false;
        }
        line.contains('*') == child
    })
}

pub(crate) fn parse_pf(text: &str) -> PfContract {
    let mut pf = PfContract {
        has_main_hooks: main_hooks_present(text),
        ..PfContract::default()
    };
    parse_pf_macros(text, &mut pf);
    let expanded = expand_pf_macros(text);
    for line in expanded.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("rdr ") {
            if let Some((iface, ip)) = parse_dns_rdr(rest) {
                pf.lan = Some(iface);
                pf.lan_ip = Some(ip);
                pf.has_dns_rdr = true;
            }
        } else if let Some(rest) = line.strip_prefix("nat on ") {
            parse_nat_line(rest, &mut pf);
        } else if line.contains("route-to") && line.contains("tunshare_bypass") {
            pf.has_route_to = true;
            if let Some((iface, gw)) = parse_route_to(line) {
                pf.wan = Some(iface);
                pf.wan_gw = Some(gw);
            }
        }
    }
    pf
}

fn parse_pf_macros(text: &str, pf: &mut PfContract) {
    for line in text.lines() {
        let trimmed = line.trim();
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if name.contains(' ') || value.is_empty() {
            continue;
        }
        match name {
            "ext_if" if pf.vpn.is_none() => pf.vpn = Some(value),
            "int_if" if pf.lan.is_none() => pf.lan = Some(value),
            "wan_if" if pf.wan.is_none() => pf.wan = Some(value),
            "wan_gw" if pf.wan_gw.is_none() => pf.wan_gw = value.parse().ok(),
            _ => {}
        }
    }
}

fn expand_pf_macros(text: &str) -> String {
    let mut out = text.to_string();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if name.is_empty() || value.is_empty() || name.contains(' ') {
            continue;
        }
        out = out.replace(&format!("${name}"), &value);
    }
    out
}

fn parse_dns_rdr(rest: &str) -> Option<(String, Ipv4Addr)> {
    if !rest.contains("port") || !rest.contains("53") {
        return None;
    }
    let iface = iface_after_on(rest)?;
    let ip = rest
        .rsplit("->")
        .next()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((iface, ip))
}

fn parse_nat_line(rest: &str, pf: &mut PfContract) {
    let Some(iface) = rest.split_whitespace().next().map(str::to_string) else {
        return;
    };
    let to_bypass =
        rest.contains("to <tunshare_bypass>") || rest.contains("to < tunshare_bypass >");
    let to_not_bypass = rest.contains("to ! <tunshare_bypass>") || rest.contains("to ! <");
    if to_bypass && !to_not_bypass {
        pf.has_bypass_nat = true;
        pf.wan = Some(iface);
    } else if pf.vpn.is_none() {
        pf.vpn = Some(iface);
    }
}

fn parse_route_to(line: &str) -> Option<(String, Ipv4Addr)> {
    let rest = line.split("route-to").nth(1)?;
    let inner = rest.split('(').nth(1)?.split(')').next()?.trim();
    let mut parts = inner.split_whitespace();
    let iface = parts.next()?.to_string();
    let gw = parts.next()?.parse().ok()?;
    Some((iface, gw))
}

fn iface_after_on(text: &str) -> Option<String> {
    let mut parts = text.split_whitespace();
    while let Some(tok) = parts.next() {
        if tok == "on" {
            return parts.next().map(str::to_string);
        }
    }
    None
}

fn remaining_main_is_empty(text: &str) -> bool {
    text.lines().all(|line| {
        let trimmed = line.trim();
        trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed == "set skip on lo0"
            || is_tunshare_main_line(trimmed)
    })
}

/// Standalone sync cleanup. Flush nested then parent, strip MAIN hooks.
/// `/etc/pf.conf` only if leftover MAIN has no foreign rules.
fn cleanup_sync_impl(config_path: &str) -> Result<()> {
    let mut errors = Vec::new();

    flush_anchor_sync(NATPMP_ANCHOR);
    flush_anchor_sync(ANCHOR_NAME);

    let existing = snapshot_main_sync();
    let stripped: String = existing
        .lines()
        .filter(|line| !is_tunshare_main_line(line) && line.trim() != "set skip on lo0")
        .map(|line| format!("{}\n", line.trim()))
        .collect();

    if remaining_main_is_empty(&stripped) {
        if Path::new(DEFAULT_PF_CONF).exists() {
            let output = SyncCommand::new("pfctl")
                .args(["-f", DEFAULT_PF_CONF])
                .output();
            if let Ok(output) = output {
                if let Err(error) = interpret_pfctl(&output, "Failed to restore default rules") {
                    errors.push(error.to_string());
                }
            }
        }
    } else {
        let ordered = order_main(&stripped);
        let _ = fs::write(PF_MAIN_PATH, &ordered);
        let output = SyncCommand::new("pfctl")
            .args(["-f", PF_MAIN_PATH])
            .output();
        if let Ok(output) = output {
            if let Err(error) = interpret_pfctl(&output, "Failed to strip MAIN hooks") {
                errors.push(error.to_string());
            }
        }
    }

    Firewall::table_flush();

    if Path::new(config_path).exists() {
        if let Err(e) = fs::remove_file(config_path) {
            errors.push(format!("Failed to remove config file: {e}"));
        }
    }
    if Path::new(PF_MAIN_PATH).exists() {
        let _ = fs::remove_file(PF_MAIN_PATH);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(TunshareError::FirewallError(errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bypass() -> BypassConfig {
        BypassConfig {
            wan_if: "en0".into(),
            wan_gw: Ipv4Addr::new(192, 168, 1, 1),
        }
    }

    #[test]
    fn generate_rules_always_redirects_dns() {
        let rules =
            Firewall::generate_rules("utun10", "en8", Ipv4Addr::new(192, 168, 2, 1), 1400, None);
        assert!(rules.contains(
            "rdr on $int_if inet proto udp from $int_if:network to any port 53 -> 192.168.2.1"
        ));
        assert!(rules.contains(
            "rdr on $int_if inet proto tcp from $int_if:network to any port 53 -> 192.168.2.1"
        ));
        assert!(rules
            .contains("nat on $ext_if inet from $int_if:network to any -> ($ext_if) static-port"));
        assert!(!rules.contains("tunshare_bypass"));
        assert!(!rules.contains("route-to"));
        assert!(!rules.contains("rdr-anchor"));
        assert!(!rules.contains("anchor \"natpmp\""));
        assert!(!rules.contains("anchor \"com.tunshare\""));
    }

    #[test]
    fn generate_rules_bypass_uses_wan_not_lan() {
        let rules = Firewall::generate_rules(
            "utun10",
            "en8",
            Ipv4Addr::new(192, 168, 2, 1),
            1400,
            Some(&bypass()),
        );
        assert!(rules.contains("table <tunshare_bypass> persist"));
        assert!(rules.contains("wan_if = \"en0\""));
        assert!(rules.contains("wan_gw = \"192.168.1.1\""));
        assert!(rules.contains("to ! <tunshare_bypass>"));
        assert!(rules.contains("nat on $wan_if inet from $int_if:network to <tunshare_bypass>"));
        assert!(rules.contains(
            "pass in quick on $int_if route-to ($wan_if $wan_gw) inet from $int_if:network to <tunshare_bypass> keep state"
        ));
        assert!(rules.contains(
            "scrub out on $wan_if inet proto tcp from $int_if:network to any max-mss 1400"
        ));
        assert!(!rules.contains("to <tunshare_bypass> route-to"));
        assert!(!rules.contains("route-to ($int_if"));
    }

    #[test]
    fn main_hooks_are_six_and_named() {
        let hooks = Firewall::main_hooks();
        assert_eq!(hooks.len(), 6);
        assert!(hooks.contains(&"nat-anchor \"com.tunshare\""));
        assert!(hooks.contains(&"nat-anchor \"com.tunshare/*\""));
        assert!(hooks.contains(&"rdr-anchor \"com.tunshare\""));
        assert!(hooks.contains(&"rdr-anchor \"com.tunshare/*\""));
        assert!(hooks.contains(&"anchor \"com.tunshare\""));
        assert!(hooks.contains(&"anchor \"com.tunshare/*\""));
        let text = Firewall::generate_main_hooks();
        assert!(main_hooks_present(&text));
    }

    #[test]
    fn merge_main_strips_legacy_nat_and_injects_hooks() {
        let existing = r#"
nat on utun4 inet from 192.168.2.0/24 to ! <tunshare_bypass> -> (utun4) round-robin static-port
nat on en0 inet from 192.168.2.0/24 to <tunshare_bypass> -> (en0) round-robin static-port
rdr on en8 inet proto udp from 192.168.2.0/24 to any port = 53 -> 192.168.2.1
nat on utun4 inet from 10.0.0.0/8 to any -> (utun4) static-port
pass in quick on en8 route-to (en0 192.0.2.1) inet from 192.168.2.0/24 to <tunshare_bypass> keep state
pass in quick on en8 proto tcp from any to any port 443 keep state
"#;
        let merged = Firewall::merge_main(existing);
        for hook in MAIN_HOOKS {
            assert!(merged.contains(hook), "missing {hook}");
        }
        assert!(merged.contains("nat on utun4 inet from 10.0.0.0/8"));
        assert!(merged.contains("pass in quick on en8 proto tcp"));
        assert!(!merged.contains("tunshare_bypass"));
        assert!(!merged.contains("port = 53"));
        assert!(!merged.contains("route-to (en0"));
        assert!(merged.contains("set skip on lo0"));
        let second = Firewall::merge_main(&merged);
        assert_eq!(
            second.matches("nat-anchor \"com.tunshare\"").count(),
            1,
            "hooks must stay unique on re-merge"
        );
    }

    #[test]
    fn merge_main_keeps_apple_scrub_anchor_before_nat() {
        let existing = r#"
scrub-anchor "com.apple/*" all
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
anchor "com.apple/*"
dummynet-anchor "com.apple/*"
"#;
        let merged = Firewall::merge_main(existing);
        let line_at = |needle: &str| -> usize {
            merged
                .lines()
                .scan(0usize, |offset, line| {
                    let start = *offset;
                    *offset += line.len() + 1;
                    Some((start, line))
                })
                .find(|(_, line)| *line == needle)
                .map(|(start, _)| start)
                .unwrap_or_else(|| panic!("missing {needle}"))
        };
        let scrub = line_at("scrub-anchor \"com.apple/*\" all");
        let nat_hook = line_at("nat-anchor \"com.tunshare\"");
        let apple_nat = line_at("nat-anchor \"com.apple/*\"");
        let filter_hook = line_at("anchor \"com.tunshare\"");
        let apple_filter = line_at("anchor \"com.apple/*\"");
        assert!(scrub < nat_hook, "scrub must precede translation");
        assert!(nat_hook < apple_nat);
        assert!(apple_nat < filter_hook);
        assert!(filter_hook < apple_filter);
        let dummy = merged.find("dummynet-anchor").expect("dummynet");
        assert!(dummy < nat_hook, "queueing must precede translation");
        let stopped = order_main(existing);
        assert!(!stopped.contains("com.tunshare"));
        assert!(stopped.find("scrub-anchor").unwrap() < stopped.find("nat-anchor").unwrap());
        assert!(stopped.find("dummynet-anchor").unwrap() < stopped.find("nat-anchor").unwrap());
    }

    #[test]
    fn pfctl_warning_does_not_hide_syntax_error() {
        let stderr = "\
Use of -f option, could result in flushing of rules
present in the main ruleset added by the system at startup.
See /etc/pf.conf for further details.
No ALTQ support in kernel
ALTQ related functions disabled
/tmp/tunshare_pf_main.conf:10: Rules must be in order: options, normalization, queueing, translation, filtering
pfctl: Syntax error in config file: pf rules not loaded
";
        assert!(pfctl_syntax_error(stderr));
        assert!(!pfctl_f_warning_only(stderr));
        let warning_only = "\
Use of -f option, could result in flushing of rules
No ALTQ support in kernel
ALTQ related functions disabled
";
        assert!(pfctl_f_warning_only(warning_only));
        assert!(!pfctl_syntax_error(warning_only));
    }

    #[test]
    fn unhooked_main_plus_intact_body_is_not_bypass_ok() {
        let body = Firewall::generate_rules(
            "utun4",
            "en8",
            Ipv4Addr::new(192, 168, 2, 1),
            1400,
            Some(&bypass()),
        );
        let main =
            "nat on en0 inet from 192.168.2.0/24 to <tunshare_bypass> -> (en0) static-port\n";
        let pf = Firewall::contract_from_text(main, &body);
        assert!(pf.has_dns_rdr);
        assert!(pf.has_bypass_nat);
        assert!(pf.has_route_to);
        assert!(!pf.has_main_hooks);
        assert!(!pf.bypass_ok());
        assert_eq!(
            pf.miss_message(true),
            Some("MAIN is missing com.tunshare hooks")
        );
    }

    #[test]
    fn hooked_main_plus_body_is_bypass_ok() {
        let body = Firewall::generate_rules(
            "utun4",
            "en8",
            Ipv4Addr::new(192, 168, 2, 1),
            1400,
            Some(&bypass()),
        );
        let main = Firewall::generate_main_hooks();
        let pf = Firewall::contract_from_text(&main, &body);
        assert!(pf.has_main_hooks);
        assert!(pf.bypass_ok());
        assert_eq!(pf.wan_gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(pf.miss_message(true).is_none());
    }

    #[test]
    fn is_tunshare_main_line_does_not_eat_foreign_nat() {
        assert!(is_tunshare_main_line(
            "nat on en0 inet from 192.168.2.0/24 to <tunshare_bypass> -> (en0) static-port"
        ));
        assert!(!is_tunshare_main_line(
            "nat on utun4 inet from 10.0.0.0/8 to any -> (utun4) static-port"
        ));
        assert!(is_tunshare_main_line(r#"anchor "com.tunshare""#));
        assert!(is_tunshare_main_line(r#"anchor "natpmp""#));
    }
}
