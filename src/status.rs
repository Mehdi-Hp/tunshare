//! Live sharing inspect (`tunshare status`).
//!
//! Infers session state from process + pf + prefs + list cache. No IPC.

use std::net::Ipv4Addr;
use std::process::{self, Command};
use std::time::{Duration, SystemTime};

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;

use crate::config::Config;
use crate::error::{Result, TunshareError};
use crate::system::lists::LoadedList;
use crate::system::{load_cached_list, Firewall, IpForwarding};

const LABEL_WIDTH: usize = 16;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Block,
    Allow,
    Vpn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharingState {
    Running,
    TuiIdle,
    Leftover,
    Stopped,
    NeedRoot,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LivePf {
    vpn: Option<String>,
    lan: Option<String>,
    lan_ip: Option<Ipv4Addr>,
    wan: Option<String>,
    wan_gw: Option<Ipv4Addr>,
    has_dns_rdr: bool,
    has_bypass_nat: bool,
    has_route_to: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckOutcome {
    Ok,
    Mismatch,
    ProbeFailed,
}

pub async fn run_status_cli(args: Vec<String>) -> Result<()> {
    let check = parse_status_args(&args)?;
    let snapshot = gather().await;
    print_snapshot(&snapshot);

    if let Some(name) = check {
        let outcome = run_check(&snapshot, &name).await;
        process::exit(match outcome {
            CheckOutcome::Ok => 0,
            CheckOutcome::Mismatch => 1,
            CheckOutcome::ProbeFailed => 2,
        });
    }

    process::exit(snapshot.exit_code());
}

fn parse_status_args(args: &[String]) -> Result<Option<String>> {
    match args {
        [] => Ok(None),
        [flag, name] if flag == "--check" => {
            let name = name.trim();
            if name.is_empty() {
                return Err(TunshareError::ParseError(
                    "status --check needs a domain name".into(),
                ));
            }
            Ok(Some(name.to_string()))
        }
        [flag] if flag == "--check" => Err(TunshareError::ParseError(
            "status --check needs a domain name".into(),
        )),
        [other, ..] => Err(TunshareError::ParseError(format!(
            "unknown argument: {other}"
        ))),
    }
}

struct Snapshot {
    pids: Vec<u32>,
    pf: Option<LivePf>,
    pf_error: Option<String>,
    table: Option<Vec<Ipv4Addr>>,
    table_error: Option<String>,
    forwarding: Option<bool>,
    config: Config,
    block_cache: LoadedList,
    allow_cache: LoadedList,
}

impl Snapshot {
    fn sharing_state(&self) -> SharingState {
        sharing_state(
            !self.pids.is_empty(),
            self.pf.as_ref().map(|pf| pf.has_dns_rdr),
        )
    }

    fn mismatches(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.pf.is_none() {
            out.push(self.pf_error.clone().unwrap_or_else(|| "need root".into()));
            return out;
        }
        match self.sharing_state() {
            SharingState::TuiIdle => {
                out.push("TUI is up, sharing has not started".into());
            }
            SharingState::Leftover => {
                out.push("tunshare NAT is loaded but no tunshare process (leftover rules)".into());
            }
            SharingState::Running => {
                if self.config.lists.allow.enabled {
                    if let Some(pf) = self.pf.as_ref() {
                        if !pf.has_bypass_nat || !pf.has_route_to {
                            out.push(
                                "WAN bypass is on in prefs but pf has no route-to / WAN NAT".into(),
                            );
                        }
                        if pf.wan.is_none() {
                            out.push("WAN bypass is on but no WAN uplink in loaded rules".into());
                        }
                        if self.table.is_none() && self.table_error.is_none() {
                            out.push(
                                "WAN bypass is on but <tunshare_bypass> table is missing".into(),
                            );
                        }
                    }
                }
            }
            SharingState::Stopped | SharingState::NeedRoot => {}
        }
        if self.pf.is_some() {
            if let Some(error) = &self.table_error {
                out.push(error.clone());
            }
        }
        out
    }

    fn exit_code(&self) -> i32 {
        if self.mismatches().is_empty() {
            0
        } else {
            1
        }
    }
}

async fn gather() -> Snapshot {
    let pids = tunshare_pids();
    let config = Config::load();
    let block_cache = load_cached_list(&config.lists.block);
    let allow_cache = load_cached_list(&config.lists.allow);

    let mut pf = None;
    let mut pf_error = None;
    match load_live_pf().await {
        Ok(parsed) => pf = Some(parsed),
        Err(TunshareError::PermissionDenied) => pf_error = Some("need root".into()),
        Err(error) => pf_error = Some(error.to_string()),
    }

    let mut table = None;
    let mut table_error = None;
    match Firewall::table_show() {
        Ok(ips) => table = ips,
        Err(TunshareError::PermissionDenied) => table_error = Some("need root".into()),
        Err(error) => table_error = Some(error.to_string()),
    }

    let forwarding = IpForwarding::new().get_state().await.ok();

    Snapshot {
        pids,
        pf,
        pf_error,
        table,
        table_error,
        forwarding,
        config,
        block_cache,
        allow_cache,
    }
}

async fn load_live_pf() -> Result<LivePf> {
    // Non-root pfctl often returns empty stdout; don't treat that as "stopped".
    if !is_root() {
        return Err(TunshareError::PermissionDenied);
    }
    let nat = Firewall::get_current_rules().await.map_err(map_pf_perm)?;
    Ok(parse_pf(&nat))
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn map_pf_perm(error: TunshareError) -> TunshareError {
    let text = error.to_string();
    if text.contains("Permission denied") || text.contains("Operation not permitted") {
        TunshareError::PermissionDenied
    } else {
        error
    }
}

fn tunshare_pids() -> Vec<u32> {
    let output = Command::new("pgrep").args(["-x", "tunshare"]).output();
    let Ok(output) = output else {
        return Vec::new();
    };
    let self_pid = process::id();
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|pid| pid.parse::<u32>().ok())
        .filter(|pid| *pid != self_pid)
        .collect()
}

fn print_snapshot(snapshot: &Snapshot) {
    let state = snapshot.sharing_state();
    let sharing = match state {
        SharingState::Running => {
            let pid = snapshot
                .pids
                .first()
                .map(|pid| format!("pid {pid}"))
                .unwrap_or_else(|| "pid ?".into());
            format!("running   {pid}")
        }
        SharingState::TuiIdle => {
            let pid = snapshot
                .pids
                .first()
                .map(|pid| format!("pid {pid}"))
                .unwrap_or_default();
            format!("TUI up, sharing not started   {pid}")
        }
        SharingState::Leftover => "leftover NAT (no process)".into(),
        SharingState::Stopped => "stopped".into(),
        SharingState::NeedRoot => {
            if snapshot.pids.is_empty() {
                "unknown   need root for pf".into()
            } else {
                let pid = snapshot.pids[0];
                format!("process pid {pid}   need root for pf")
            }
        }
    };
    row("Sharing", sharing);

    match snapshot.pf.as_ref() {
        Some(pf) => {
            row("VPN", pf.vpn.clone().unwrap_or_else(|| "—".into()));
            let lan = match (pf.lan.as_ref(), pf.lan_ip) {
                (Some(name), Some(ip)) => format!("{name}       {ip}"),
                (Some(name), None) => name.clone(),
                (None, Some(ip)) => ip.to_string(),
                (None, None) => "—".into(),
            };
            row("LAN", lan);
            let wan = match (pf.wan.as_ref(), pf.wan_gw) {
                (Some(iface), Some(gw)) => format!("{iface} via {gw}"),
                (Some(iface), None) => iface.clone(),
                _ => "—".into(),
            };
            row("WAN", wan);
        }
        None => {
            let note = snapshot.pf_error.as_deref().unwrap_or("unavailable");
            row("VPN", note.to_string());
            row("LAN", note.to_string());
            row("WAN", note.to_string());
        }
    }

    println!();
    row(
        "Block",
        job_line(
            snapshot.config.lists.block.enabled,
            snapshot.config.lists.block.sources.len(),
            snapshot
                .config
                .lists
                .block
                .sources
                .iter()
                .filter(|s| s.enabled)
                .count(),
            snapshot.block_cache.last_fetch,
        ),
    );
    row(
        "WAN bypass",
        job_line(
            snapshot.config.lists.allow.enabled,
            snapshot.config.lists.allow.sources.len(),
            snapshot
                .config
                .lists
                .allow
                .sources
                .iter()
                .filter(|s| s.enabled)
                .count(),
            snapshot.allow_cache.last_fetch,
        ),
    );

    println!();
    println!("pf");
    match snapshot.pf.as_ref() {
        Some(pf) => {
            let nat = if pf.has_dns_rdr {
                match pf.lan_ip {
                    Some(ip) => format!("loaded   rdr :53 → {ip}"),
                    None => "loaded   rdr :53".into(),
                }
            } else {
                "not loaded".into()
            };
            indent("NAT", nat);
            let bypass = if pf.has_bypass_nat || pf.has_route_to {
                let count = snapshot
                    .table
                    .as_ref()
                    .map(|ips| format!("{} addrs", ips.len()))
                    .unwrap_or_else(|| {
                        snapshot
                            .table_error
                            .clone()
                            .unwrap_or_else(|| "table missing".into())
                    });
                let route = match pf.wan.as_deref() {
                    Some(iface) if pf.has_route_to => format!("route-to {iface}"),
                    _ if pf.has_route_to => "route-to loaded".into(),
                    _ => "no route-to".into(),
                };
                format!("table {count}   {route}")
            } else {
                "off".into()
            };
            indent("bypass", bypass);
        }
        None => {
            let note = snapshot.pf_error.as_deref().unwrap_or("unavailable");
            indent("NAT", note.to_string());
            indent("bypass", note.to_string());
        }
    }
    let forwarding = match snapshot.forwarding {
        Some(true) => "on".into(),
        Some(false) => "off".into(),
        None => snapshot
            .pf_error
            .clone()
            .unwrap_or_else(|| "unavailable".into()),
    };
    indent("forwarding", forwarding);

    for hint in snapshot.mismatches() {
        println!();
        println!("hint: {hint}");
    }
}

fn job_line(enabled: bool, total: usize, on: usize, fetched: Option<SystemTime>) -> String {
    let state = if enabled { "On" } else { "Off" };
    format!(
        "{state}    {on}/{total} sources   cache {}",
        cache_age(fetched)
    )
}

fn cache_age(when: Option<SystemTime>) -> String {
    let Some(when) = when else {
        return "none".into();
    };
    let Ok(age) = SystemTime::now().duration_since(when) else {
        return "just now".into();
    };
    let secs = age.as_secs();
    if secs < 60 {
        "just now".into()
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

fn row(label: &str, value: String) {
    println!("{label:<LABEL_WIDTH$} {value}");
}

fn indent(label: &str, value: String) {
    println!("  {label:<14} {value}");
}

fn classify(
    qname: &str,
    block: &LoadedList,
    allow: &LoadedList,
    block_on: bool,
    allow_on: bool,
) -> Decision {
    let name = qname.trim_end_matches('.');
    if block_on && block.set.contains_suffix(name) {
        return Decision::Block;
    }
    if allow_on && allow.set.contains_suffix(name) {
        return Decision::Allow;
    }
    Decision::Vpn
}

fn listed(qname: &str, list: &LoadedList) -> bool {
    list.set.contains_suffix(qname.trim_end_matches('.'))
}

async fn run_check(snapshot: &Snapshot, name: &str) -> CheckOutcome {
    let block_on = snapshot.config.lists.block.enabled;
    let allow_on = snapshot.config.lists.allow.enabled;
    let on_block = listed(name, &snapshot.block_cache);
    let on_allow = listed(name, &snapshot.allow_cache);

    if !on_block && !on_allow {
        println!();
        println!("{name} is on neither Block nor WAN bypass (enabled sources).");
        println!("hint: wrong name, not a bypass bug");
        return CheckOutcome::Mismatch;
    }

    let decision = classify(
        name,
        &snapshot.block_cache,
        &snapshot.allow_cache,
        block_on,
        allow_on,
    );
    match decision {
        Decision::Vpn => {
            println!();
            if on_allow && !allow_on {
                println!("{name} is on WAN bypass, but the job is Off.");
                println!("hint: WAN bypass master is off in prefs");
            } else if on_block && !block_on {
                println!("{name} is on Block, but the job is Off.");
                println!("hint: Block master is off in prefs");
            } else {
                println!("{name} classifies as VPN-path (not Block / WAN bypass).");
            }
            CheckOutcome::Mismatch
        }
        Decision::Block | Decision::Allow => {
            if snapshot.sharing_state() != SharingState::Running {
                println!();
                println!("Sharing is not on. --check needs the live LAN resolver.");
                return CheckOutcome::Mismatch;
            }
            let Some(lan_ip) = snapshot.pf.as_ref().and_then(|pf| pf.lan_ip) else {
                println!();
                println!("Need the live rdr target (LAN IP) to probe. Need root?");
                return CheckOutcome::Mismatch;
            };
            match lookup_a(lan_ip, name).await {
                Ok(LookupResult::NxDomain) => {
                    if decision == Decision::Block {
                        println!();
                        println!("{name} → NXDOMAIN (Block)");
                        CheckOutcome::Ok
                    } else {
                        println!();
                        println!("{name} → NXDOMAIN (expected WAN-bypass A records)");
                        println!("hint: Block overrode, or WAN resolver failed");
                        CheckOutcome::ProbeFailed
                    }
                }
                Ok(LookupResult::Addrs(ips)) => {
                    if decision == Decision::Block {
                        println!();
                        println!("{name} → {} (expected NXDOMAIN)", format_ips(&ips));
                        CheckOutcome::ProbeFailed
                    } else {
                        verify_bypass_table(snapshot, name, &ips)
                    }
                }
                Err(error) => {
                    println!();
                    println!("{name} lookup failed: {error}");
                    CheckOutcome::ProbeFailed
                }
            }
        }
    }
}

fn verify_bypass_table(snapshot: &Snapshot, name: &str, ips: &[Ipv4Addr]) -> CheckOutcome {
    println!();
    println!("{name} → {}", format_ips(ips));
    let Some(table) = snapshot.table.as_ref() else {
        println!("hint: <tunshare_bypass> table is missing (bypass rules not loaded)");
        return CheckOutcome::ProbeFailed;
    };
    let missing: Vec<_> = ips
        .iter()
        .filter(|ip| !table.contains(ip))
        .copied()
        .collect();
    if missing.is_empty() {
        println!("pf table contains {}", format_ips(ips));
        CheckOutcome::Ok
    } else {
        println!(
            "hint: {} not in <tunshare_bypass> (resolver did not add before answer)",
            format_ips(&missing)
        );
        CheckOutcome::ProbeFailed
    }
}

fn format_ips(ips: &[Ipv4Addr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

enum LookupResult {
    NxDomain,
    Addrs(Vec<Ipv4Addr>),
}

async fn lookup_a(lan_ip: Ipv4Addr, name: &str) -> Result<LookupResult> {
    let resolver = lan_resolver(lan_ip)?;
    let qname = name.trim_end_matches('.');
    let lookup = tokio::time::timeout(PROBE_TIMEOUT, resolver.lookup(qname, RecordType::A)).await;
    match lookup {
        Err(_) => Err(TunshareError::Resolver(format!(
            "lookup of <{qname}> timed out"
        ))),
        Ok(Ok(response)) => {
            let ips: Vec<Ipv4Addr> = response
                .answers()
                .iter()
                .filter_map(|record| match record.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect();
            if ips.is_empty() {
                Err(TunshareError::Resolver(format!(
                    "no A records for <{qname}>"
                )))
            } else {
                Ok(LookupResult::Addrs(ips))
            }
        }
        Ok(Err(error)) => {
            if is_nxdomain(&error) {
                Ok(LookupResult::NxDomain)
            } else {
                Err(TunshareError::Resolver(error.to_string()))
            }
        }
    }
}

fn is_nxdomain(error: &impl std::fmt::Display) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("nxdomain") || text.contains("norecordsfound") || text.contains("no record")
}

fn lan_resolver(lan_ip: Ipv4Addr) -> Result<Resolver<TokioRuntimeProvider>> {
    let udp = ConnectionConfig::udp();
    let tcp = ConnectionConfig::tcp();
    let name_servers = vec![NameServerConfig::new(
        std::net::IpAddr::V4(lan_ip),
        true,
        vec![udp, tcp],
    )];
    let mut config = ResolverConfig::default();
    config.name_servers = name_servers;
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().ndots = 0;
    builder
        .build()
        .map_err(|error| TunshareError::Resolver(error.to_string()))
}

fn parse_pf(text: &str) -> LivePf {
    let mut pf = LivePf::default();
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

fn parse_pf_macros(text: &str, pf: &mut LivePf) {
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

fn parse_nat_line(rest: &str, pf: &mut LivePf) {
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

fn sharing_state(has_tui: bool, has_rdr: Option<bool>) -> SharingState {
    match (has_tui, has_rdr) {
        (_, None) => SharingState::NeedRoot,
        (true, Some(true)) => SharingState::Running,
        (true, Some(false)) => SharingState::TuiIdle,
        (false, Some(true)) => SharingState::Leftover,
        (false, Some(false)) => SharingState::Stopped,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::lists::DomainSet;
    use crate::system::{BypassConfig, Firewall};
    use std::collections::HashSet;

    fn loaded(names: &[&str]) -> LoadedList {
        LoadedList {
            set: DomainSet::new(names.iter().map(|s| s.to_string()).collect::<HashSet<_>>()),
            last_fetch: None,
            used_stale: false,
            errors: Vec::new(),
        }
    }

    #[test]
    fn parse_generated_bypass_rules() {
        let bypass = BypassConfig {
            wan_if: "en0".into(),
            wan_gw: Ipv4Addr::new(192, 168, 1, 1),
        };
        let rules = Firewall::generate_rules(
            "utun10",
            "en8",
            Ipv4Addr::new(192, 168, 2, 1),
            1400,
            Some(&bypass),
        );
        let pf = parse_pf(&rules);
        assert_eq!(pf.vpn.as_deref(), Some("utun10"));
        assert_eq!(pf.lan.as_deref(), Some("en8"));
        assert_eq!(pf.lan_ip, Some(Ipv4Addr::new(192, 168, 2, 1)));
        assert_eq!(pf.wan.as_deref(), Some("en0"));
        assert_eq!(pf.wan_gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(pf.has_dns_rdr);
        assert!(pf.has_bypass_nat);
        assert!(pf.has_route_to);
    }

    #[test]
    fn parse_generated_rules_without_bypass() {
        let rules =
            Firewall::generate_rules("utun10", "en8", Ipv4Addr::new(192, 168, 2, 1), 1400, None);
        let pf = parse_pf(&rules);
        assert_eq!(pf.vpn.as_deref(), Some("utun10"));
        assert!(pf.has_dns_rdr);
        assert!(!pf.has_bypass_nat);
        assert!(!pf.has_route_to);
        assert!(pf.wan.is_none());
    }

    #[test]
    fn parse_pfctl_expanded_bypass() {
        let nat = r#"
nat on utun10 inet from 192.168.2.0/24 to ! <tunshare_bypass> -> (utun10) static-port
nat on en0 inet from 192.168.2.0/24 to <tunshare_bypass> -> (en0) static-port
rdr on en8 inet proto udp from 192.168.2.0/24 to any port = 53 -> 192.168.2.1
"#;
        let filter = r#"
pass in quick on en8 route-to (en0 192.168.1.1) inet from 192.168.2.0/24 to <tunshare_bypass> keep state
"#;
        let pf = parse_pf(&format!("{nat}\n{filter}"));
        assert_eq!(pf.vpn.as_deref(), Some("utun10"));
        assert_eq!(pf.lan.as_deref(), Some("en8"));
        assert_eq!(pf.lan_ip, Some(Ipv4Addr::new(192, 168, 2, 1)));
        assert_eq!(pf.wan.as_deref(), Some("en0"));
        assert_eq!(pf.wan_gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(pf.has_route_to);
        assert!(pf.has_bypass_nat);
    }

    #[test]
    fn classify_block_wins_and_respects_flags() {
        let block = loaded(&["ads.example.com"]);
        let allow = loaded(&["example.com"]);
        assert_eq!(
            classify("ads.example.com", &block, &allow, true, true),
            Decision::Block
        );
        assert_eq!(
            classify("shop.example.com", &block, &allow, true, true),
            Decision::Allow
        );
        assert_eq!(
            classify("shop.example.com", &block, &allow, true, false),
            Decision::Vpn
        );
        assert!(listed("shop.example.com", &allow));
        assert!(!listed("google.com", &allow));
    }

    #[test]
    fn sharing_state_from_process_and_rdr() {
        assert_eq!(sharing_state(true, Some(true)), SharingState::Running);
        assert_eq!(sharing_state(true, Some(false)), SharingState::TuiIdle);
        assert_eq!(sharing_state(false, Some(true)), SharingState::Leftover);
        assert_eq!(sharing_state(false, Some(false)), SharingState::Stopped);
        assert_eq!(sharing_state(true, None), SharingState::NeedRoot);
    }

    #[test]
    fn parse_status_args_accepts_check() {
        let name = parse_status_args(&["--check".into(), "digikala.com".into()]).unwrap();
        assert_eq!(name.as_deref(), Some("digikala.com"));
        assert!(parse_status_args(&[]).unwrap().is_none());
        assert!(parse_status_args(&["--check".into()]).is_err());
        assert!(parse_status_args(&["--json".into()]).is_err());
    }
}
