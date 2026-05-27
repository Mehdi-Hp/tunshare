//! Per-interface byte counters via `netstat -ibn`.
//!
//! The output has one summary row per interface (with `<Link#N>` in the
//! Network column) plus one row per assigned address. The summary row holds
//! the kernel's cumulative `Ibytes`/`Obytes`, which is what we want.

use crate::error::{Result, TunshareError};
use crate::system::run_cmd;

/// Cumulative byte counters for an interface since boot.
///
/// `ibytes` is bytes received on the interface; `obytes` is bytes sent.
/// From the VPN's perspective, `ibytes` corresponds to traffic flowing toward
/// LAN clients (download) and `obytes` to traffic leaving from them (upload).
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceBytes {
    pub ibytes: u64,
    pub obytes: u64,
}

/// Read cumulative byte counters for the named interface.
pub async fn read_interface_bytes(iface: &str) -> Result<InterfaceBytes> {
    let output = run_cmd("netstat", &["-ibn", "-I", iface]).await?;
    if !output.status.success() {
        return Err(TunshareError::CommandFailed {
            command: format!("netstat -ibn -I {iface}"),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_netstat_ibn(&stdout, iface).ok_or_else(|| TunshareError::CommandFailed {
        command: format!("netstat -ibn -I {iface}"),
        message: "no summary row for interface".into(),
    })
}

/// Find the `<Link#N>` summary row for `iface` and pull ibytes/obytes from it.
///
/// The summary row has no Address field, so it's 10 columns wide instead of
/// 11. After whitespace-splitting:
///   0=Name 1=Mtu 2=Network(<Link#N>) 3=Ipkts 4=Ierrs 5=Ibytes
///   6=Opkts 7=Oerrs 8=Obytes 9=Coll
fn parse_netstat_ibn(stdout: &str, iface: &str) -> Option<InterfaceBytes> {
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // The interface name may have a trailing `*` when marked down — strip
        // it before comparing so `utun4` matches a `utun4*` row too.
        let name = fields[0].trim_end_matches('*');
        if name != iface {
            continue;
        }
        if !fields[2].starts_with("<Link#") {
            continue;
        }
        let ibytes = fields[5].parse::<u64>().ok()?;
        let obytes = fields[8].parse::<u64>().ok()?;
        return Some(InterfaceBytes { ibytes, obytes });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                        451844     0 2854541159   451844     0 2854541159     0
lo0        16384 127           127.0.0.1         451844     - 2854541159   451844     - 2854541159     -
utun4      1400  <Link#22>                       123456     0  987654321    65432     0  111222333     0
utun4      1400  10.0.0/24   10.0.0.2            123456     -  987654321    65432     -  111222333     -
";

    #[test]
    fn parses_summary_row() {
        let b = parse_netstat_ibn(SAMPLE, "utun4").expect("found");
        assert_eq!(b.ibytes, 987_654_321);
        assert_eq!(b.obytes, 111_222_333);
    }

    #[test]
    fn returns_none_for_missing_interface() {
        assert!(parse_netstat_ibn(SAMPLE, "en9").is_none());
    }

    #[test]
    fn skips_address_rows() {
        // Confirms we don't accidentally match the address row (which has a
        // `10.0.0/24` in column 3 instead of `<Link#...>`).
        let b = parse_netstat_ibn(SAMPLE, "lo0").expect("found");
        assert_eq!(b.ibytes, 2_854_541_159);
    }
}
