//! In-process DNS server for LAN clients.
//!
//! Binds the LAN IPv4 on :53 (UDP + TCP). Decision tree:
//! block suffix → NXDOMAIN; allow suffix → WAN gateway :53 (BoundIf), then
//! pf table add, then answer; else → VPN-path upstream (`custom` or 1.1.1.1).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::Resolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, RwLock};
use tokio::time::interval;

use crate::error::{Result, TunshareError};
use crate::system::bound_if::BoundIfProvider;
use crate::system::firewall::Firewall;
use crate::system::lists::DomainSet;
use crate::system::WanUplink;

/// Flat pf-table lifetime. Real DNS TTLs are a later-bead nicety.
const BYPASS_TTL: Duration = Duration::from_secs(3600);
const EVICT_TICK: Duration = Duration::from_secs(60);
const UDP_BUF: usize = 4096;

/// Live matching state, swapped on toggle/refresh without rebinding :53.
#[derive(Clone, Default)]
pub struct ResolverLists {
    pub block: DomainSet,
    pub allow: DomainSet,
    pub block_enabled: bool,
    pub allow_enabled: bool,
}

pub struct DnsServer {
    shutdown_tx: watch::Sender<bool>,
    lists: Arc<RwLock<ResolverLists>>,
    wan_upstream: Arc<std::sync::RwLock<Option<Resolver<BoundIfProvider>>>>,
    blocked_queries: Arc<AtomicU64>,
}

impl DnsServer {
    /// Bind LAN:53 and spawn UDP/TCP/evict tasks. Fails if :53 is taken.
    pub async fn start(
        lan_ip: Ipv4Addr,
        vpn_dns: Vec<String>,
        wan: Option<&WanUplink>,
        lists: ResolverLists,
    ) -> Result<Self> {
        let bind = SocketAddrV4::new(lan_ip, 53);
        let udp = UdpSocket::bind(bind)
            .await
            .map_err(|error| TunshareError::Resolver(format!("bind UDP {bind}: {error}")))?;
        let tcp = TcpListener::bind(SocketAddr::from(bind))
            .await
            .map_err(|error| TunshareError::Resolver(format!("bind TCP {bind}: {error}")))?;

        let vpn_upstream = build_vpn_resolver(&vpn_dns)?;
        let wan_resolver = match wan {
            Some(wan) => Some(build_wan_resolver(wan)?),
            None => None,
        };
        let wan_upstream = Arc::new(std::sync::RwLock::new(wan_resolver));

        let lists = Arc::new(RwLock::new(lists));
        let bypass = Arc::new(tokio::sync::Mutex::new(HashMap::<Ipv4Addr, Instant>::new()));
        let blocked_queries = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let shared = Arc::new(ServerInner {
            lists: lists.clone(),
            vpn_upstream,
            wan_upstream: wan_upstream.clone(),
            bypass: bypass.clone(),
            blocked_queries: blocked_queries.clone(),
        });

        tokio::spawn(udp_loop(udp, shared.clone(), shutdown_rx.clone()));
        tokio::spawn(tcp_loop(tcp, shared.clone(), shutdown_rx.clone()));
        tokio::spawn(evict_loop(bypass, shutdown_rx));

        Ok(Self {
            shutdown_tx,
            lists,
            wan_upstream,
            blocked_queries,
        })
    }

    pub fn lists(&self) -> Arc<RwLock<ResolverLists>> {
        self.lists.clone()
    }

    /// DNS queries answered NXDOMAIN this session because they hit Block.
    pub fn blocked_queries(&self) -> u64 {
        self.blocked_queries.load(Ordering::Relaxed)
    }

    /// Bind a WAN-path resolver. Needed when allowlist turns on after sharing started.
    pub fn attach_wan(&self, wan: &WanUplink) -> Result<()> {
        let resolver = build_wan_resolver(wan)?;
        let mut slot = self
            .wan_upstream
            .write()
            .map_err(|_| TunshareError::Resolver("WAN resolver lock poisoned".into()))?;
        *slot = Some(resolver);
        Ok(())
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ServerInner {
    lists: Arc<RwLock<ResolverLists>>,
    vpn_upstream: Resolver<TokioRuntimeProvider>,
    wan_upstream: Arc<std::sync::RwLock<Option<Resolver<BoundIfProvider>>>>,
    bypass: Arc<tokio::sync::Mutex<HashMap<Ipv4Addr, Instant>>>,
    blocked_queries: Arc<AtomicU64>,
}

fn name_server_ips(servers: &[String]) -> Vec<IpAddr> {
    let ips: Vec<IpAddr> = servers
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .filter(|ip| ip.is_ipv4())
        .collect();
    if ips.is_empty() {
        vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
    } else {
        ips
    }
}

fn resolver_config(servers: &[String]) -> ResolverConfig {
    let name_servers = name_server_ips(servers)
        .into_iter()
        .map(|ip| {
            NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            )
        })
        .collect();
    let mut config = ResolverConfig::default();
    config.name_servers = name_servers;
    config
}

fn build_vpn_resolver(servers: &[String]) -> Result<Resolver<TokioRuntimeProvider>> {
    let mut builder =
        Resolver::builder_with_config(resolver_config(servers), TokioRuntimeProvider::default());
    builder.options_mut().ndots = 0;
    builder
        .build()
        .map_err(|error| TunshareError::Resolver(error.to_string()))
}

fn build_wan_resolver(wan: &WanUplink) -> Result<Resolver<BoundIfProvider>> {
    // Some WAN uplinks block public resolvers (1.1.1.1, 8.8.8.8) and DoH.
    // The default-route gateway is the DNS that still answers.
    let provider = BoundIfProvider::new(&wan.iface, wan.ip)?;
    let mut builder =
        Resolver::builder_with_config(resolver_config(&[wan.gateway.to_string()]), provider);
    builder.options_mut().ndots = 0;
    builder
        .build()
        .map_err(|error| TunshareError::Resolver(error.to_string()))
}

async fn udp_loop(socket: UdpSocket, inner: Arc<ServerInner>, mut shutdown: watch::Receiver<bool>) {
    let mut buf = [0u8; UDP_BUF];
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            result = socket.recv_from(&mut buf) => {
                let Ok((len, from)) = result else { continue };
                let bytes = buf[..len].to_vec();
                let inner = inner.clone();
                let socket_addr = socket.local_addr().ok();
                // Reply from the same socket so the source is still LAN:53.
                match handle_query(&inner, &bytes).await {
                    Ok(response) => {
                        let _ = socket.send_to(&response, from).await;
                    }
                    Err(error) => {
                        tracing::debug!("[Resolver] query from <{from}> failed: {error}");
                        let _ = socket_addr;
                    }
                }
            }
        }
    }
}

async fn tcp_loop(
    listener: TcpListener,
    inner: Arc<ServerInner>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            result = listener.accept() => {
                let Ok((mut stream, _)) = result else { continue };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    if len == 0 || len > 16 * 1024 {
                        return;
                    }
                    let mut body = vec![0u8; len];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    if let Ok(response) = handle_query(&inner, &body).await {
                        let n = response.len() as u16;
                        let mut framed = Vec::with_capacity(2 + response.len());
                        framed.extend_from_slice(&n.to_be_bytes());
                        framed.extend_from_slice(&response);
                        let _ = stream.write_all(&framed).await;
                    }
                });
            }
        }
    }
}

async fn evict_loop(
    bypass: Arc<tokio::sync::Mutex<HashMap<Ipv4Addr, Instant>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = interval(EVICT_TICK);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let mut map = bypass.lock().await;
                let stale: Vec<Ipv4Addr> = map
                    .iter()
                    .filter(|(_, expiry)| now >= **expiry)
                    .map(|(ip, _)| *ip)
                    .collect();
                for ip in &stale {
                    map.remove(ip);
                }
                drop(map);
                if !stale.is_empty() {
                    let _ = Firewall::table_delete(&stale);
                }
            }
        }
    }
}

async fn handle_query(inner: &ServerInner, bytes: &[u8]) -> Result<Vec<u8>> {
    let request = Message::from_bytes(bytes)
        .map_err(|error| TunshareError::Resolver(format!("parse query: {error}")))?;
    let Some(query) = request.queries.first() else {
        return encode_servfail(&request);
    };
    let qname = query.name().to_string();
    let qtype = query.query_type();

    let lists = inner.lists.read().await.clone();
    let decision = classify(&qname, &lists);

    match decision {
        Decision::Block => {
            inner.blocked_queries.fetch_add(1, Ordering::Relaxed);
            encode_nxdomain(&request, Vec::new())
        }
        Decision::Allow => {
            if qtype == RecordType::AAAA {
                return encode_nodata(&request, Vec::new());
            }
            let wan = inner
                .wan_upstream
                .read()
                .ok()
                .and_then(|guard| guard.clone());
            let Some(wan) = wan else {
                return encode_servfail(&request);
            };
            match wan.lookup(&qname, qtype).await {
                Ok(lookup) => {
                    if let Err(error) = install_bypass(inner, lookup.answers()).await {
                        tracing::debug!(
                            "[Resolver] bypass table add failed for <{qname}> {qtype}: {error}"
                        );
                        return encode_servfail(&request);
                    }
                    encode_answers(&request, lookup.answers().to_vec())
                }
                Err(error) => encode_lookup_error(&request, &qname, qtype, error),
            }
        }
        Decision::Vpn => match inner.vpn_upstream.lookup(&qname, qtype).await {
            Ok(lookup) => encode_lookup(&request, lookup.message()),
            Err(error) => encode_lookup_error(&request, &qname, qtype, error),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Block,
    Allow,
    Vpn,
}

fn classify(qname: &str, lists: &ResolverLists) -> Decision {
    let name = qname.trim_end_matches('.');
    if lists.block_enabled && lists.block.contains_suffix(name) {
        return Decision::Block;
    }
    if lists.allow_enabled && lists.allow.contains_suffix(name) {
        return Decision::Allow;
    }
    Decision::Vpn
}

async fn install_bypass(inner: &ServerInner, records: &[Record]) -> Result<()> {
    let ips: Vec<Ipv4Addr> = records
        .iter()
        .filter_map(|record| match record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    if ips.is_empty() {
        return Ok(());
    }
    Firewall::table_add(&ips)?;
    let expiry = Instant::now() + BYPASS_TTL;
    let mut map = inner.bypass.lock().await;
    for ip in ips {
        map.insert(ip, expiry);
    }
    Ok(())
}

fn encode_lookup_error(
    request: &Message,
    qname: &str,
    qtype: RecordType,
    error: NetError,
) -> Result<Vec<u8>> {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            let code = no_records.response_code;
            let authorities = authorities_from_no_records(no_records);
            match code {
                ResponseCode::NXDomain => encode_nxdomain(request, authorities),
                ResponseCode::NoError => encode_nodata(request, authorities),
                code => {
                    tracing::debug!(
                        "[Resolver] unexpected NoRecordsFound code {code} for <{qname}> {qtype}"
                    );
                    encode_servfail(request)
                }
            }
        }
        error => {
            tracing::debug!("[Resolver] upstream lookup failed for <{qname}> {qtype}: {error}");
            encode_servfail(request)
        }
    }
}

fn authorities_from_no_records(no_records: NoRecords) -> Vec<Record> {
    if let Some(authorities) = no_records.authorities {
        return authorities.to_vec();
    }
    no_records
        .soa
        .map(|soa| vec![soa.into_record_of_rdata()])
        .unwrap_or_default()
}

fn encode_lookup(request: &Message, upstream: &Message) -> Result<Vec<u8>> {
    let mut response = upstream.clone();
    response.metadata.id = request.metadata.id;
    response.metadata.message_type = MessageType::Response;
    encode(&response)
}

fn encode_answers(request: &Message, answers: Vec<Record>) -> Result<Vec<u8>> {
    let mut response = base_response(request);
    response.answers = answers;
    encode(&response)
}

fn encode_nxdomain(request: &Message, authorities: Vec<Record>) -> Result<Vec<u8>> {
    let mut response = base_response(request);
    response.metadata.response_code = ResponseCode::NXDomain;
    response.authorities = authorities;
    encode(&response)
}

fn encode_nodata(request: &Message, authorities: Vec<Record>) -> Result<Vec<u8>> {
    let mut response = base_response(request);
    response.authorities = authorities;
    encode(&response)
}

fn encode_servfail(request: &Message) -> Result<Vec<u8>> {
    let mut response = base_response(request);
    response.metadata.response_code = ResponseCode::ServFail;
    encode(&response)
}

fn base_response(request: &Message) -> Message {
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();
    response
}

fn encode(message: &Message) -> Result<Vec<u8>> {
    message
        .to_bytes()
        .map_err(|error| TunshareError::Resolver(format!("encode: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::lists::parse_list_body;
    use hickory_resolver::proto::op::Query;
    use hickory_resolver::proto::rr::{rdata::SOA, Name};
    use std::collections::HashSet;
    use std::str::FromStr;

    fn lists(block: &[&str], allow: &[&str]) -> ResolverLists {
        let mut block_set = HashSet::new();
        let mut allow_set = HashSet::new();
        parse_list_body(&block.join("\n"), &mut block_set);
        parse_list_body(&allow.join("\n"), &mut allow_set);
        ResolverLists {
            block: DomainSet::new(block_set),
            allow: DomainSet::new(allow_set),
            block_enabled: true,
            allow_enabled: true,
        }
    }

    fn name(value: &str) -> Name {
        Name::from_str(value).expect("test name")
    }

    fn query_message(qname: &str, qtype: RecordType) -> Message {
        let mut request = Message::query();
        request.queries.push(Query::query(name(qname), qtype));
        request
    }

    fn no_records_error(qname: &str, qtype: RecordType, code: ResponseCode) -> NetError {
        let mut no_records = NoRecords::new(Query::query(name(qname), qtype), code);
        let soa = SOA::new(
            name("ns.example."),
            name("hostmaster.example."),
            1,
            3600,
            600,
            86400,
            1800,
        );
        no_records.soa = Some(Box::new(Record::from_rdata(name("example."), 1800, soa)));
        NetError::from(no_records)
    }

    fn decode(bytes: &[u8]) -> Message {
        Message::from_bytes(bytes).expect("response decodes")
    }

    fn respond(qname: &str, qtype: RecordType, error: NetError) -> Message {
        let request = query_message(qname, qtype);
        decode(&encode_lookup_error(&request, qname, qtype, error).expect("encode"))
    }

    #[test]
    fn classify_block_wins_over_allow() {
        let lists = lists(&["ads.example.com"], &["example.com"]);
        assert_eq!(classify("ads.example.com.", &lists), Decision::Block);
        assert_eq!(classify("shop.example.com.", &lists), Decision::Allow);
        assert_eq!(classify("google.com.", &lists), Decision::Vpn);
    }

    #[test]
    fn classify_respects_enabled_flags() {
        let mut lists = lists(&["ads.example.com"], &["digikala.com"]);
        lists.block_enabled = false;
        assert_eq!(classify("ads.example.com", &lists), Decision::Vpn);
        lists.allow_enabled = false;
        assert_eq!(classify("shop.digikala.com", &lists), Decision::Vpn);
    }

    #[test]
    fn no_records_noerror_is_nodata_with_soa() {
        let qname = "gym.example.";
        let response = respond(
            qname,
            RecordType::CNAME,
            no_records_error(qname, RecordType::CNAME, ResponseCode::NoError),
        );
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
        assert_eq!(response.authorities.len(), 1);
        assert!(matches!(response.authorities[0].data, RData::SOA(_)));
    }

    #[test]
    fn no_records_noerror_without_soa_is_nodata() {
        let qname = "gym.example.";
        let error = NetError::from(NoRecords::new(
            Query::query(name(qname), RecordType::CNAME),
            ResponseCode::NoError,
        ));
        let response = respond(qname, RecordType::CNAME, error);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
        assert!(response.authorities.is_empty());
    }

    #[test]
    fn no_records_nxdomain_is_nxdomain_with_soa() {
        let qname = "missing.example.";
        let response = respond(
            qname,
            RecordType::A,
            no_records_error(qname, RecordType::A, ResponseCode::NXDomain),
        );
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
        assert_eq!(response.authorities.len(), 1);
        assert!(matches!(response.authorities[0].data, RData::SOA(_)));
    }

    #[test]
    fn timeout_and_io_and_servfail_are_servfail() {
        let qname = "gym.example.";
        for error in [
            NetError::Timeout,
            NetError::from(std::io::Error::other("upstream closed")),
            NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)),
        ] {
            let response = respond(qname, RecordType::A, error);
            assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
            assert!(response.answers.is_empty());
            assert!(response.authorities.is_empty());
        }
    }
}
