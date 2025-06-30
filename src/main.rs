use fastly::http::{request::SendError, StatusCode};
use fastly::kv_store::{KVStore, KVStoreError};
use fastly::{mime, Error as FastlyError, Request, Response};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::form_urlencoded;

// Define backends/urls.
const GOOGLE_BACKEND: &str = "google";
const GOOGLE_BASE_URL: &str = "https://dns.google.com/resolve";

const CLOUDFLARE_BACKEND: &str = "cloudflare";
const CLOUDFLARE_BASE_URL: &str = "https://cloudflare-dns.com/dns-query";

#[derive(Deserialize, Debug)]
struct DnsAnswer {
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "data")]
    data: String,
}

#[derive(Deserialize, Debug)]
struct DnsResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsAnswer>>,
}

#[derive(Serialize)]struct VerificationResult<'a> {
    result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<&'a str>,
    duration_ms: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct KvDnsEntry<T> {
    data: T,
    expires_at_unix_sec: u64,
}

type PtrKvEntryData = String;
type AddressKvEntryData = Vec<String>;

const DNS_KV_STORE_NAME: &str = "example_store";
const DEFAULT_DNS_TTL_SECS: u64 = 300;

#[derive(Debug, thiserror::Error)]
enum VerifyError {
    #[error("Invalid Request: {0}")]
    BadRequest(String),
    #[error("DNS Request Send Error: {0}")]
    SendError(#[from] SendError),
    #[error("DNS Query Failed for {url}: HTTP Status {status}")]
    DnsQueryHttpFailed { url: String, status: StatusCode },
    #[error("DNS Query Failed (Resolver Status {resolver_status}) for {query_type} record of '{name}'")]
    DnsQueryResolverFailed { name: String, query_type: String, resolver_status: u32 },
    #[error("DNS Response format unexpected: {0}")]
    DnsFormatError(String),
    #[error("KV Store Operation Failed: {0}")]
    KvStore(#[from] KVStoreError),
    #[error("KV Store Value Read Error: {0}")]
    KvValueReadError(#[from] io::Error),
    #[error("KV Store Not Found or Linked: {0}")]
    KvStoreNotFound(String),
    #[error("Failed to parse/serialize JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid IP Address Format: {0}")]
    InvalidIpFormat(String),
    
    // not used.
    #[error("Internal Operation Error: {0}")]
    InternalError(String), 
}

impl VerifyError {
    fn to_response(&self) -> Response {
        let (status_code, result, reason) = match self {
            VerifyError::BadRequest(reason) | VerifyError::InvalidIpFormat(reason) => {
                (StatusCode::BAD_REQUEST, "error", reason.as_str())
            }
            VerifyError::SendError(_) | VerifyError::DnsQueryHttpFailed { .. } | VerifyError::DnsQueryResolverFailed { .. } | VerifyError::DnsFormatError(_) => {
                (StatusCode::BAD_GATEWAY, "error", "DNS resolution error")
            }
            VerifyError::KvStore(_) | VerifyError::KvValueReadError(_) | VerifyError::KvStoreNotFound(_) => {
                eprintln!("KV Store Error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "error", "Internal cache operation failed")
            }
            VerifyError::JsonError(e) => {
                eprintln!("JSON Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "error", "JSON processing error")
            }
            VerifyError::InternalError(e) => {
                eprintln!("Internal Operation Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "error", "Internal operation failed")
            }
        };

        eprintln!("Verification Error: {:?}", self);
        build_json_response(status_code, result, Some(reason), None, 0.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsResolver {
    Google,
    Cloudflare,
}

// TODO: Remove cloudflare.
// It is neither better, or worse and using 2 providers for diff TTLs is a bit meh unless I want to change the KV store to be per provider.
impl DnsResolver {
    fn config(&self) -> (&'static str, &'static str) {
        match self {
            DnsResolver::Google => (GOOGLE_BACKEND, GOOGLE_BASE_URL),
            DnsResolver::Cloudflare => (CLOUDFLARE_BACKEND, CLOUDFLARE_BASE_URL),
        }
    }
}

#[fastly::main]
fn main(req: Request) -> Result<Response, FastlyError> {
    // Unless on verify, return 404.
    if !(req.get_path() == "/verify" && req.get_method() == "GET") {
        return Ok(Response::from_status(StatusCode::NOT_FOUND)
            .with_content_type(mime::TEXT_PLAIN_UTF_8)
            .with_body("Not Found"));
    }

    match run_verification(&req) {
        Ok(response) => Ok(response),
        Err(err) => Ok(err.to_response()),
    }
}

fn run_verification(req: &Request) -> Result<Response, VerifyError> {
    let start = Instant::now();

    let (ip_addr, resolver) = get_ip_and_resolver(req)?;
    let ip_str = ip_addr.to_string();

    let reverse_name = ip_addr.reverse_lookup_name()?;
    let ptr_domain = fetch_ptr_domain(&reverse_name, &resolver)?;
    let forward_ips = fetch_address_records(&ptr_domain, &ip_addr, &resolver)?;

    let (status_code, result_str, reason_str, answer_str) =
    if forward_ips.iter().any(|forward_ip| *forward_ip == ip_str) {
        (StatusCode::OK, "ok", None, Some(ptr_domain.as_str()))
    } else {
        (
            StatusCode::OK,
            "err",
            Some("PTR domain's A/AAAA records do not match original IP."),
            None,
        )
    };

    let duration_ms = start.elapsed().as_nanos() as f64 / 1_000_000.0;
    Ok(build_json_response(status_code, result_str, reason_str, answer_str, duration_ms))
}

fn get_current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn get_ip_and_resolver(req: &Request) -> Result<(IpAddr, DnsResolver), VerifyError> {
    let raw_query = req.get_url().query().unwrap_or("");
    let mut ip_opt: Option<String> = None;
    let mut resolver = DnsResolver::Cloudflare;

    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "ip" => ip_opt = Some(value.into_owned()),
            "resolver" => {
                resolver = match value.as_ref() {
                    "google" => DnsResolver::Google,
                    "cloudflare" => DnsResolver::Cloudflare,
                    other => return Err(VerifyError::BadRequest(format!("Unsupported resolver '{}'. Use 'google' or 'cloudflare'.", other))),
                };
            }
            _ => {}
        }
    }

    let ip_str = ip_opt.ok_or_else(|| VerifyError::BadRequest("Missing query parameter 'ip'".to_string()))?;
    let ip: IpAddr = ip_str.parse().map_err(|e| VerifyError::InvalidIpFormat(format!("'{}': {}", ip_str, e)))?;

    if !is_public_ip(&ip) {
        return Err(VerifyError::BadRequest(format!(
            "IP address {} is in a reserved or non-routable range", ip
        )));
    }

    Ok((ip, resolver))
}

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            !addr.is_private()
                && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_broadcast()
                && !addr.is_documentation()
                && addr.octets()[0] != 0
        }
        IpAddr::V6(addr) => {
            !addr.is_loopback()
                && !addr.is_multicast()
                && !addr.is_unspecified()
                && !addr.is_unique_local()
                && !addr.is_unicast_link_local()
        }
    }
}

fn open_kv_store() -> Result<KVStore, VerifyError> {
    KVStore::open(DNS_KV_STORE_NAME)?
        .ok_or_else(|| VerifyError::KvStoreNotFound(format!("KV Store '{}' not found or not linked.", DNS_KV_STORE_NAME)))
}

fn kv_lookup<T>(key: &str) -> Result<Option<T>, VerifyError>
where
    T: serde::de::DeserializeOwned,
{
    let store = open_kv_store()?;
    let mut lookup_resp = store.lookup(key)?;

    let mut body = lookup_resp.take_body();
    let mut bytes_vec = Vec::new();
    body.read_to_end(&mut bytes_vec)?;
    
    match serde_json::from_slice::<KvDnsEntry<T>>(&bytes_vec) {
        Ok(entry) => {
            let now_sec = get_current_time_secs();
            if entry.expires_at_unix_sec > now_sec {
                Ok(Some(entry.data))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            eprintln!("KVStore corrupted entry for key '{}': {}. Treating as cache miss.", key, e);
            Ok(None)
        }
    }
}

fn kv_insert<T>(key: &str, data: T, ttl: Duration) -> Result<(), VerifyError>
where
    T: Serialize,
{
    if ttl.is_zero() {
        return Ok(());
    }

    match open_kv_store() {
        Ok(store) => {
            let now_sec = get_current_time_secs();
            let expires_at_unix_sec = now_sec.saturating_add(ttl.as_secs());
            if expires_at_unix_sec > now_sec {
                let entry = KvDnsEntry { data, expires_at_unix_sec };
                let bytes = serde_json::to_vec(&entry)?;
                store.insert(key, bytes)?;
            }
            println!(
                "KVStore INSERT for key: {} (TTL: {}s, expires_at_unix_sec: {})",
                key,
                ttl.as_secs(),
                expires_at_unix_sec
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("KVStore insert failed for key '{}' (store open error): {}", key, e);
            Err(e)
        }
    }
}

fn fetch_dns_response(url: &str, backend: &str) -> Result<DnsResponse, VerifyError> {
    let resp = Request::get(url)
        .with_header("Accept", "application/dns-json")
        .send(backend)?;

    let status = resp.get_status();
    if status == StatusCode::OK {
        let mut body_bytes = Vec::new();
        resp.into_body().read_to_end(&mut body_bytes)?;
        match std::str::from_utf8(&body_bytes) {
            Ok(json_str) => println!("Upstream DNS response: {}", json_str),
            Err(_) => println!("Upstream DNS response: <non-UTF8 or binary>"),
        }
        Ok(serde_json::from_slice(&body_bytes)?)
    } else {
        Err(VerifyError::DnsQueryHttpFailed {
            url: url.to_string(),
            status,
        })
    }
}

fn fetch_ptr_domain(reverse_name: &str, resolver: &DnsResolver) -> Result<String, VerifyError> {
    let kv_key = format!("ptr:{}", reverse_name);

    if let Ok(Some(domain)) = kv_lookup::<PtrKvEntryData>(&kv_key) {
        return Ok(domain);
    }

    let (backend_name, base_url) = resolver.config();
    let url = format!("{}?name={}&type=PTR", base_url, reverse_name);
    let dns_resp = fetch_dns_response(&url, backend_name)?;

    if dns_resp.status != 0 {
        return Err(VerifyError::DnsQueryResolverFailed {
            name: reverse_name.to_string(),
            query_type: "PTR".to_string(),
            resolver_status: dns_resp.status,
        });
    }

    let answer = dns_resp.answer
        .as_ref()
        .and_then(|a| a.first())
        .ok_or_else(|| VerifyError::DnsFormatError(format!("No PTR answer found for {}", reverse_name)))?;

    let domain = answer.data.trim_end_matches('.').to_string();
    let ttl = Duration::from_secs(answer.ttl.into());

    let _ = kv_insert(&kv_key, domain.clone(), ttl);

    Ok(domain)
}

fn fetch_address_records(domain: &str, original_ip: &IpAddr, resolver: &DnsResolver) -> Result<Vec<String>, VerifyError> {
    let (query_type, kv_key_prefix) = match original_ip {
        IpAddr::V4(_) => ("A", "a"),
        IpAddr::V6(_) => ("AAAA", "aaaa"),
    };
    let kv_key = format!("{}:{}", kv_key_prefix, domain);

    if let Ok(Some(ips)) = kv_lookup::<AddressKvEntryData>(&kv_key) {
        return Ok(ips);
    }

    let (backend_name, base_url) = resolver.config();
    let url = format!("{}?name={}&type={}", base_url, domain, query_type);
    let dns_resp = fetch_dns_response(&url, backend_name)?;

    if dns_resp.status != 0 {
        return Err(VerifyError::DnsQueryResolverFailed {
            name: domain.to_string(),
            query_type: query_type.to_string(),
            resolver_status: dns_resp.status,
        });
    }

    let answers = dns_resp.answer.as_deref().unwrap_or(&[]);
    if answers.is_empty() {
        return Err(VerifyError::DnsFormatError(format!(
            "No {} records found for domain '{}' (empty answer section)", query_type, domain
        )));
    }

    let ttl = Duration::from_secs(answers.iter().map(|a| a.ttl).min().unwrap_or(DEFAULT_DNS_TTL_SECS as u32) as u64);
    let ips: Vec<String> = answers.into_iter().map(|ans| ans.data).collect();

    let _ = kv_insert(&kv_key, ips.clone(), ttl);

    Ok(ips)
}

fn build_json_response(
    status: StatusCode,
    result: &str,
    reason: Option<&str>,
    answer: Option<&str>,
    duration_ms: f64,
) -> Response {
    let body_struct = VerificationResult {
        result,
        reason,
        answer,
        duration_ms,
    };

    let body_string = serde_json::to_string(&body_struct).unwrap_or_else(|e| {
        eprintln!("FATAL: Failed to serialize final response: {}", e);
        format!(
            r#"{{"result":"error", "reason":"Internal serialization failure", "duration_ms":{}}}"#,
            duration_ms
        )
    });

    let mut resp = Response::from_status(status)
        .with_content_type(mime::APPLICATION_JSON)
        .with_header("X-Verified", result)
        .with_body(body_string);

    if let Some(r) = reason {
        resp.set_header("X-Reason", r);
    }

    resp
}

trait ReverseLookup {
    fn reverse_lookup_name(&self) -> Result<String, VerifyError>;
}

impl ReverseLookup for Ipv4Addr {
    fn reverse_lookup_name(&self) -> Result<String, VerifyError> {
        let octets = self.octets();
        Ok(format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]))
    }
}

// i did my CCNA 19 years go lol.
impl ReverseLookup for Ipv6Addr {
    fn reverse_lookup_name(&self) -> Result<String, VerifyError> {
        let segments = self.segments();
        let mut reversed_nibbles = String::with_capacity(73);

        for segment in segments.iter().rev() {
            let high_byte = (segment >> 8) as u8;
            let low_byte = (segment & 0xff) as u8;

            // Ref: https://afrinic.net/support/ipv6/nibble
            let nibble3 = low_byte & 0x0f;
            let nibble2 = low_byte >> 4;
            let nibble1 = high_byte & 0x0f;
            let nibble0 = high_byte >> 4;

            reversed_nibbles.push_str(&format!("{:x}.{:x}.{:x}.{:x}.", nibble3, nibble2, nibble1, nibble0));
        }

        reversed_nibbles.push_str("ip6.arpa");
        Ok(reversed_nibbles)
    }
}

impl ReverseLookup for IpAddr {
    fn reverse_lookup_name(&self) -> Result<String, VerifyError> {
        match self {
            IpAddr::V4(ip4) => ip4.reverse_lookup_name(),
            IpAddr::V6(ip6) => ip6.reverse_lookup_name(),
        }
    }
}