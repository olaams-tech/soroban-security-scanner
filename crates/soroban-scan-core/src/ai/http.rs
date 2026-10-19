//! Opt-in outbound HTTP policy for model-backed providers.
//!
//! This module is compiled only with the non-default `ai-http` feature. It
//! centralizes every network decision so the policy can be audited in one
//! place:
//!
//! * HTTPS only (unless a test explicitly permits loopback HTTP).
//! * An explicit destination allowlist, validated when the policy is built.
//! * Connect and read timeouts.
//! * A hard response-size limit.
//! * Redirects are never followed automatically; each target is re-validated.
//! * Loopback, link-local, private, carrier-grade NAT, documentation, and
//!   multicast destinations are rejected, as are hostnames commonly used for
//!   internal services.
//! * Every failure is returned as an error. There is no fallback transport.
//!
//! The default build does not enable this feature and therefore performs no
//! network access at all.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

use serde::de::DeserializeOwned;
use url::Url;

/// Default connection timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default read timeout (response headers and body).
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Default maximum response body size (1 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Default maximum number of redirects.
pub const DEFAULT_MAX_REDIRECTS: usize = 3;

/// Errors from the outbound HTTP policy.
///
/// Errors are deliberately explicit so callers can fail closed and log a clear
/// reason without falling back to an unvalidated request.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetworkError {
    /// No destinations were configured. Network access is denied.
    #[error("network access denied: the destination allowlist is empty")]
    EmptyAllowlist,
    /// An allowlist entry is malformed or unsafe.
    #[error("invalid destination allowlist entry: {0}")]
    InvalidAllowlist(String),
    /// A policy limit is zero or otherwise invalid.
    #[error("invalid network policy limit: {0}")]
    InvalidLimit(String),
    /// The URL could not be parsed.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    /// The URL scheme is not allowed.
    #[error("URL scheme is not allowed: {0}")]
    SchemeNotAllowed(String),
    /// The destination is not on the allowlist.
    #[error("destination is not allowlisted: {0}")]
    HostNotAllowed(String),
    /// The destination resolves to a prohibited address.
    #[error("destination resolves to a prohibited address: {0}")]
    DeniedAddress(String),
    /// The destination host could not be resolved.
    #[error("destination host could not be resolved: {0}")]
    HostUnresolved(String),
    /// A connect or read timeout elapsed.
    #[error("network request timed out")]
    Timeout,
    /// The redirect budget was exhausted.
    #[error("too many redirects")]
    TooManyRedirects,
    /// A redirect was malformed or targeted a disallowed destination.
    #[error("unsafe or malformed redirect")]
    UnsafeRedirect,
    /// The response body exceeded the configured limit.
    #[error("response exceeds the configured size limit")]
    ResponseTooLarge,
    /// The peer returned a malformed HTTP response.
    #[error("malformed response: {0}")]
    InvalidResponse(String),
    /// A non-success HTTP status was returned.
    #[error("unexpected HTTP status: {0}")]
    UnexpectedStatus(u16),
    /// The response content type is not accepted.
    #[error("unexpected content type: {0}")]
    InvalidContentType(String),
    /// A transport-level failure occurred.
    #[error("transport error: {0}")]
    Transport(String),
}

/// A validated destination allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowlistEntry {
    host: String,
    port: u16,
    wildcard: bool,
}

impl AllowlistEntry {
    fn parse(raw: &str) -> Result<Self, NetworkError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(NetworkError::InvalidAllowlist(
                "entries must not be empty".to_string(),
            ));
        }
        if raw.contains("://")
            || raw.contains('/')
            || raw.contains('?')
            || raw.contains('#')
            || raw.contains('@')
            || raw.chars().any(char::is_whitespace)
        {
            return Err(NetworkError::InvalidAllowlist(format!(
                "{raw:?} must be a bare host name with an optional port"
            )));
        }

        let (host, port) = match raw.rsplit_once(':') {
            Some((host, port)) => {
                if host.contains(':') {
                    return Err(NetworkError::InvalidAllowlist(format!(
                        "{raw:?} is not a supported IPv6 allowlist entry"
                    )));
                }
                let port = port.parse::<u16>().map_err(|_| {
                    NetworkError::InvalidAllowlist(format!("{raw:?} has an invalid port"))
                })?;
                (host, port)
            }
            None => (raw, 443),
        };
        if port == 0 {
            return Err(NetworkError::InvalidAllowlist(format!(
                "{raw:?} has an invalid port"
            )));
        }

        let wildcard = host.starts_with("*.");
        let bare = if wildcard { &host[2..] } else { host };
        if wildcard && (bare.is_empty() || bare.contains('*')) {
            return Err(NetworkError::InvalidAllowlist(format!(
                "{raw:?} has an invalid wildcard"
            )));
        }
        if bare.contains('*') {
            return Err(NetworkError::InvalidAllowlist(format!(
                "{raw:?} has an invalid wildcard"
            )));
        }

        let host = bare.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err(NetworkError::InvalidAllowlist(format!(
                "{raw:?} has an empty host"
            )));
        }
        if is_internal_name(&host) {
            return Err(NetworkError::InvalidAllowlist(format!(
                "{raw:?} names an internal service"
            )));
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_forbidden_ip(ip) {
                return Err(NetworkError::InvalidAllowlist(format!(
                    "{raw:?} is not a publicly routable destination"
                )));
            }
        } else {
            validate_domain(&host).map_err(|reason| {
                NetworkError::InvalidAllowlist(format!("{raw:?} is invalid: {reason}"))
            })?;
        }

        Ok(AllowlistEntry {
            host,
            port,
            wildcard,
        })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port != port {
            return false;
        }
        if self.wildcard {
            host.len() > self.host.len()
                && host.ends_with(&self.host)
                && host.as_bytes()[host.len() - self.host.len() - 1] == b'.'
        } else {
            host == self.host
        }
    }
}

/// Validates a DNS host name.
fn validate_domain(host: &str) -> Result<(), &'static str> {
    if host.len() > 253 {
        return Err("host name is too long");
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("host name contains an empty label");
        }
        if label.len() > 63 {
            return Err("host label is too long");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("host label starts or ends with a hyphen");
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err("host contains unsupported characters");
        }
    }
    if !host.contains('.') {
        return Err("host name must be fully qualified");
    }
    Ok(())
}

/// Returns true for names that commonly resolve to internal services.
fn is_internal_name(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
        || host.ends_with(".home")
        || host.ends_with(".corp")
        || host == "metadata.google.internal"
        || host == "instance-data"
}

/// The outbound network policy.
#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    entries: Vec<AllowlistEntry>,
    connect_timeout: Duration,
    read_timeout: Duration,
    max_response_bytes: usize,
    max_redirects: usize,
    /// Only enabled by tests that exercise the transport against a local socket.
    allow_insecure_http: bool,
    #[cfg(test)]
    allow_loopback: bool,
}

impl NetworkPolicy {
    /// Builds a policy from an explicit destination allowlist.
    ///
    /// An empty allowlist is an error: there is no implicit "allow everything"
    /// mode.
    pub fn new<I, S>(allowlist: I) -> Result<Self, NetworkError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entries = Vec::new();
        for raw in allowlist {
            entries.push(AllowlistEntry::parse(raw.as_ref())?);
        }
        if entries.is_empty() {
            return Err(NetworkError::EmptyAllowlist);
        }
        Ok(NetworkPolicy {
            entries,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            allow_insecure_http: false,
            #[cfg(test)]
            allow_loopback: false,
        })
    }

    /// Sets explicit timeouts, response-size limit, and redirect budget.
    pub fn with_limits(
        mut self,
        connect_timeout: Duration,
        read_timeout: Duration,
        max_response_bytes: usize,
        max_redirects: usize,
    ) -> Result<Self, NetworkError> {
        if connect_timeout.is_zero() {
            return Err(NetworkError::InvalidLimit(
                "connect timeout must be greater than zero".to_string(),
            ));
        }
        if read_timeout.is_zero() {
            return Err(NetworkError::InvalidLimit(
                "read timeout must be greater than zero".to_string(),
            ));
        }
        if max_response_bytes == 0 {
            return Err(NetworkError::InvalidLimit(
                "response-size limit must be greater than zero".to_string(),
            ));
        }
        if max_redirects > 10 {
            return Err(NetworkError::InvalidLimit(
                "redirect limit must be 10 or less".to_string(),
            ));
        }
        self.connect_timeout = connect_timeout;
        self.read_timeout = read_timeout;
        self.max_response_bytes = max_response_bytes;
        self.max_redirects = max_redirects;
        Ok(self)
    }

    /// Validates a destination URL against the allowlist and SSRF rules.
    ///
    /// The returned URL is safe to pass to the transport. Redirect targets are
    /// validated with this same function.
    pub fn validate_url(&self, input: &str) -> Result<Url, NetworkError> {
        let url = Url::parse(input).map_err(|error| NetworkError::InvalidUrl(error.to_string()))?;
        let scheme = url.scheme();
        if scheme != "https" && !(self.allow_insecure_http && scheme == "http") {
            return Err(NetworkError::SchemeNotAllowed(scheme.to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NetworkError::InvalidUrl(
                "embedded credentials are not allowed".to_string(),
            ));
        }

        let host = url
            .host_str()
            .ok_or_else(|| NetworkError::InvalidUrl("missing host".to_string()))?;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| NetworkError::InvalidUrl("the URL has no usable port".to_string()))?;

        if !self.entries.iter().any(|entry| entry.matches(&host, port)) {
            return Err(NetworkError::HostNotAllowed(host));
        }

        self.check_destination(&host, port)?;
        Ok(url)
    }

    /// Rejects an internal address and resolves DNS names to check every answer.
    fn check_destination(&self, host: &str, port: u16) -> Result<(), NetworkError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.check_ip(ip);
        }

        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|_| NetworkError::HostUnresolved(host.to_string()))?;
        let mut any = false;
        for address in addresses {
            any = true;
            self.check_ip(address.ip())?;
        }
        if !any {
            return Err(NetworkError::HostUnresolved(host.to_string()));
        }
        Ok(())
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), NetworkError> {
        #[cfg(test)]
        if self.allow_loopback && ip.is_loopback() {
            return Ok(());
        }
        if is_forbidden_ip(ip) {
            return Err(NetworkError::DeniedAddress(ip.to_string()));
        }
        Ok(())
    }

    /// The configured connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// The configured read timeout.
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// The configured response-size limit.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// The configured redirect budget.
    pub fn max_redirects(&self) -> usize {
        self.max_redirects
    }
}

/// Returns true when an IP address must never be contacted.
fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_forbidden_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_forbidden_v4(mapped);
            }
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
        }
    }
}

/// Returns true for IPv4 ranges that are not globally routable.
fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || octets[0] >= 240
}

/// A validated HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl HttpResponse {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The `Content-Type` header, when present.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// The response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Parses and validates a JSON provider response.
    ///
    /// Validation is strict: a 2xx status, a JSON media type, and valid JSON are
    /// all required. Anything else fails closed.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, NetworkError> {
        if !(200..300).contains(&self.status) {
            return Err(NetworkError::UnexpectedStatus(self.status));
        }
        let content_type = self.content_type.as_deref().unwrap_or("");
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if media_type != "application/json" && !media_type.ends_with("+json") {
            return Err(NetworkError::InvalidContentType(content_type.to_string()));
        }
        serde_json::from_slice(&self.body)
            .map_err(|_| NetworkError::InvalidResponse("response is not valid JSON".to_string()))
    }
}

/// An HTTP client bound to a [`NetworkPolicy`].
#[derive(Debug, Clone)]
pub struct HttpClient {
    policy: NetworkPolicy,
    agent: ureq::Agent,
}

impl HttpClient {
    /// Builds a client with the policy's timeouts and no automatic redirects.
    pub fn new(policy: NetworkPolicy) -> Self {
        let total = policy
            .connect_timeout
            .saturating_add(policy.read_timeout.saturating_mul(2));
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .https_only(!policy.allow_insecure_http)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .save_redirect_history(false)
            .proxy(None)
            .timeout_connect(Some(policy.connect_timeout))
            .timeout_recv_response(Some(policy.read_timeout))
            .timeout_recv_body(Some(policy.read_timeout))
            .timeout_global(Some(total))
            .max_response_header_size(16 * 1024)
            .build()
            .new_agent();
        HttpClient { policy, agent }
    }

    /// The policy enforced by this client.
    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// Performs a GET request, validating every URL and redirect target.
    pub fn get(&self, url: &str) -> Result<HttpResponse, NetworkError> {
        let mut current = url.to_string();
        for redirects in 0..=self.policy.max_redirects {
            let target = self.policy.validate_url(&current)?;
            let response = self
                .agent
                .get(target.as_str())
                .call()
                .map_err(map_transport_error)?;
            let status = response.status().as_u16();

            if (300..400).contains(&status) && status != 304 {
                if redirects == self.policy.max_redirects {
                    return Err(NetworkError::TooManyRedirects);
                }
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .ok_or(NetworkError::UnsafeRedirect)?;
                current = target
                    .join(location)
                    .map_err(|_| NetworkError::UnsafeRedirect)?
                    .to_string();
                continue;
            }

            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let limit = self.policy.max_response_bytes.saturating_add(1);
            let body = response
                .into_body()
                .into_with_config()
                .limit(limit as u64)
                .read_to_vec()
                .map_err(map_transport_error)?;
            if body.len() > self.policy.max_response_bytes {
                return Err(NetworkError::ResponseTooLarge);
            }
            return Ok(HttpResponse {
                status,
                content_type,
                body,
            });
        }
        Err(NetworkError::TooManyRedirects)
    }
}

/// Maps transport failures onto the policy's stable error surface.
fn map_transport_error(error: ureq::Error) -> NetworkError {
    match error {
        ureq::Error::Timeout(_) => NetworkError::Timeout,
        ureq::Error::BodyExceedsLimit(_) => NetworkError::ResponseTooLarge,
        ureq::Error::RequireHttpsOnly(_) => NetworkError::SchemeNotAllowed("https".to_string()),
        ureq::Error::HostNotFound => NetworkError::HostUnresolved("destination".to_string()),
        ureq::Error::TooManyRedirects => NetworkError::TooManyRedirects,
        ureq::Error::StatusCode(code) => NetworkError::UnexpectedStatus(code),
        ureq::Error::BadUri(_)
        | ureq::Error::Protocol(_)
        | ureq::Error::Http(_)
        | ureq::Error::RedirectFailed => {
            NetworkError::InvalidResponse("malformed HTTP response".to_string())
        }
        ureq::Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            NetworkError::Timeout
        }
        ureq::Error::Io(error) => NetworkError::Transport(error.to_string()),
        _ => NetworkError::Transport("request failed".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn test_policy(entries: &[String], max_bytes: usize, timeout: Duration) -> NetworkPolicy {
        let mut policy = NetworkPolicy::new(["8.8.8.8"])
            .unwrap()
            .with_limits(timeout, timeout, max_bytes, 2)
            .unwrap();
        // The public constructor correctly rejects loopback entries. Test-only
        // transport checks use a local listener, so build that entry directly.
        policy.entries = entries
            .iter()
            .map(|entry| {
                let (host, port) = entry.rsplit_once(':').expect("test entry has a port");
                AllowlistEntry {
                    host: host.to_string(),
                    port: port.parse().expect("test entry port"),
                    wildcard: false,
                }
            })
            .collect();
        policy.allow_insecure_http = true;
        policy.allow_loopback = true;
        policy
    }

    fn spawn_server(response: Vec<u8>, delay: Duration) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                thread::sleep(delay);
                let _ = stream.write_all(&response);
            }
        });
        (port, handle)
    }

    fn response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[test]
    fn empty_allowlist_is_rejected() {
        assert_eq!(
            NetworkPolicy::new(Vec::<String>::new()).unwrap_err(),
            NetworkError::EmptyAllowlist
        );
    }

    #[test]
    fn invalid_allowlist_entries_are_rejected() {
        for entry in [
            "*",
            "https://api.example.com",
            "api.example.com/path",
            "user@api.example.com",
            "api.example.com:0",
            "localhost",
            "metadata.google.internal",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "::1",
        ] {
            assert!(
                NetworkPolicy::new([entry]).is_err(),
                "entry should be rejected: {entry}"
            );
        }
    }

    #[test]
    fn invalid_limits_fail_closed() {
        let policy = NetworkPolicy::new(["api.example.com"]).unwrap();
        assert!(policy
            .clone()
            .with_limits(Duration::ZERO, Duration::from_secs(1), 10, 1)
            .is_err());
        assert!(policy
            .clone()
            .with_limits(Duration::from_secs(1), Duration::ZERO, 10, 1)
            .is_err());
        assert!(policy
            .clone()
            .with_limits(Duration::from_secs(1), Duration::from_secs(1), 0, 1)
            .is_err());
        assert!(policy
            .with_limits(Duration::from_secs(1), Duration::from_secs(1), 10, 11)
            .is_err());
    }

    #[test]
    fn http_and_unlisted_destinations_are_rejected() {
        let policy = NetworkPolicy::new(["8.8.8.8"]).unwrap();
        assert_eq!(
            policy.validate_url("http://8.8.8.8/").unwrap_err(),
            NetworkError::SchemeNotAllowed("http".to_string())
        );
        assert!(policy.validate_url("not a url").is_err());
        assert!(matches!(
            policy.validate_url("https://1.1.1.1/").unwrap_err(),
            NetworkError::HostNotAllowed(_)
        ));
        assert!(policy.validate_url("https://user:pass@8.8.8.8/").is_err());
    }

    #[test]
    fn private_and_special_addresses_are_forbidden() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_forbidden_ip(ip), "address should be denied: {ip}");
        }
        assert!(!is_forbidden_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn wildcard_entries_only_match_subdomains() {
        let policy = NetworkPolicy::new(["*.example.com:443"]).unwrap();
        assert!(policy.entries[0].matches("api.example.com", 443));
        assert!(!policy.entries[0].matches("example.com", 443));
        assert!(!policy.entries[0].matches("evil-example.com", 443));
        assert!(!policy.entries[0].matches("api.example.com", 8443));
    }

    #[test]
    fn redirects_are_validated_before_following() {
        let (port, handle) = spawn_server(
            b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            Duration::ZERO,
        );
        let policy = test_policy(
            &[format!("127.0.0.1:{port}")],
            DEFAULT_MAX_RESPONSE_BYTES,
            Duration::from_secs(1),
        );
        let client = HttpClient::new(policy);
        let error = client
            .get(&format!("http://127.0.0.1:{port}/"))
            .unwrap_err();
        assert!(
            matches!(
                error,
                NetworkError::HostNotAllowed(_) | NetworkError::DeniedAddress(_)
            ),
            "unexpected error: {error:?}"
        );
        handle.join().unwrap();
    }

    #[test]
    fn response_size_limit_is_enforced() {
        let body = vec![b'x'; 1024];
        let (port, handle) = spawn_server(
            response("200 OK", "application/json", &body),
            Duration::ZERO,
        );
        let policy = test_policy(&[format!("127.0.0.1:{port}")], 32, Duration::from_secs(1));
        let client = HttpClient::new(policy);
        let error = client
            .get(&format!("http://127.0.0.1:{port}/"))
            .unwrap_err();
        assert_eq!(error, NetworkError::ResponseTooLarge);
        handle.join().unwrap();
    }

    #[test]
    fn read_timeout_is_enforced() {
        let (port, handle) = spawn_server(
            response("200 OK", "application/json", b"{}"),
            Duration::from_millis(500),
        );
        let policy = test_policy(
            &[format!("127.0.0.1:{port}")],
            DEFAULT_MAX_RESPONSE_BYTES,
            Duration::from_millis(50),
        );
        let client = HttpClient::new(policy);
        let error = client
            .get(&format!("http://127.0.0.1:{port}/"))
            .unwrap_err();
        assert_eq!(error, NetworkError::Timeout);
        handle.join().unwrap();
    }

    #[test]
    fn malformed_responses_are_rejected() {
        let (port, handle) = spawn_server(b"definitely not http\r\n\r\n".to_vec(), Duration::ZERO);
        let policy = test_policy(
            &[format!("127.0.0.1:{port}")],
            DEFAULT_MAX_RESPONSE_BYTES,
            Duration::from_secs(1),
        );
        let client = HttpClient::new(policy);
        let error = client
            .get(&format!("http://127.0.0.1:{port}/"))
            .unwrap_err();
        assert!(
            matches!(
                error,
                NetworkError::InvalidResponse(_) | NetworkError::Transport(_)
            ),
            "unexpected error: {error:?}"
        );
        handle.join().unwrap();
    }

    #[test]
    fn json_response_validation_fails_closed() {
        let valid = HttpResponse {
            status: 200,
            content_type: Some("application/json; charset=utf-8".to_string()),
            body: br#"{"ok":true}"#.to_vec(),
        };
        let value: serde_json::Value = valid.json().unwrap();
        assert_eq!(value["ok"], true);

        let bad_status = HttpResponse {
            status: 500,
            ..valid.clone()
        };
        assert_eq!(
            bad_status.json::<serde_json::Value>().unwrap_err(),
            NetworkError::UnexpectedStatus(500)
        );

        let bad_type = HttpResponse {
            content_type: Some("text/plain".to_string()),
            ..valid.clone()
        };
        assert!(matches!(
            bad_type.json::<serde_json::Value>().unwrap_err(),
            NetworkError::InvalidContentType(_)
        ));

        let malformed = HttpResponse {
            body: b"not json".to_vec(),
            ..valid
        };
        assert!(matches!(
            malformed.json::<serde_json::Value>().unwrap_err(),
            NetworkError::InvalidResponse(_)
        ));
    }
}
