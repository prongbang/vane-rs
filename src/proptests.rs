//! Randomized enforcement of the invariants on the attacker-facing parser and
//! decision surface.
//!
//! The release profile ships `panic = "abort"` and the C ABI's `catch_unwind`
//! shields compile to nothing under it, so any panic reachable from bytes a
//! peer controls is a remote crash. Beyond panic-freedom, each property pins
//! the *answer* — host discipline, cookie scope, header-fold rules, redirect
//! refusals — so a future edit cannot quietly weaken one and still pass.
//!
//! Structure: each surface has a plain `check_*` function taking the raw
//! input(s) and asserting its invariants; the `proptest!` blocks only generate
//! inputs and call them. A libfuzzer target could wrap the same functions
//! unchanged.
//!
//! Failure persistence: proptest writes a counterexample to
//! `proptest-regressions/proptests.txt` on failure. Commit that file — it
//! replays the found case first on every future run.

use super::*;
use proptest::prelude::*;

// ---------- Input strategies ----------

/// Concatenations drawn from a fragment pool, optionally salted with fully
/// arbitrary Unicode. Uniform random strings almost never hit a parser's
/// interesting branches; fragments of separators, escapes, and
/// past-differential shapes do.
fn nasty(pool: &'static [&'static str]) -> impl Strategy<Value = String> {
    let fragments =
        prop::collection::vec(prop::sample::select(pool), 0..12).prop_map(|parts| parts.concat());
    prop_oneof![
        6 => fragments.clone(),
        1 => any::<String>(),
        1 => (fragments, any::<String>()).prop_map(|(a, b)| format!("{a}{b}")),
    ]
}

fn url_from(pool: &'static [&'static str]) -> impl Strategy<Value = Url> {
    prop::sample::select(pool).prop_map(|s| Url::parse(s).expect("pool URL must parse"))
}

const URL_POOL: &[&str] = &[
    "https://",
    "http://",
    "HTTPS://",
    "ftp://",
    "wss://",
    "//",
    "://",
    ":",
    "@",
    "user:pass@",
    "example.com",
    "EXAMPLE.com",
    "a",
    "127.0.0.1",
    "10.0.0.1",
    "[::1]",
    "[::A]",
    "[2001:DB8::1]",
    // Whole-authority fragments: a single draw exercises the branch, so the
    // per-run hit probability of these shapes stays ~1 at default case counts
    // instead of depending on two adjacent draws lining up.
    "https://[::A]/",
    "https://[2001:DB8::1]:8080/",
    "https://[::1]:+80/",
    "https://EXAMPLE.com/A/B?Q=1",
    "https://example.com@evil.example/",
    "[",
    "]",
    "[]",
    ":8080",
    ":80",
    ":+80",
    ":0",
    ":65536",
    ":008",
    "/",
    "/..",
    "/./",
    "/a/b",
    "//host",
    "?",
    "?q=1",
    "#",
    "#frag",
    "%2e",
    "%41",
    "%",
    "\\",
    " ",
    "\t",
    "\r\n",
    "\0",
    ".",
    "..",
    "-",
    "_",
    ",",
    ", ",
    "xn--e1afmkfd",
    "ê",
    "。",
    "．",
    "０",
    "🌐",
];

const PORT_POOL: &[&str] = &[
    "",
    "0",
    "1",
    "80",
    "443",
    "0080",
    "65535",
    "65536",
    "99999",
    "18446744073709551616",
    "+80",
    "+0",
    "-1",
    " 80",
    "80 ",
    "8_0",
    "0x50",
    "8.0",
    "80\n",
    "٨٠",
    "８０",
];

const COOKIE_ATTRS: &[&str] = &[
    "Domain=example.com",
    "Domain=.example.com",
    "Domain=..example.com",
    "Domain=com",
    "Domain=COM",
    "Domain=co.uk",
    "Domain=github.io",
    "Domain=EXAMPLE.COM",
    "Domain=evil.com",
    "Domain=sub.example.com",
    "Domain=example.co.uk",
    "Domain=[::1]",
    "Domain=10.0.0.1",
    "Domain=0.0.1",
    "Domain=example.com.",
    "Domain=",
    "domain=example.com",
    "Path=/",
    "Path=/a/b",
    "Path=relative",
    "Path=",
    "Secure",
    "secure",
    "SECURE",
    "HttpOnly",
    "SameSite=None",
    "Max-Age=3600",
    "Max-Age=0",
    "Max-Age=-1",
    "Max-Age=+5",
    "Max-Age=99999999999999999999",
    "Expires=Wed, 21 Oct 2015 07:28:00 GMT",
    "",
    " ",
    "\t",
    "=",
    ";",
    ",",
    "\"q\"",
    "\0",
    "🍪",
];

/// Origins for `StoredCookie::parse`: IP literals, a public-suffix-adjacent
/// host, deep subdomains, a trailing-dot FQDN.
const ORIGIN_POOL: &[&str] = &[
    "https://example.com/",
    "https://sub.example.com/a/b",
    "http://example.com/",
    "https://site.co.uk/x/y/z",
    "https://user.github.io/p",
    "http://10.0.0.1/",
    "https://[::1]/",
    "https://localhost/",
    "https://a.b.c.example.com/deep/path/here",
    "https://example.com./",
];

const DOMAIN_POOL: &[&str] = &[
    "example.com",
    "sub.example.com",
    "com",
    "uk",
    "co.uk",
    "github.io",
    "io",
    "10.0.0.1",
    "0.0.1",
    "[::1]",
    "::1",
    "localhost",
    "example.co.uk",
    "EXAMPLE.COM",
    "a.",
    ".",
    "",
    "xn--p1ai",
    "a.xn--p1ai",
    "example.com.",
];

const HOST_POOL: &[&str] = &[
    "example.com",
    "www.example.com",
    "a.b.c.example.co.uk",
    "site.co.uk",
    "user.github.io",
    "10.0.0.1",
    "127.0.0.1",
    "[::1]",
    "[2001:db8::1]",
    "localhost",
    "com",
    "co.uk",
    "io",
    "xn--p1ai",
    "a.xn--p1ai",
    "example.com.",
    "255.255.255.255",
    "1.2.3.4.5",
];

const HEADER_NAMES: &[&str] = &[
    "set-cookie",
    "location",
    "content-length",
    "x-multi",
    "x-a",
    "content-type",
    "etag",
    "vary",
    "date",
    "link",
];

const HEADER_VALUES: &[&str] = &[
    "",
    "a",
    "b",
    "a, b",
    ", ",
    ",",
    ";",
    "https://first.example/",
    "https://second.example/",
    "0",
    "1",
    "42",
    "1048576",
    "1048577",
    "67108864",
    "18446744073709551615",
    "18446744073709551616",
    "+5",
    "-1",
    " 5",
    "5 ",
    "abc",
    "🍪",
    "\t",
    "x\r\ny",
    "a=1; Path=/",
];

const LOCATION_POOL: &[&str] = &[
    "https://other.example/",
    "http://evil.example/",
    "HTTP://EVIL.EXAMPLE/",
    "//evil.example/x",
    "/relative",
    "relative/x",
    "../..",
    "?q=1",
    "#frag",
    "",
    " ",
    "https://api.example.com/next",
    "https://api.example.com:8443/",
    "HTTPS://API.EXAMPLE.COM/UP",
    "https://example.com@evil.example/",
    "https://a.example/x, https://b.example/",
    "ftp://example.com/",
    "javascript:alert(1)",
    "data:text/html,x",
    "%2F%2Fevil.example",
    "\r\nset-cookie: x=1",
    "https://[::1]/",
    "https://[2001:DB8::A]/",
];

const CROSS_ORIGIN_NAME_POOL: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "user-agent",
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "set-cookie",
    "host",
    "",
    " accept",
    "accept ",
    "Accept",
    "AUTHORIZATION",
];

fn header_name() -> impl Strategy<Value = String> {
    prop_oneof![
        5 => prop::sample::select(HEADER_NAMES).prop_map(str::to_string),
        1 => "[a-z][a-z0-9-]{0,12}",
    ]
}

fn header_value() -> impl Strategy<Value = String> {
    prop_oneof![
        5 => prop::sample::select(HEADER_VALUES).prop_map(str::to_string),
        1 => any::<String>(),
    ]
}

/// Fully arbitrary cookie fields: the round-trip and match rules must hold for
/// anything a jar could ever contain, not just what `parse` produces today.
fn stored_cookie() -> impl Strategy<Value = StoredCookie> {
    (
        any::<String>(),
        any::<String>(),
        prop_oneof![
            4 => prop::sample::select(DOMAIN_POOL).prop_map(str::to_string),
            1 => any::<String>(),
        ],
        any::<bool>(),
        prop_oneof![
            3 => prop::sample::select(["/", "/a", "/a/", "/a/b", "", "a", "/deep/path"].as_slice())
                .prop_map(str::to_string),
            1 => any::<String>(),
        ],
        any::<bool>(),
        prop::option::of(any::<u64>()),
    )
        .prop_map(
            |(name, value, domain, host_only, path, secure, expires_at_epoch_seconds)| {
                StoredCookie {
                    name,
                    value,
                    domain,
                    host_only,
                    path,
                    secure,
                    expires_at_epoch_seconds,
                }
            },
        )
}

// ---------- Check functions (libfuzzer-wrappable shims) ----------

/// Everything an accepted URL promises. Every security decision downstream —
/// pins, cross-origin header stripping, cookie scope — keys off these fields.
fn check_accepted_url(url: &Url) {
    assert!(
        matches!(url.scheme(), "http" | "https"),
        "scheme escaped the allowlist: {:?}",
        url.scheme()
    );
    let host = url.host_str().expect("accepted URL must have a host");
    assert!(!host.is_empty(), "accepted URL with empty host");
    assert_eq!(
        host,
        host.to_ascii_lowercase(),
        "host must be lowercase; host-keyed lookups (pins, cookies) assume it"
    );
    // The past HIGH finding: userinfo must never reach the host field.
    assert!(!host.contains('@'), "userinfo leaked into host: {host:?}");
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner
            .strip_suffix(']')
            .unwrap_or_else(|| panic!("unclosed bracketed host: {host:?}"));
        inner
            .parse::<std::net::Ipv6Addr>()
            .unwrap_or_else(|_| panic!("bracketed host is not an IPv6 address: {host:?}"));
    } else {
        assert!(
            host.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
            "host escaped the documented charset: {host:?}"
        );
    }
    assert!(
        url.path().starts_with('/'),
        "path must be absolute: {:?}",
        url.path()
    );
    // Round-trip: printing and reparsing must reproduce the identical URL, or
    // the host a decision was made about and the host a transport re-derives
    // from the string can differ.
    let display = url.to_string();
    let reparsed = Url::parse(&display).unwrap_or_else(|e| {
        panic!("accepted URL failed to reparse its own display {display:?}: {e}")
    });
    assert_eq!(&reparsed, url, "URL did not round-trip: {display:?}");
}

fn check_url_parse(input: &str) {
    if let Ok(url) = Url::parse(input) {
        check_accepted_url(&url);
    }
}

fn check_url_join(base: &Url, input: &str) {
    if let Ok(url) = base.join(input) {
        check_accepted_url(&url);
    }
}

fn check_parse_port(input: &str) {
    if let Ok(port) = parse_port(input) {
        assert!(
            !input.is_empty() && input.bytes().all(|b| b.is_ascii_digit()),
            "parse_port accepted a non-digit spelling: {input:?}"
        );
        assert_eq!(
            input.parse::<u16>().expect("digits in range"),
            port,
            "parse_port changed the value of {input:?}"
        );
    }
}

/// A parsed `Set-Cookie` is never scoped wider than RFC 6265 lets the origin
/// claim. The rules are restated concretely here — not by re-calling
/// `domain_is_assignable` — so an edit to the shipped check fails the test.
fn check_set_cookie_scope(origin: &Url, set_cookie: &str) {
    let Some(cookie) = StoredCookie::parse(origin, set_cookie) else {
        return;
    };
    let origin_host = origin.host_str().expect("pool origin").to_ascii_lowercase();
    assert!(!cookie.name.is_empty(), "empty cookie name accepted");
    assert!(
        cookie.path.starts_with('/'),
        "cookie path must be absolute: {:?}",
        cookie.path
    );
    if cookie.host_only {
        assert_eq!(
            cookie.domain, origin_host,
            "host-only cookie must be scoped to the origin exactly"
        );
    } else {
        assert!(
            origin_host == cookie.domain
                || origin_host
                    .strip_suffix(&cookie.domain)
                    .is_some_and(|prefix| prefix.ends_with('.')),
            "Domain {:?} does not cover origin {origin_host:?}",
            cookie.domain
        );
        assert!(
            cookie.domain.contains('.'),
            "bare-TLD supercookie accepted: {:?}",
            cookie.domain
        );
        assert!(
            !origin_host.starts_with('[') && origin_host.parse::<IpAddr>().is_err(),
            "IP-literal origin {origin_host:?} took a Domain cookie"
        );
        #[cfg(feature = "psl")]
        assert_ne!(
            psl::suffix_str(&cookie.domain),
            Some(cookie.domain.as_str()),
            "public-suffix supercookie accepted: {:?}",
            cookie.domain
        );
    }
}

fn check_domain_assignability(host: &str, domain: &str) {
    let assignable = domain_is_assignable(host, domain);
    if !domain.contains('.') {
        assert!(!assignable, "bare TLD {domain:?} was assignable");
    }
    if host.starts_with('[') || host.parse::<IpAddr>().is_ok() {
        assert!(
            !assignable,
            "IP-literal host {host:?} took Domain {domain:?}"
        );
    }
    #[cfg(feature = "psl")]
    if psl::suffix_str(domain) == Some(domain) {
        assert!(!assignable, "public suffix {domain:?} was assignable");
    }
}

/// If a cookie is selected for a request, every scope rule held: never Secure
/// over cleartext, never off-domain, never expired.
fn check_cookie_match_rules(cookie: &StoredCookie, url: &Url, now: u64) {
    if !cookie.matches(url, now) {
        return;
    }
    let host = url.host_str().expect("pool URL").to_ascii_lowercase();
    if cookie.secure {
        assert_eq!(
            url.scheme(),
            "https",
            "Secure cookie selected for a cleartext origin"
        );
    }
    if cookie.host_only {
        assert_eq!(host, cookie.domain, "host-only cookie matched another host");
    } else {
        assert!(
            host == cookie.domain
                || host
                    .strip_suffix(&cookie.domain)
                    .is_some_and(|prefix| prefix.ends_with('.')),
            "cookie for {:?} matched host {host:?}",
            cookie.domain
        );
    }
    assert!(!cookie.is_expired(now), "expired cookie matched");
    assert!(
        url.path() == cookie.path || url.path().starts_with(&cookie.path),
        "cookie path {:?} matched request path {:?}",
        cookie.path,
        url.path()
    );
}

/// Persistence is the identity: what the jar writes, loading reads back
/// bit-for-bit, so a restart can never widen (or lose) a cookie's scope.
fn check_persisted_round_trip(cookie: &StoredCookie) {
    let line = persisted_cookie_line(cookie);
    let reparsed = parse_persisted_cookie(&line)
        .unwrap_or_else(|| panic!("persisted line failed to parse: {line:?}"));
    assert_eq!(&reparsed, cookie, "cookie changed across persist/load");
}

/// The header-fold rules both transports share, restated as a model:
/// `set-cookie` never enters the map, `location` keeps its first occurrence
/// exactly, everything else joins `", "` in wire order, and only the first
/// `content-length` feeds the (capped) reservation hint.
fn check_merge_headers(entries: &[(String, String)]) {
    let mut state = ResponseState::new(DEFAULT_MAX_RESPONSE_BODY_BYTES, None)
        .expect("no body file, cannot fail");
    for (name, value) in entries {
        state.merge_header(name.clone(), value.clone());
    }

    assert!(
        !state.headers.contains_key("set-cookie"),
        "set-cookie leaked into the header map"
    );
    let expected_cookies: Vec<&String> = entries
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value)
        .collect();
    assert_eq!(
        state.set_cookie_headers.iter().collect::<Vec<_>>(),
        expected_cookies,
        "set-cookie values must be kept verbatim, in wire order"
    );

    let mut expected: Vec<(String, String)> = Vec::new();
    for (name, value) in entries {
        if name == "set-cookie" {
            continue;
        }
        match expected.iter_mut().find(|(existing, _)| existing == name) {
            Some((existing, joined)) => {
                if existing != "location" {
                    joined.push_str(", ");
                    joined.push_str(value);
                }
            }
            None => expected.push((name.clone(), value.clone())),
        }
    }
    assert_eq!(state.headers.len(), expected.len(), "ghost header key");
    for (name, joined) in &expected {
        assert_eq!(
            state.headers.get(name),
            Some(joined),
            "fold rule broke for {name:?}"
        );
    }

    let expected_total = entries
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| value.parse::<u64>().unwrap_or(0))
        .unwrap_or(0);
    assert_eq!(
        state.download_total, expected_total,
        "content-length hint must come from the first occurrence only"
    );
    assert!(
        state.body.capacity() <= MAX_BODY_RESERVE_BYTES as usize,
        "reservation hint exceeded the cap: {}",
        state.body.capacity()
    );
}

/// No advertised length — hostile, repeated, or absurd — reserves past the cap.
fn check_content_length_hint(values: &[String]) {
    let mut state = ResponseState::new(DEFAULT_MAX_RESPONSE_BODY_BYTES, None)
        .expect("no body file, cannot fail");
    for value in values {
        state.on_content_length(value);
    }
    assert!(
        state.body.capacity() <= MAX_BODY_RESERVE_BYTES as usize,
        "reservation hint exceeded the cap: {}",
        state.body.capacity()
    );
}

/// The redirect gate's refusal rules, exactly as three review rounds set them:
/// a followed hop is never cleartext, never past the hop cap, never off a
/// pinned host, and never happens when the caller opted out.
fn check_redirect_gate(
    status: u16,
    location: &str,
    current: &Url,
    follow: bool,
    hops: usize,
    max_redirects: u32,
    pin_current_host: bool,
) {
    let mut request = test_request(&current.to_string());
    request.follow_redirects = follow;
    let mut pins = HashMap::new();
    if pin_current_host {
        pins.insert(
            current.host_str().expect("pool URL").to_string(),
            vec!["sha256/AAAA".to_string()],
        );
    }
    if let RedirectDecision::Follow(next) = next_redirect_url(
        status,
        Some(location),
        current,
        &request,
        hops,
        max_redirects,
        &pins,
    ) {
        assert!(follow, "followed a redirect the caller opted out of");
        assert!(
            (300..400).contains(&status),
            "followed a non-3xx status {status}"
        );
        assert!(
            hops < max_redirects as usize,
            "followed past the hop cap"
        );
        assert_eq!(next.scheme(), "https", "followed a cleartext downgrade");
        if pin_current_host {
            assert_eq!(
                next.host_str(),
                current.host_str(),
                "redirect left a pinned host"
            );
        }
        check_accepted_url(&next);
    }
}

/// The cross-origin survivor list is closed: the four content-negotiation
/// names and nothing else — never a credential header. Restated by hand so
/// editing the shipped const to widen it fails here.
fn check_cross_origin_header_policy(name: &str) {
    if header_survives_origin_change(name) {
        assert!(
            matches!(
                name,
                "accept" | "accept-language" | "content-type" | "user-agent"
            ),
            "{name:?} must not survive an origin change"
        );
    }
}

/// A request body is never replayed at a different origin, and a *streamed*
/// body is never replayed at all: any hop that still has a body to send
/// either drops it (GET rewrite) or is refused. `Keep` with a streamed body
/// would mean re-sending bytes the caller can no longer produce.
fn check_redirect_rewrite(
    status: u16,
    method: &str,
    has_body: bool,
    streamed: bool,
    cross_origin: bool,
) {
    let rewrite = redirect_rewrite(status, method, has_body, streamed, cross_origin);
    if has_body && cross_origin {
        assert_ne!(
            rewrite,
            RedirectRewrite::Keep,
            "cross-origin body replay permitted: {status} {method}"
        );
    }
    if streamed {
        assert_ne!(
            rewrite,
            RedirectRewrite::Keep,
            "streamed body replay permitted: {status} {method} cross_origin={cross_origin}"
        );
    }
}

// ---------- Properties ----------

proptest! {
    #[test]
    fn url_parse_holds_its_invariants(input in prop_oneof![
        8 => nasty(URL_POOL),
        1 => (1usize..5000).prop_map(|n| format!("https://{}/", "a".repeat(n))),
    ]) {
        check_url_parse(&input);
    }

    #[test]
    fn url_join_holds_the_same_invariants(
        base in url_from(ORIGIN_POOL),
        input in nasty(URL_POOL),
    ) {
        check_url_join(&base, &input);
    }

    #[test]
    fn parse_port_accepts_only_digit_strings(input in prop_oneof![
        4 => prop::sample::select(PORT_POOL).prop_map(str::to_string),
        2 => "[0-9+\\- _.x]{0,8}",
        1 => any::<String>(),
    ]) {
        check_parse_port(&input);
    }

    #[test]
    fn set_cookie_never_widens_scope(
        origin in url_from(ORIGIN_POOL),
        set_cookie in prop_oneof![
            6 => (nasty(COOKIE_ATTRS), prop::collection::vec(prop::sample::select(COOKIE_ATTRS), 0..5))
                .prop_map(|(name_value, attrs)| {
                    let mut line = name_value;
                    for attr in attrs {
                        line.push_str("; ");
                        line.push_str(attr);
                    }
                    line
                }),
            2 => ("[a-z]{1,8}", "[a-z0-9]{0,8}", prop::collection::vec(prop::sample::select(COOKIE_ATTRS), 0..5))
                .prop_map(|(name, value, attrs)| {
                    let mut line = format!("{name}={value}");
                    for attr in attrs {
                        line.push_str("; ");
                        line.push_str(attr);
                    }
                    line
                }),
            1 => any::<String>(),
        ],
    ) {
        check_set_cookie_scope(&origin, &set_cookie);
    }

    #[test]
    fn domain_assignability_never_permits_supercookies(
        host in prop_oneof![
            4 => prop::sample::select(HOST_POOL).prop_map(str::to_string),
            1 => "([a-z0-9]{1,6}\\.){0,4}[a-z0-9]{1,6}",
        ],
        domain in prop_oneof![
            4 => prop::sample::select(DOMAIN_POOL).prop_map(str::to_string),
            1 => "([a-z0-9]{1,6}\\.){0,4}[a-z0-9]{1,6}",
        ],
    ) {
        check_domain_assignability(&host, &domain);
    }

    #[test]
    fn cookie_match_respects_secure_domain_and_expiry(
        cookie in stored_cookie(),
        url in url_from(ORIGIN_POOL),
        now in any::<u64>(),
    ) {
        check_cookie_match_rules(&cookie, &url, now);
    }

    #[test]
    fn persisted_cookie_line_round_trips_exactly(cookie in stored_cookie()) {
        check_persisted_round_trip(&cookie);
    }

    #[test]
    fn parse_persisted_cookie_never_panics(line in prop_oneof![
        4 => nasty(&["\t", "1", "0", "a", "=", "==", "AAAA", "c2Vzc2lvbg==", "!!!", " ", "\0",
                     "9999999999999999999999", "-1", "🍪", "\t\t\t\t\t\t"]),
        1 => any::<String>(),
    ]) {
        let _ = parse_persisted_cookie(&line);
    }

    #[test]
    fn merged_headers_follow_the_fold_rules(
        entries in prop::collection::vec((header_name(), header_value()), 0..12),
    ) {
        check_merge_headers(&entries);
    }

    #[test]
    fn content_length_hint_never_reserves_past_the_cap(
        values in prop::collection::vec(header_value(), 0..8),
    ) {
        check_content_length_hint(&values);
    }

    #[test]
    fn redirect_gate_never_follows_unsafe_targets(
        status in prop_oneof![
            3 => prop::sample::select([300u16, 301, 302, 303, 304, 307, 308, 399, 200, 404].as_slice()),
            1 => 0u16..1000,
        ],
        location in prop_oneof![
            5 => prop::sample::select(LOCATION_POOL).prop_map(str::to_string),
            2 => nasty(URL_POOL),
        ],
        current in url_from(&[
            "https://api.example.com/login",
            "https://example.com/",
            "https://example.com:8443/a",
            "https://[::1]/x",
            "https://sub.example.co.uk/",
            "http://example.com/",
        ]),
        follow in any::<bool>(),
        // Past both sides of any cap the config validator admits (<= 64),
        // including the cap-0 "first 3xx already refused" edge.
        hops in 0usize..70,
        max_redirects in 0u32..67,
        pin_current_host in any::<bool>(),
    ) {
        check_redirect_gate(status, &location, &current, follow, hops, max_redirects, pin_current_host);
    }

    #[test]
    fn cross_origin_header_allowlist_is_closed(name in prop_oneof![
        4 => prop::sample::select(CROSS_ORIGIN_NAME_POOL).prop_map(str::to_string),
        1 => "[a-z-]{1,16}",
        1 => any::<String>(),
    ]) {
        check_cross_origin_header_policy(&name);
    }

    #[test]
    fn redirect_rewrite_never_replays_a_body_cross_origin(
        status in 200u16..600,
        method in prop::sample::select(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "get", "Post"].as_slice()),
        has_body in any::<bool>(),
        streamed in any::<bool>(),
        cross_origin in any::<bool>(),
    ) {
        check_redirect_rewrite(status, method, has_body, streamed, cross_origin);
    }
}

/// The per-feature halves of the public-suffix rule, pinned as plain cases:
/// what ships in every build (bare TLD, IP literal) and what only the `psl`
/// list can refuse (multi-label suffixes).
#[test]
fn public_suffix_rules_match_the_feature_set() {
    assert!(!domain_is_assignable("evil.com", "com"));
    assert!(!domain_is_assignable("10.0.0.1", "0.0.1"));
    assert!(!domain_is_assignable("[::1]", "::1"));
    assert!(domain_is_assignable("deep.a.example.com", "a.example.com"));
    #[cfg(feature = "psl")]
    {
        assert!(!domain_is_assignable("site.co.uk", "co.uk"));
        assert!(!domain_is_assignable("user.github.io", "github.io"));
    }
    // Without the embedded list, multi-label public suffixes are the
    // documented gap (ARTIFACT_SIZES.md): the cheap rules still hold above.
    #[cfg(not(feature = "psl"))]
    assert!(domain_is_assignable("site.co.uk", "co.uk"));
}
