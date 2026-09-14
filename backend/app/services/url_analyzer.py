import ipaddress
import re
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urlsplit,
    urlunsplit,
)

from app.schemas.url_intelligence import (
    URLFinding,
    URLStructure,
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "rebrand.ly",
    "tiny.cc",
    "lnkd.in",
    "s.id",
    "short.io",
    "trib.al",
    "t.ly",
}

SUSPICIOUS_TOKENS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "password",
    "credential",
    "wallet",
    "payment",
    "invoice",
    "billing",
    "update",
    "confirm",
    "authenticate",
    "auth",
    "unlock",
    "suspend",
    "suspended",
    "recover",
    "reset",
    "webmail",
    "microsoft",
    "office365",
    "outlook",
    "google",
    "apple",
    "paypal",
    "amazon",
    "bank",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "work",
    "download",
    "stream",
    "buzz",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
}

def normalize_url(
    value: str,
) -> str:

    value = (
        value
        .strip()
        .replace("\u200b", "")
    )

    if not value:
        return value

    parts = urlsplit(
        value
    )

    scheme = (
        parts.scheme.lower()
        if parts.scheme
        else ""
    )

    hostname = (
        parts.hostname.lower()
        if parts.hostname
        else ""
    )

    try:

        port = parts.port

    except ValueError:

        port = None

    username = parts.username

    password = parts.password

    netloc = hostname

    if username is not None:

        netloc = (
            quote(
                username,
                safe="",
            )
            + "@"
            + netloc
        )

    if password is not None:

        if "@" in netloc:

            prefix, host = netloc.rsplit(
                "@",
                1,
            )

            netloc = (
                prefix
                + ":"
                + quote(
                    password,
                    safe="",
                )
                + "@"
                + host
            )

        else:

            netloc = (
                quote(
                    username or "",
                    safe="",
                )
                + ":"
                + quote(
                    password,
                    safe="",
                )
                + "@"
                + netloc
            )

    if port is not None:

        default_port = (
            (
                scheme == "http"
                and port == 80
            )
            or
            (
                scheme == "https"
                and port == 443
            )
        )

        if not default_port:

            netloc += (
                f":{port}"
            )

    return urlunsplit(
        (
            scheme,
            netloc,
            parts.path or "",
            parts.query or "",
            "",
        )
    )

def get_registrable_domain(
    hostname: str | None,
) -> str | None:

    if not hostname:
        return None

    hostname = (
        hostname
        .lower()
        .rstrip(".")
    )

    try:

        ipaddress.ip_address(
            hostname
        )

        return None

    except ValueError:
        pass

    labels = hostname.split(".")

    if len(labels) < 2:
        return hostname

    # Basic fallback without PSL dependency.
    #
    # Common multi-label public suffixes are handled here.
    #
    # This is intentionally conservative and should not be
    # treated as a complete Public Suffix List implementation.

    known_two_level_suffixes = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",
        "co.jp",
        "co.nz",
        "com.br",
        "com.cn",
        "com.sg",
        "com.my",
        "co.za",
    }

    suffix_two = (
        ".".join(
            labels[-2:]
        )
    )

    if suffix_two in known_two_level_suffixes:

        if len(labels) >= 3:

            return ".".join(
                labels[-3:]
            )

        return hostname

    return ".".join(
        labels[-2:]
    )

def parse_ip_host(
    hostname: str | None,
) -> tuple[
    bool,
    int | None,
]:

    if not hostname:
        return False, None

    try:

        address = ipaddress.ip_address(
            hostname
        )

        return True, address.version

    except ValueError:

        return False, None


def contains_unicode(
    value: str,
) -> bool:

    return any(
        ord(char) > 127
        for char in value
    )

def find_suspicious_tokens(
    url: str,
    hostname: str | None,
    path: str | None,
    query: str | None,
) -> list[str]:

    text = " ".join(
        value or ""
        for value in (
            url,
            hostname,
            path,
            query,
        )
    ).lower()

    tokens = []

    for token in SUSPICIOUS_TOKENS:

        if token in text:

            tokens.append(
                token
            )

    return sorted(
        set(tokens)
    )

def analyze_url_structure(
    url: str,
) -> tuple[
    URLStructure,
    list[URLFinding],
]:

    parts = urlsplit(
        url
    )

    hostname = (
        parts.hostname.lower()
        if parts.hostname
        else None
    )

    is_ip_host, ip_version = (
        parse_ip_host(
            hostname
        )
    )

    normalized = normalize_url(
        url
    )

    punycode = bool(
        hostname
        and (
            "xn--"
            in hostname
        )
    )

    unicode_present = contains_unicode(
        url
    )

    shortener = (
        hostname in SHORTENER_DOMAINS
        if hostname
        else False
    )

    try:

        port = parts.port

    except ValueError:

        port = None

    is_https = (
        parts.scheme.lower()
        == "https"
    )

    is_http = (
        parts.scheme.lower()
        == "http"
    )

    non_standard_port = (
        (
            is_http
            and port not in (
                None,
                80,
            )
        )
        or
        (
            is_https
            and port not in (
                None,
                443,
            )
        )
    )

    tokens = find_suspicious_tokens(
        url,
        hostname,
        parts.path,
        parts.query,
    )

    structural_findings = []

    findings: list[
        URLFinding
    ] = []

    if is_http:

        structural_findings.append(
            "URL uses HTTP instead of HTTPS."
        )

        findings.append(
            URLFinding(
                severity="low",
                code="HTTP_URL",
                title="Non-HTTPS URL",
                description=(
                    "The extracted URL uses HTTP. "
                    "Transport encryption is not present "
                    "at the URL scheme level."
                ),
                evidence=url,
            )
        )

    if is_ip_host:

        structural_findings.append(
            "URL hostname is an IP address."
        )

        findings.append(
            URLFinding(
                severity="medium",
                code="IP_HOST",
                title="IP address used as URL host",
                description=(
                    "The URL points directly to an IP "
                    "address instead of a domain name."
                ),
                evidence=hostname,
            )
        )

    if punycode:

        structural_findings.append(
            "Hostname contains an IDN/Punycode label."
        )

        findings.append(
            URLFinding(
                severity="medium",
                code="PUNYCODE_HOST",
                title="Punycode hostname",
                description=(
                    "The hostname contains xn-- IDN labels. "
                    "This can be legitimate, but it deserves "
                    "additional scrutiny for look-alike domains."
                ),
                evidence=hostname,
            )
        )

    if parts.username is not None:

        structural_findings.append(
            "URL contains username information."
        )

        findings.append(
            URLFinding(
                severity="medium",
                code="URL_USERINFO",
                title="Username embedded in URL",
                description=(
                    "The URL contains userinfo before the "
                    "hostname. This can be abused to disguise "
                    "the actual destination."
                ),
                evidence=url,
            )
        )


    if parts.password is not None:

        structural_findings.append(
            "URL contains password information."
        )

        findings.append(
            URLFinding(
                severity="high",
                code="URL_PASSWORD",
                title="Password embedded in URL",
                description=(
                    "The URL contains password-style "
                    "userinfo before the destination host."
                ),
                evidence=url,
            )
        )

    if shortener:

        structural_findings.append(
            "URL uses a known URL-shortening domain."
        )

        findings.append(
            URLFinding(
                severity="medium",
                code="URL_SHORTENER",
                title="URL shortener detected",
                description=(
                    "The URL uses a known shortening service. "
                    "The final destination cannot be determined "
                    "without actively following the redirect."
                ),
                evidence=hostname,
            )
        )

    if non_standard_port:

        structural_findings.append(
            "URL uses a non-standard port."
        )

        findings.append(
            URLFinding(
                severity="medium",
                code="NON_STANDARD_PORT",
                title="Non-standard URL port",
                description=(
                    "The URL specifies a port that differs "
                    "from the normal port for its scheme."
                ),
                evidence=str(port),
            )
        )

    if tokens:

        structural_findings.append(
            "URL contains security-sensitive tokens."
        )

        findings.append(
            URLFinding(
                severity="low",
                code="SUSPICIOUS_TOKENS",
                title="Security-sensitive URL terms",
                description=(
                    "The URL contains terms commonly seen "
                    "in account, authentication, payment or "
                    "verification workflows."
                ),
                evidence=", ".join(tokens),
            )
        )

    tld = None

    if hostname and "." in hostname:

        tld = hostname.rsplit(
            ".",
            1,
        )[-1].lower()

    if tld in SUSPICIOUS_TLDS:

        structural_findings.append(
            "Hostname uses a TLD frequently observed "
            "in suspicious or abuse-heavy infrastructure."
        )

        findings.append(
            URLFinding(
                severity="low",
                code="SUSPICIOUS_TLD",
                title="Higher-risk TLD signal",
                description=(
                    "The hostname uses a TLD that PhishingTrack "
                    "marks as a heuristic signal. This is not "
                    "evidence of maliciousness by itself."
                ),
                evidence=f".{tld}",
            )
        )

    if len(url) > 2048:

        structural_findings.append(
            "URL is unusually long."
        )

        findings.append(
            URLFinding(
                severity="low",
                code="LONG_URL",
                title="Unusually long URL",
                description=(
                    "The URL is longer than 2048 characters."
                ),
                evidence=str(
                    len(url)
                ),
            )
        )

    try:

        query_params = parse_qsl(
            parts.query,
            keep_blank_values=True,
        )

    except Exception:

        query_params = []

    if len(query_params) >= 10:

        findings.append(
            URLFinding(
                severity="low",
                code="MANY_QUERY_PARAMETERS",
                title="Many query parameters",
                description=(
                    "The URL contains a large number "
                    "of query parameters."
                ),
                evidence=str(
                    len(query_params)
                ),
            )
        )


    structure = URLStructure(

        original_url=url,

        normalized_url=normalized,

        scheme=(
            parts.scheme.lower()
            or None
        ),

        hostname=hostname,

        registrable_domain=(
            get_registrable_domain(
                hostname
            )
        ),

        port=port,

        path=(
            unquote(
                parts.path
            )
            if parts.path
            else None
        ),

        query=(
            parts.query
            if parts.query
            else None
        ),

        fragment_present=bool(
            parts.fragment
        ),

        username_present=(
            parts.username is not None
        ),

        password_present=(
            parts.password is not None
        ),

        is_ip_host=is_ip_host,

        ip_version=ip_version,

        is_punycode=punycode,

        contains_unicode=unicode_present,

        is_shortener=shortener,

        is_https=is_https,

        is_http=is_http,

        is_non_standard_port=(
            non_standard_port
        ),

        suspicious_tokens=tokens,

        structural_findings=(
            structural_findings
        ),
    )

    return structure, findings