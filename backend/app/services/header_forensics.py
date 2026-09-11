import ipaddress
import re

from email import policy
from email.parser import Parser
from email.utils import parseaddr

from app.schemas.email import (
    AuthenticationResult,
    HeaderFinding,
    HeaderForensicsResult,
    ReceivedHop,
)


IP_PATTERN = re.compile(
    r"\[?("
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[0-9a-fA-F:]{3,}"
    r")\]?"
)


RECEIVED_FROM_PATTERN = re.compile(
    r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|\s*;|$)",
    re.IGNORECASE,
)

RECEIVED_BY_PATTERN = re.compile(
    r"\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|\s*;|$)",
    re.IGNORECASE,
)

RECEIVED_WITH_PATTERN = re.compile(
    r"\bwith\s+([A-Za-z0-9._+-]+)",
    re.IGNORECASE,
)

RECEIVED_DATE_PATTERN = re.compile(
    r";\s*(.+)$"
)


AUTH_TOKEN_PATTERN = re.compile(
    r"([a-zA-Z0-9_-]+)=([^\s;]+)"
)


def analyze_headers(
    evidence_id: str,
    raw_headers: str,
) -> HeaderForensicsResult:

    message = Parser(
        policy=policy.default
    ).parsestr(
        raw_headers
    )

    received_headers = (
        message.get_all(
            "Received",
            []
        )
    )

    hops = parse_received_chain(
        received_headers
    )

    auth_results = (
        parse_authentication_results(
            message
        )
    )

    spf_result, spf_domain = (
        extract_spf(message)
    )

    dkim_result, dkim_domain, dkim_selector = (
        extract_dkim(
            message,
            auth_results,
        )
    )

    dmarc_result, dmarc_domain = (
        extract_dmarc(
            auth_results
        )
    )

    from_address = (
        parseaddr(
            message.get(
                "From",
                ""
            )
        )[1]
        or None
    )

    reply_to_address = (
        parseaddr(
            message.get(
                "Reply-To",
                ""
            )
        )[1]
        or None
    )

    return_path = (
        message.get(
            "Return-Path"
        )
        or None
    )

    if return_path:
        return_path = (
            return_path
            .strip()
            .strip("<>")
        )

    from_domain = (
        get_domain(
            from_address
        )
    )

    reply_to_domain = (
        get_domain(
            reply_to_address
        )
    )

    return_path_domain = (
        get_domain(
            return_path
        )
    )

    message_id_domain = (
        extract_message_id_domain(
            message.get(
                "Message-ID"
            )
        )
    )

    public_ip_count = 0
    private_ip_count = 0

    for hop in hops:

        if hop.is_public_ip:
            public_ip_count += 1

        if hop.is_private_ip:
            private_ip_count += 1

    findings = []

    run_identity_checks(
        findings=findings,
        from_address=from_address,
        from_domain=from_domain,
        reply_to_address=reply_to_address,
        reply_to_domain=reply_to_domain,
        return_path=return_path,
        return_path_domain=return_path_domain,
        dkim_domain=dkim_domain,
        spf_domain=spf_domain,
        dmarc_domain=dmarc_domain,
    )

    run_authentication_checks(
        findings=findings,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
    )

    run_routing_checks(
        findings=findings,
        hops=hops,
    )

    run_message_id_checks(
        findings=findings,
        from_domain=from_domain,
        message_id_domain=message_id_domain,
    )

    return HeaderForensicsResult(

        evidence_id=evidence_id,

        received_hops=hops,

        authentication_results=
            auth_results,

        spf_result=
            spf_result,

        spf_domain=
            spf_domain,

        dkim_result=
            dkim_result,

        dkim_domain=
            dkim_domain,

        dkim_selector=
            dkim_selector,

        dmarc_result=
            dmarc_result,

        dmarc_domain=
            dmarc_domain,

        from_address=
            from_address,

        from_domain=
            from_domain,

        reply_to_address=
            reply_to_address,

        reply_to_domain=
            reply_to_domain,

        return_path=
            return_path,

        return_path_domain=
            return_path_domain,

        message_id_domain=
            message_id_domain,

        relay_count=
            len(hops),

        public_ip_count=
            public_ip_count,

        private_ip_count=
            private_ip_count,

        findings=
            findings,
    )


def parse_received_chain(
    headers,
):

    result = []

    for index, raw in enumerate(
        headers,
        start=1,
    ):

        raw_text = (
            str(raw)
            .replace(
                "\r\n",
                " "
            )
            .replace(
                "\n",
                " "
            )
        )

        from_host = None
        by_host = None
        protocol = None
        timestamp = None

        from_match = (
            RECEIVED_FROM_PATTERN.search(
                raw_text
            )
        )

        by_match = (
            RECEIVED_BY_PATTERN.search(
                raw_text
            )
        )

        with_match = (
            RECEIVED_WITH_PATTERN.search(
                raw_text
            )
        )

        date_match = (
            RECEIVED_DATE_PATTERN.search(
                raw_text
            )
        )

        if from_match:
            from_host = (
                from_match.group(1)
                .strip()
            )

        if by_match:
            by_host = (
                by_match.group(1)
                .strip()
            )

        if with_match:
            protocol = (
                with_match.group(1)
                .strip()
            )

        if date_match:
            timestamp = (
                date_match.group(1)
                .strip()
            )

        from_ip = extract_ip(
            from_host
        )

        by_ip = extract_ip(
            by_host
        )

        ip_for_classification = (
            from_ip
            or by_ip
        )

        is_private = None
        is_public = None

        if ip_for_classification:

            is_private = is_private_ip(
                ip_for_classification
            )

            is_public = not is_private

        result.append(
            ReceivedHop(

                hop_number=index,

                raw=raw_text,

                from_host=from_host,

                from_ip=from_ip,

                by_host=by_host,

                by_ip=by_ip,

                protocol=protocol,

                timestamp=timestamp,

                is_private_ip=is_private,

                is_public_ip=is_public,
            )
        )

    return result


def parse_authentication_results(
    message,
):

    headers = (
        message.get_all(
            "Authentication-Results",
            []
        )
    )

    results = []

    for header in headers:

        raw = (
            str(header)
        )

        service = None

        parts = raw.split(
            ";"
        )

        if parts:

            service = (
                parts[0]
                .strip()
            )

        tokens = dict(
            AUTH_TOKEN_PATTERN.findall(
                raw
            )
        )

        for method in (
            "spf",
            "dkim",
            "dmarc",
        ):

            if method in tokens:

                result = (
                    tokens[
                        method
                    ]
                )

                domain = (
                    tokens.get(
                        "header.from"
                    )
                    or tokens.get(
                        "smtp.mailfrom"
                    )
                    or tokens.get(
                        "header.d"
                    )
                )

                selector = (
                    tokens.get(
                        "header.s"
                    )
                )

                results.append(
                    AuthenticationResult(

                        service=service,

                        result=result,

                        method=method,

                        domain=(
                            domain
                            or None
                        ),

                        selector=(
                            selector
                            or None
                        ),

                        raw=raw,
                    )
                )

    return results


def extract_spf(
    message,
):

    spf_header = (
        message.get(
            "Received-SPF"
        )
    )

    if spf_header:

        raw = str(
            spf_header
        )

        first = (
            raw.split(
                " ",
                1
            )[0]
            .strip()
            .lower()
        )

        domain = extract_parameter(
            raw,
            "envelope-from"
        )

        return (
            first or None,
            clean_email_domain(
                domain
            ),
        )

    auth = message.get_all(
        "Authentication-Results",
        []
    )

    for header in auth:

        text = str(
            header
        )

        match = re.search(
            r"\bspf=([a-zA-Z0-9_-]+)",
            text,
            re.IGNORECASE,
        )

        if match:

            result = (
                match.group(1)
                .lower()
            )

            domain = (
                extract_parameter(
                    text,
                    "smtp.mailfrom"
                )
            )

            return (
                result,
                clean_email_domain(
                    domain
                ),
            )

    return None, None


def extract_dkim(
    message,
    auth_results,
):

    dkim_headers = (
        message.get_all(
            "DKIM-Signature",
            []
        )
    )

    if dkim_headers:

        raw = str(
            dkim_headers[0]
        )

        domain = extract_parameter(
            raw,
            "d"
        )

        selector = extract_parameter(
            raw,
            "s"
        )

        result = None

        for auth in auth_results:

            if auth.method == "dkim":

                result = auth.result

                if not domain:
                    domain = auth.domain

                if not selector:
                    selector = auth.selector

                break

        return (
            result,
            clean_domain(
                domain
            ),
            selector,
        )

    for auth in auth_results:

        if auth.method == "dkim":

            return (
                auth.result,
                auth.domain,
                auth.selector,
            )

    return None, None, None


def extract_dmarc(
    auth_results,
):

    for auth in auth_results:

        if auth.method == "dmarc":

            return (
                auth.result,
                auth.domain,
            )

    return None, None


def run_identity_checks(
    findings,
    from_address,
    from_domain,
    reply_to_address,
    reply_to_domain,
    return_path,
    return_path_domain,
    dkim_domain,
    spf_domain,
    dmarc_domain,
):

    if (
        from_domain
        and reply_to_domain
        and not domains_match(
            from_domain,
            reply_to_domain,
        )
    ):

        findings.append(
            HeaderFinding(

                severity="medium",

                code="REPLY_TO_MISMATCH",

                title="Reply-To domain differs from From domain",

                description=(
                    "The visible sender domain and "
                    "Reply-To domain are different. "
                    "This can be legitimate, but is "
                    "a common phishing indicator."
                ),

                evidence=(
                    f"From={from_address}; "
                    f"Reply-To={reply_to_address}"
                ),
            )
        )

    if (
        from_domain
        and return_path_domain
        and not domains_match(
            from_domain,
            return_path_domain,
        )
    ):

        findings.append(
            HeaderFinding(

                severity="low",

                code="RETURN_PATH_MISMATCH",

                title="Return-Path differs from From domain",

                description=(
                    "The envelope return address "
                    "uses a different domain from "
                    "the visible From address."
                ),

                evidence=(
                    f"From={from_domain}; "
                    f"Return-Path="
                    f"{return_path_domain}"
                ),
            )
        )

    if (
        from_domain
        and dkim_domain
        and not domains_match(
            from_domain,
            dkim_domain,
        )
    ):

        findings.append(
            HeaderFinding(

                severity="low",

                code="DKIM_DOMAIN_MISMATCH",

                title="DKIM signing domain differs from From domain",

                description=(
                    "The DKIM signing domain does not "
                    "match the visible sender domain."
                ),

                evidence=(
                    f"From={from_domain}; "
                    f"DKIM={dkim_domain}"
                ),
            )
        )

    if (
        from_domain
        and spf_domain
        and not domains_match(
            from_domain,
            spf_domain,
        )
    ):

        findings.append(
            HeaderFinding(

                severity="low",

                code="SPF_DOMAIN_MISMATCH",

                title="SPF envelope domain differs from From domain",

                description=(
                    "The SPF-authenticated envelope "
                    "domain differs from the visible "
                    "From domain."
                ),

                evidence=(
                    f"From={from_domain}; "
                    f"SPF={spf_domain}"
                ),
            )
        )


def run_authentication_checks(
    findings,
    spf_result,
    dkim_result,
    dmarc_result,
):

    if spf_result:

        if spf_result in (
            "fail",
            "softfail",
        ):

            severity = (
                "high"
                if spf_result == "fail"
                else "medium"
            )

            findings.append(
                HeaderFinding(

                    severity=severity,

                    code="SPF_FAILURE",

                    title="SPF authentication failed",

                    description=(
                        "The sender's SPF authentication "
                        "did not successfully validate."
                    ),

                    evidence=(
                        f"SPF result={spf_result}"
                    ),
                )
            )

    if dkim_result:

        if dkim_result in (
            "fail",
            "temperror",
            "permerror",
        ):

            findings.append(
                HeaderFinding(

                    severity="high",

                    code="DKIM_FAILURE",

                    title="DKIM authentication failed",

                    description=(
                        "The DKIM authentication result "
                        "indicates that the cryptographic "
                        "signature could not be trusted."
                    ),

                    evidence=(
                        f"DKIM result={dkim_result}"
                    ),
                )
            )

    if dmarc_result:

        if dmarc_result in (
            "fail",
            "permerror",
            "temperror",
        ):

            findings.append(
                HeaderFinding(

                    severity="high",

                    code="DMARC_FAILURE",

                    title="DMARC authentication failed",

                    description=(
                        "DMARC authentication/alignment "
                        "did not pass."
                    ),

                    evidence=(
                        f"DMARC result={dmarc_result}"
                    ),
                )
            )

    if (
        spf_result in (
            "fail",
            "softfail",
        )
        and dmarc_result == "fail"
    ):

        findings.append(
            HeaderFinding(

                severity="critical",

                code="MULTIPLE_AUTH_FAILURE",

                title="Multiple email authentication failures",

                description=(
                    "Both SPF and DMARC indicate "
                    "authentication failure. This "
                    "significantly increases the "
                    "likelihood that sender identity "
                    "should be investigated."
                ),

                evidence=(
                    f"SPF={spf_result}; "
                    f"DMARC={dmarc_result}"
                ),
            )
        )


def run_routing_checks(
    findings,
    hops,
):

    if not hops:
        findings.append(
            HeaderFinding(

                severity="medium",

                code="NO_RECEIVED_CHAIN",

                title="No Received chain detected",

                description=(
                    "The message contains no usable "
                    "Received headers. This may occur "
                    "with incomplete samples or "
                    "sanitized email evidence."
                ),
            )
        )

        return

    if len(hops) >= 8:

        findings.append(
            HeaderFinding(

                severity="medium",

                code="LONG_RECEIVED_CHAIN",

                title="Unusually long mail relay chain",

                description=(
                    "The message contains many "
                    "Received hops. Long chains can "
                    "be legitimate, but deserve "
                    "additional investigation."
                ),

                evidence=(
                    f"Received hops={len(hops)}"
                ),
            )
        )

    malformed_count = 0

    for hop in hops:

        if not hop.by_host:
            malformed_count += 1

    if malformed_count:

        findings.append(
            HeaderFinding(

                severity="low",

                code="MALFORMED_RECEIVED_HOP",

                title="Incomplete Received header detected",

                description=(
                    "One or more Received headers "
                    "could not be fully parsed."
                ),

                evidence=(
                    f"Incomplete hops="
                    f"{malformed_count}"
                ),
            )
        )


def run_message_id_checks(
    findings,
    from_domain,
    message_id_domain,
):

    if (
        from_domain
        and message_id_domain
        and not domains_match(
            from_domain,
            message_id_domain,
        )
    ):

        findings.append(
            HeaderFinding(

                severity="low",

                code="MESSAGE_ID_DOMAIN_MISMATCH",

                title="Message-ID domain differs from From domain",

                description=(
                    "The Message-ID domain differs "
                    "from the visible sender domain."
                ),

                evidence=(
                    f"From={from_domain}; "
                    f"Message-ID="
                    f"{message_id_domain}"
                ),
            )
        )


def extract_ip(
    text,
):

    if not text:
        return None

    matches = IP_PATTERN.findall(
        text
    )

    for candidate in matches:

        try:

            ipaddress.ip_address(
                candidate
            )

            return candidate

        except ValueError:

            continue

    return None


def is_private_ip(
    ip,
):

    try:

        address = ipaddress.ip_address(
            ip
        )

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
        )

    except ValueError:

        return False


def get_domain(
    email,
):

    if not email:
        return None

    if "@" not in email:
        return None

    return (
        email.rsplit(
            "@",
            1
        )[1]
        .strip()
        .lower()
        .strip(".")
    )


def clean_email_domain(
    value,
):

    if not value:
        return None

    value = (
        value
        .strip()
        .strip("<>")
    )

    if "@" in value:
        return get_domain(
            value
        )

    return clean_domain(
        value
    )


def clean_domain(
    value,
):

    if not value:
        return None

    return (
        value
        .strip()
        .lower()
        .strip(".")
    )


def domains_match(
    first,
    second,
):

    if not first or not second:
        return False

    first = clean_domain(
        first
    )

    second = clean_domain(
        second
    )

    return (
        first == second
        or first.endswith(
            "." + second
        )
        or second.endswith(
            "." + first
        )
    )


def extract_parameter(
    text,
    parameter,
):

    if not text:
        return None

    pattern = (
        rf'(?:^|[;\s])'
        rf'{re.escape(parameter)}'
        rf'\s*=\s*'
        rf'(?:\"([^\"]+)\"|([^\s;]+))'
    )

    match = re.search(
        pattern,
        text,
        re.IGNORECASE,
    )

    if not match:
        return None

    return (
        match.group(1)
        or match.group(2)
    )

def extract_message_id_domain(
    message_id,
):

    if not message_id:
        return None

    value = (
        str(message_id)
        .strip()
        .strip("<>")
    )

    if "@" not in value:
        return None

    return get_domain(
        value
    )