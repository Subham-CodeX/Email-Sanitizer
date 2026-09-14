from datetime import (
    datetime,
    timezone,
)

import httpx
from app.core.config import settings

from app.schemas.url_intelligence import (
    DomainRegistrationIntelligence,
)

def parse_rdap_date(
    value: str | None,
) -> datetime | None:

    if not value:
        return None

    value = value.strip()

    try:

        if value.endswith(
            "Z"
        ):

            value = (
                value[:-1]
                + "+00:00"
            )

        dt = datetime.fromisoformat(
            value
        )

        if dt.tzinfo is None:

            dt = dt.replace(
                tzinfo=timezone.utc
            )

        return dt

    except ValueError:

        return None

def get_event_date(
    events: list[dict],
    event_action: str,
) -> str | None:

    for event in events:

        if (
            event.get(
                "eventAction"
            )
            == event_action
        ):

            value = event.get(
                "eventDate"
            )

            if value:

                return value

    return None

def find_registrar(
    entities: list[dict],
) -> tuple[
    str | None,
    str | None,
]:

    for entity in entities:

        roles = entity.get(
            "roles"
        ) or []

        if "registrar" not in roles:
            continue

        vcard = entity.get(
            "vcardArray"
        )

        if (
            not vcard
            or len(vcard) < 2
        ):
            continue

        properties = vcard[1]

        registrar_name = None

        for item in properties:

            if (
                len(item) >= 4
                and item[0]
                == "fn"
            ):

                registrar_name = (
                    item[3]
                )

                break

        registrar_iana_id = None

        public_ids = entity.get(
            "publicIds"
        ) or []

        for public_id in public_ids:

            if (
                public_id.get(
                    "type"
                )
                == "IANA Registrar ID"
            ):

                registrar_iana_id = (
                    public_id.get(
                        "identifier"
                    )
                )

        return (
            registrar_name,
            registrar_iana_id,
        )

    return None, None

async def analyze_domain_rdap(
    domain: str,
) -> DomainRegistrationIntelligence:

    result = DomainRegistrationIntelligence(
        domain=domain
    )

    if not settings.enable_rdap:

        result.errors.append(
            "RDAP analysis is disabled."
        )

        return result

    url = (
        settings.rdap_base_url.rstrip("/")
        + "/"
        + domain
    )

    try:

        async with httpx.AsyncClient(
            timeout=(
                settings
                .url_intelligence_timeout_seconds
            ),
            follow_redirects=True,
        ) as client:

            response = await client.get(
                url,
                headers={
                    "Accept":
                        "application/rdap+json, "
                        "application/json",
                    "User-Agent":
                        "PhishingTrack/0.4",
                },
            )

        if response.status_code == 404:

            result.errors.append(
                "Domain was not found by RDAP."
            )

            return result

        response.raise_for_status()

        data = response.json()

        result.rdap_available = True

        # -------------------------------------------------
        # Registrar
        # -------------------------------------------------

        (
            result.registrar_name,
            result.registrar_iana_id,
        ) = find_registrar(
            data.get(
                "entities"
            ) or []
        )

        events = data.get(
            "events"
        ) or []

        registration_date = (
            get_event_date(
                events,
                "registration",
            )
        )

        last_changed_date = (
            get_event_date(
                events,
                "last changed",
            )
        )

        expiration_date = (
            get_event_date(
                events,
                "expiration",
            )
        )

        result.registration_date = (
            registration_date
        )

        result.last_changed_date = (
            last_changed_date
        )

        result.expiration_date = (
            expiration_date
        )

        registration_dt = parse_rdap_date(
            registration_date
        )

        if registration_dt:

            now = datetime.now(
                timezone.utc
            )

            age = (
                now
                - registration_dt
            ).days

            if age >= 0:

                result.registration_age_days = (
                    age
                )

        result.domain_status = [
            str(status)
            for status in (
                data.get(
                    "status"
                )
                or []
            )
        ]

        nameservers = []

        for nameserver in (
            data.get(
                "nameservers"
            )
            or []
        ):

            name = nameserver.get(
                "ldhName"
            )

            if name:

                nameservers.append(
                    name.lower()
                )

        result.nameservers = sorted(
            set(nameservers)
        )

        return result

    except Exception as exc:

        result.errors.append(
            "RDAP lookup failed: "
            f"{type(exc).__name__}"
        )

        return result