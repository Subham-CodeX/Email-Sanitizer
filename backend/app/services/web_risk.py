from urllib.parse import quote
import httpx
from app.core.config import settings
from app.schemas.url_intelligence import (
    URLReputation,
)

WEB_RISK_ENDPOINT = (
    "https://webrisk.googleapis.com/v1/uris:search"
)


THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
]

async def check_web_risk(
    url: str,
) -> URLReputation:

    result = URLReputation(
        provider="google_web_risk"
    )

    if not settings.enable_web_risk:

        result.error = (
            "Google Web Risk is disabled."
        )

        return result

    if not settings.web_risk_api_key:

        result.error = (
            "Google Web Risk API key is not configured."
        )

        return result

    try:

        params = [
            (
                "threatTypes",
                threat_type,
            )
            for threat_type
            in THREAT_TYPES
        ]

        params.append(
            (
                "uri",
                url,
            )
        )

        params.append(
            (
                "key",
                settings.web_risk_api_key,
            )
        )

        async with httpx.AsyncClient(
            timeout=(
                settings
                .url_intelligence_timeout_seconds
            )
        ) as client:

            response = await client.get(
                WEB_RISK_ENDPOINT,
                params=params,
                headers={
                    "Accept":
                        "application/json",
                    "User-Agent":
                        "PhishingTrack/0.4",
                },
            )

        if response.status_code == 200:

            data = response.json()

            result.checked = True

            matches = data.get(
                "threat",
            )

            if matches:

                result.malicious = True

                threat_type = (
                    matches.get(
                        "threatType"
                    )
                )

                if threat_type:

                    result.threat_types.append(
                        threat_type
                    )

                expire_time = (
                    matches.get(
                        "expireTime"
                    )
                )

                if expire_time:

                    result.expires_at = (
                        expire_time
                    )

            return result

        if response.status_code == 404:

            result.checked = True

            result.malicious = False

            return result

        result.error = (
            "Web Risk returned HTTP "
            f"{response.status_code}"
        )

        return result

    except Exception as exc:

        result.error = (
            "Web Risk lookup failed: "
            f"{type(exc).__name__}"
        )

        return result