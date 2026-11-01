import html
import logging
import os

import requests

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org"


def send_telegram_alert(event: dict) -> bool:
    """Send a high-risk LoKey event to the configured Telegram chat."""

    enabled = os.getenv("TELEGRAM_ENABLED", "false").lower() == "true"

    if not enabled:
        return False

    assessment = event["assessment"]

    # Only notify the team about high-risk events.
    if assessment["risk"].lower() != "high":
        return False

    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        logger.warning("Telegram enabled, but bot token or chat ID is missing")
        return False

    observation = event["observation"]
    index = event["index"]

    domain = html.escape(observation["domain"])
    changes = html.escape(", ".join(observation["changes"]))
    reasons = assessment["reasons"]

    reason_text = "\n".join(
        f"• {html.escape(reason)}"
        for reason in reasons
    ) or "No reasons provided"

    public_url = os.getenv(
        "LOKEY_PUBLIC_URL",
        "http://localhost:5000"
    ).rstrip("/")

    proof_url = f"{public_url}/proof/{index}"

    message = (
        "🚨 <b>LoKey SECURITY ALERT</b>\n\n"
        "Risk: <b>HIGH</b>\n"
        f"Domain: <code>{domain}</code>\n"
        f"Changes: <code>{changes}</code>\n\n"
        "<b>Reasons:</b>\n"
        f"{reason_text}\n\n"
        f'<a href="{html.escape(proof_url, quote=True)}">'
        "View Merkle inclusion proof</a>\n"
        f"Entry index: <code>{index}</code>"
    )

    try:
        response = requests.post(
            f"{TELEGRAM_API}/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=5,
        )

        response.raise_for_status()

        result = response.json()

        if not result.get("ok"):
            logger.error("Telegram rejected notification: %s", result)
            return False

        logger.info("Telegram notification sent for event #%s", index)
        return True

    except requests.RequestException:
        logger.exception("Failed to deliver Telegram notification")
        return False
