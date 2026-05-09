"""Diagnostics support for S/MIME Notify."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_FILE_TYPES,
    CONF_FROM_EMAIL,
    CONF_HASH_MODE,
    CONF_SIGN_CERT_PATH,
    CONF_SMTP_ENCRYPTION,
    CONF_SMTP_HOST,
    CONF_SMTP_PORT,
    CONF_SOURCE_ORDER,
    CONF_TLS_VERIFY,
    DATA_MANAGER,
    DOMAIN,
)


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    merged = {**config_entry.data, **config_entry.options}
    manager_data = hass.data.get(DOMAIN, {}).get(config_entry.entry_id, {})
    manager = manager_data.get(DATA_MANAGER)

    cert_expiry: str | None = None
    cache_size = 0
    if manager and getattr(manager, "_sender_material", None):
        cert_expiry = manager._sender_material.signing_cert.not_valid_after_utc.isoformat()
    if manager and hasattr(manager, "_cert_cache"):
        cache_size = len(manager._cert_cache)

    return {
        "entry_id": config_entry.entry_id,
        "smtp_host": merged.get(CONF_SMTP_HOST),
        "smtp_port": merged.get(CONF_SMTP_PORT),
        "smtp_encryption": merged.get(CONF_SMTP_ENCRYPTION),
        "tls_verify": merged.get(CONF_TLS_VERIFY),
        "from_email": merged.get(CONF_FROM_EMAIL),
        "source_order": merged.get(CONF_SOURCE_ORDER),
        "file_types": merged.get(CONF_FILE_TYPES),
        "hash_mode": merged.get(CONF_HASH_MODE),
        "sign_cert_path": merged.get(CONF_SIGN_CERT_PATH),
        "cache_size": cache_size,
        "sender_cert_expiry": cert_expiry,
    }
