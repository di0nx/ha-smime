"""S/MIME Notify integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .const import (
    DATA_MANAGER,
    DOMAIN,
    SERVICE_CLEAR_CERTIFICATE_CACHE,
    SERVICE_RELOAD_CERTIFICATES,
    SERVICE_SEND,
    SERVICE_SEND_TEST_EMAIL,
    SERVICE_TEST_RECIPIENT_CERTIFICATE,
    SERVICE_VALIDATE_CONFIG,
    SMTP_ENCRYPTION_SSL,
    SMTP_ENCRYPTION_SSL_LEGACY,
)

_LOGGER = logging.getLogger(__name__)
SERVICE_FIELD_RECIPIENT = "recipient"


SEND_SCHEMA = vol.Schema(
    {
        vol.Optional("title", default=""): cv.string,
        vol.Required("message"): cv.string,
        vol.Optional("html"): cv.string,
        vol.Optional("target"): vol.Any(cv.string, [cv.string]),
        vol.Optional("cc"): vol.Any(cv.string, [cv.string]),
        vol.Optional("bcc"): vol.Any(cv.string, [cv.string]),
        vol.Optional("reply_to"): cv.string,
        vol.Optional("sign"): cv.boolean,
        vol.Optional("encrypt"): cv.boolean,
        vol.Optional("allow_unencrypted_fallback"): cv.boolean,
        vol.Optional("skip_recipients_without_cert"): cv.boolean,
        vol.Optional("attachments"): vol.Any(cv.string, [cv.string]),
        vol.Optional("config_entry_id"): cv.string,
        vol.Optional("sender_identity"): cv.string,
    }
)

SEND_TEST_SCHEMA = vol.Schema(
    {
        vol.Required(SERVICE_FIELD_RECIPIENT): cv.string,
        vol.Optional("subject", default="S/MIME Test Email"): cv.string,
        vol.Optional("message", default="S/MIME plaintext test message."): cv.string,
        vol.Optional("html", default="<p>S/MIME HTML test message.</p>"): cv.string,
        vol.Optional("sign"): cv.boolean,
        vol.Optional("encrypt"): cv.boolean,
        vol.Optional("config_entry_id"): cv.string,
    }
)

ENTRY_SERVICE_SCHEMA = vol.Schema({vol.Optional("config_entry_id"): cv.string})

TEST_RECIPIENT_CERT_SCHEMA = vol.Schema(
    {vol.Required("email"): cv.string, vol.Optional("config_entry_id"): cv.string}
)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up global S/MIME Notify services."""
    hass.data.setdefault(DOMAIN, {})

    async def _send(call: ServiceCall) -> None:
        await _async_get_manager(hass, call).async_send_service(call)

    async def _send_test_email(call: ServiceCall) -> None:
        await _async_get_manager(hass, call).async_send_test_email(call)

    async def _test_recipient_certificate(call: ServiceCall) -> None:
        await _async_get_manager(hass, call).async_test_recipient_certificate(call)

    async def _clear_certificate_cache(call: ServiceCall) -> None:
        await _async_get_manager(hass, call).async_clear_certificate_cache()

    async def _reload_certificates(call: ServiceCall) -> None:
        await _async_get_manager(hass, call).async_reload_certificates()

    async def _validate_config(call: ServiceCall) -> None:
        await _async_get_manager(hass, call).async_validate_config_service()

    if not hass.services.has_service(DOMAIN, SERVICE_SEND):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SEND,
            _send,
            schema=SEND_SCHEMA,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_SEND_TEST_EMAIL):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SEND_TEST_EMAIL,
            _send_test_email,
            schema=SEND_TEST_SCHEMA,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_TEST_RECIPIENT_CERTIFICATE):
        hass.services.async_register(
            DOMAIN,
            SERVICE_TEST_RECIPIENT_CERTIFICATE,
            _test_recipient_certificate,
            schema=TEST_RECIPIENT_CERT_SCHEMA,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_CLEAR_CERTIFICATE_CACHE):
        hass.services.async_register(
            DOMAIN,
            SERVICE_CLEAR_CERTIFICATE_CACHE,
            _clear_certificate_cache,
            schema=ENTRY_SERVICE_SCHEMA,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_RELOAD_CERTIFICATES):
        hass.services.async_register(
            DOMAIN,
            SERVICE_RELOAD_CERTIFICATES,
            _reload_certificates,
            schema=ENTRY_SERVICE_SCHEMA,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_VALIDATE_CONFIG):
        hass.services.async_register(
            DOMAIN,
            SERVICE_VALIDATE_CONFIG,
            _validate_config,
            schema=ENTRY_SERVICE_SCHEMA,
        )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up S/MIME notify from a config entry."""
    from .notify import SmimeNotifyManager

    manager = SmimeNotifyManager(hass=hass, entry=entry)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        DATA_MANAGER: manager,
    }

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    _LOGGER.info(
        "S/MIME Notify ready for entry %s",
        entry.entry_id,
    )
    return True


def _async_get_manager(hass: HomeAssistant, call: ServiceCall | None = None) -> Any:
    """Return the requested manager, or the only loaded manager."""
    entries = hass.data.get(DOMAIN, {})
    requested_entry_id = None
    if call is not None:
        requested_entry_id = call.data.get("config_entry_id")
    if requested_entry_id:
        manager = entries.get(requested_entry_id, {}).get(DATA_MANAGER)
        if manager is not None:
            return manager
        raise HomeAssistantError(
            f"S/MIME Notify config entry {requested_entry_id} is not loaded."
        )

    managers = [
        data.get(DATA_MANAGER) for data in entries.values() if data.get(DATA_MANAGER)
    ]
    if len(managers) == 1:
        return managers[0]
    if not managers:
        raise HomeAssistantError(
            "S/MIME Notify is not loaded. Add or reload the integration before calling this action."
        )
    raise HomeAssistantError(
        "Multiple S/MIME Notify instances are loaded. Pass config_entry_id to smime_notify.send."
    )


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)

    _LOGGER.debug("S/MIME Notify unloaded for %s", entry.entry_id)
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate old config entries."""
    if entry.data.get("smtp_encryption") != SMTP_ENCRYPTION_SSL_LEGACY:
        return True

    data = {**entry.data, "smtp_encryption": SMTP_ENCRYPTION_SSL}
    hass.config_entries.async_update_entry(entry, data=data)
    return True
