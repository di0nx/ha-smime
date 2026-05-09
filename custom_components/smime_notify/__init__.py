"""S/MIME Notify integration."""

from __future__ import annotations

import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv

from .const import (
    DATA_MANAGER,
    DEFAULT_NOTIFY_SERVICE_NAME,
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
from .notify import SmimeNotifyManager

_LOGGER = logging.getLogger(__name__)
PLATFORMS: list[Platform] = [Platform.NOTIFY]
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
    }
)

TEST_RECIPIENT_CERT_SCHEMA = vol.Schema({vol.Required("email"): cv.string})


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up integration from yaml (not used)."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up S/MIME notify from a config entry."""
    manager = SmimeNotifyManager(hass=hass, entry=entry)

    notify_service_name = manager.notify_service_name
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        DATA_MANAGER: manager,
        "notify_service": notify_service_name,
    }

    async def _notify_service_handler(call: ServiceCall) -> None:
        await manager.async_send_notify_service(call)

    async def _send(call: ServiceCall) -> None:
        await manager.async_send_service(call)

    async def _send_test_email(call: ServiceCall) -> None:
        await manager.async_send_test_email(call)

    async def _test_recipient_certificate(call: ServiceCall) -> None:
        await manager.async_test_recipient_certificate(call)

    async def _clear_certificate_cache(call: ServiceCall) -> None:
        await manager.async_clear_certificate_cache()

    async def _reload_certificates(call: ServiceCall) -> None:
        await manager.async_reload_certificates()

    async def _validate_config(call: ServiceCall) -> None:
        await manager.async_validate_config_service()

    hass.services.async_register("notify", notify_service_name, _notify_service_handler)
    hass.services.async_register(
        DOMAIN,
        SERVICE_SEND,
        _send,
        schema=SEND_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_SEND_TEST_EMAIL,
        _send_test_email,
        schema=SEND_TEST_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_TEST_RECIPIENT_CERTIFICATE,
        _test_recipient_certificate,
        schema=TEST_RECIPIENT_CERT_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_CLEAR_CERTIFICATE_CACHE,
        _clear_certificate_cache,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_RELOAD_CERTIFICATES,
        _reload_certificates,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_VALIDATE_CONFIG,
        _validate_config,
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    _LOGGER.info(
        "S/MIME Notify ready. Notify service: notify.%s",
        notify_service_name,
    )
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if not data:
        return True

    notify_service_name = data.get("notify_service", DEFAULT_NOTIFY_SERVICE_NAME)
    hass.services.async_remove("notify", notify_service_name)

    if hass.services.has_service(DOMAIN, SERVICE_SEND):
        hass.services.async_remove(DOMAIN, SERVICE_SEND)
    if hass.services.has_service(DOMAIN, SERVICE_SEND_TEST_EMAIL):
        hass.services.async_remove(DOMAIN, SERVICE_SEND_TEST_EMAIL)
    if hass.services.has_service(DOMAIN, SERVICE_TEST_RECIPIENT_CERTIFICATE):
        hass.services.async_remove(DOMAIN, SERVICE_TEST_RECIPIENT_CERTIFICATE)
    if hass.services.has_service(DOMAIN, SERVICE_CLEAR_CERTIFICATE_CACHE):
        hass.services.async_remove(DOMAIN, SERVICE_CLEAR_CERTIFICATE_CACHE)
    if hass.services.has_service(DOMAIN, SERVICE_RELOAD_CERTIFICATES):
        hass.services.async_remove(DOMAIN, SERVICE_RELOAD_CERTIFICATES)
    if hass.services.has_service(DOMAIN, SERVICE_VALIDATE_CONFIG):
        hass.services.async_remove(DOMAIN, SERVICE_VALIDATE_CONFIG)

    _LOGGER.debug("S/MIME Notify unloaded for %s", entry.entry_id)
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate old config entries."""
    if entry.data.get("smtp_encryption") != SMTP_ENCRYPTION_SSL_LEGACY:
        return True

    data = {**entry.data, "smtp_encryption": SMTP_ENCRYPTION_SSL}
    hass.config_entries.async_update_entry(entry, data=data)
    return True
