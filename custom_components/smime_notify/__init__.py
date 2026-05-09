"""S/MIME Notify integration."""

from __future__ import annotations

import logging

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
    SERVICE_SEND_TEST_EMAIL,
    SERVICE_TEST_RECIPIENT_CERTIFICATE,
    SERVICE_VALIDATE_CONFIG,
)
from .notify import SmimeNotifyManager

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["notify"]

SERVICE_FIELD_RECIPIENT = "recipient"

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

    # Try to load sender certificates. If paths are not configured yet or files
    # are missing, log a warning and continue – sending will fail gracefully
    # when sign/encrypt is actually attempted.
    try:
        await manager.async_validate_sender_material()
    except HomeAssistantError as err:
        _LOGGER.warning(
            "Sender certificate material could not be loaded – signing/encryption "
            "will be unavailable until this is fixed: %s",
            err,
        )
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning(
            "Unexpected error loading sender certificates: %s",
            err,
        )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        DATA_MANAGER: manager,
    }

    # Register S/MIME-specific domain services (bound to this entry).
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

    # Forward setup to the notify entity platform.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    _LOGGER.info("S/MIME Notify loaded (entry_id=%s)", entry.entry_id)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)

        # Remove domain services if this was the last entry.
        if not hass.data.get(DOMAIN):
            for service in (
                SERVICE_SEND_TEST_EMAIL,
                SERVICE_TEST_RECIPIENT_CERTIFICATE,
                SERVICE_CLEAR_CERTIFICATE_CACHE,
                SERVICE_RELOAD_CERTIFICATES,
                SERVICE_VALIDATE_CONFIG,
            ):
                if hass.services.has_service(DOMAIN, service):
                    hass.services.async_remove(DOMAIN, service)

    _LOGGER.debug("S/MIME Notify unloaded for %s (ok=%s)", entry.entry_id, unload_ok)
    return unload_ok
