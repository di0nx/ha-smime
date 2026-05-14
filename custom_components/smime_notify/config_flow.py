"""Config flow for S/MIME Notify."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers import selector

from .const import (
    CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
    CONF_CERT_EXPIRY_WARNING_DAYS,
    CONF_DEFAULT_RECIPIENT,
    CONF_ENCRYPT_DEFAULT,
    CONF_FILE_TYPES,
    CONF_FROM_EMAIL,
    CONF_FROM_NAME,
    CONF_HASH_MODE,
    CONF_INCLUDE_CERT_CHAIN,
    CONF_LOCAL_CERT_DIR,
    CONF_LOCAL_SOURCE_ENABLED,
    CONF_NOTIFY_SERVICE_NAME,
    CONF_SENDER_IDENTITIES,
    CONF_REMOTE_ALLOW_INSECURE_HTTP,
    CONF_REMOTE_BASE_URL,
    CONF_REMOTE_CACHE_TTL_FALLBACK,
    CONF_REMOTE_SOURCE_ENABLED,
    CONF_REMOTE_TIMEOUT,
    CONF_SIGN_CERT_PATH,
    CONF_SIGN_DEFAULT,
    CONF_SIGN_KEY_PASSWORD,
    CONF_SIGN_KEY_PATH,
    CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
    CONF_SMIMEA_SOURCE_ENABLED,
    CONF_SMTP_ENCRYPTION,
    CONF_SMTP_HOST,
    CONF_SMTP_PASSWORD,
    CONF_SMTP_PORT,
    CONF_SMTP_TIMEOUT,
    CONF_SMTP_USERNAME,
    CONF_SOURCE_ORDER,
    CONF_TLS_VERIFY,
    DEFAULT_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
    DEFAULT_ENCRYPT_DEFAULT,
    DEFAULT_HASH_MODE,
    DEFAULT_LOCAL_FILE_TYPES,
    DEFAULT_NOTIFY_SERVICE_NAME,
    DEFAULT_SIGN_DEFAULT,
    DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
    DEFAULT_SMTP_PORT,
    DEFAULT_SMTP_TIMEOUT,
    DEFAULT_TLS_VERIFY,
    DEFAULT_CERT_EXPIRY_WARNING_DAYS,
    DEFAULT_FROM_NAME,
    DEFAULT_INCLUDE_CERT_CHAIN,
    DEFAULT_LOCAL_CERT_DIR,
    DEFAULT_REMOTE_ALLOW_INSECURE_HTTP,
    DEFAULT_REMOTE_CACHE_TTL_FALLBACK,
    DEFAULT_REMOTE_SOURCE_ENABLED,
    DEFAULT_REMOTE_TIMEOUT,
    DEFAULT_SMIMEA_SOURCE_ENABLED,
    DEFAULT_SOURCE_ORDER,
    DOMAIN,
    HASH_MODES,
    SMTP_ENCRYPTION_MODES,
)


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _format_sender_identities(defaults: dict[str, Any]) -> str:
    identities = defaults.get(CONF_SENDER_IDENTITIES) or []
    lines = []
    for item in identities:
        if isinstance(item, dict):
            identity_id = str(item.get("id") or "").strip()
            name = str(item.get("name") or "").strip()
            email = str(item.get("email") or "").strip()
            if identity_id and email:
                lines.append(f"{identity_id}|{name}|{email}")
    return "\n".join(lines)


def _parse_sender_identities(
    value: Any, default_name: str, default_email: str
) -> list[dict[str, str]]:
    identities: list[dict[str, str]] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                identity = {
                    "id": str(item.get("id") or "").strip(),
                    "name": str(item.get("name") or "").strip(),
                    "email": str(item.get("email") or "").strip(),
                }
                if identity["id"] and identity["email"]:
                    identities.append(identity)
    else:
        for line in str(value or "").splitlines():
            parts = [part.strip() for part in line.split("|", 2)]
            if len(parts) == 3 and parts[0] and parts[2]:
                identities.append({"id": parts[0], "name": parts[1], "email": parts[2]})
    default_identity = {"id": "default", "name": default_name, "email": default_email}
    if default_email and not any(item["id"] == "default" for item in identities):
        identities.insert(0, default_identity)
    return identities


def _normalize_flow_data(data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(data)
    normalized[CONF_FILE_TYPES] = _split_csv(str(normalized.get(CONF_FILE_TYPES, "")))
    normalized[CONF_SOURCE_ORDER] = ",".join(
        _split_csv(str(normalized.get(CONF_SOURCE_ORDER, "")))
    )
    normalized[CONF_SENDER_IDENTITIES] = _parse_sender_identities(
        normalized.get(CONF_SENDER_IDENTITIES),
        str(normalized.get(CONF_FROM_NAME) or DEFAULT_FROM_NAME),
        str(normalized.get(CONF_FROM_EMAIL) or ""),
    )
    return normalized


def _merge_entry_data(entry: config_entries.ConfigEntry) -> dict[str, Any]:
    merged = {**entry.data, **entry.options}
    merged.setdefault(CONF_FILE_TYPES, DEFAULT_LOCAL_FILE_TYPES)
    merged.setdefault(CONF_SOURCE_ORDER, DEFAULT_SOURCE_ORDER)
    return merged


def _build_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(
                CONF_NOTIFY_SERVICE_NAME,
                default=defaults.get(
                    CONF_NOTIFY_SERVICE_NAME, DEFAULT_NOTIFY_SERVICE_NAME
                ),
            ): str,
            vol.Required(CONF_SMTP_HOST, default=defaults.get(CONF_SMTP_HOST, "")): str,
            vol.Required(
                CONF_SMTP_PORT, default=defaults.get(CONF_SMTP_PORT, DEFAULT_SMTP_PORT)
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=1, max=65535, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_SMTP_ENCRYPTION,
                default=defaults.get(CONF_SMTP_ENCRYPTION, SMTP_ENCRYPTION_MODES[1]),
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=SMTP_ENCRYPTION_MODES,
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(
                CONF_SMTP_USERNAME, default=defaults.get(CONF_SMTP_USERNAME, "")
            ): str,
            vol.Optional(
                CONF_SMTP_PASSWORD, default=defaults.get(CONF_SMTP_PASSWORD, "")
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Required(
                CONF_SMTP_TIMEOUT,
                default=defaults.get(CONF_SMTP_TIMEOUT, DEFAULT_SMTP_TIMEOUT),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=5, max=300, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_TLS_VERIFY,
                default=defaults.get(CONF_TLS_VERIFY, DEFAULT_TLS_VERIFY),
            ): bool,
            vol.Optional(
                CONF_FROM_NAME, default=defaults.get(CONF_FROM_NAME, DEFAULT_FROM_NAME)
            ): str,
            vol.Required(
                CONF_FROM_EMAIL, default=defaults.get(CONF_FROM_EMAIL, "")
            ): str,
            vol.Optional(
                CONF_SENDER_IDENTITIES,
                default=_format_sender_identities(defaults),
            ): selector.TextSelector(selector.TextSelectorConfig(multiline=True)),
            vol.Optional(
                CONF_DEFAULT_RECIPIENT,
                default=defaults.get(CONF_DEFAULT_RECIPIENT, ""),
            ): str,
            vol.Required(
                CONF_SIGN_DEFAULT,
                default=defaults.get(CONF_SIGN_DEFAULT, DEFAULT_SIGN_DEFAULT),
            ): bool,
            vol.Required(
                CONF_SIGN_CERT_PATH, default=defaults.get(CONF_SIGN_CERT_PATH, "")
            ): str,
            vol.Required(
                CONF_SIGN_KEY_PATH, default=defaults.get(CONF_SIGN_KEY_PATH, "")
            ): str,
            vol.Optional(
                CONF_SIGN_KEY_PASSWORD,
                default=defaults.get(CONF_SIGN_KEY_PASSWORD, ""),
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Required(
                CONF_INCLUDE_CERT_CHAIN,
                default=defaults.get(
                    CONF_INCLUDE_CERT_CHAIN, DEFAULT_INCLUDE_CERT_CHAIN
                ),
            ): bool,
            vol.Required(
                CONF_CERT_EXPIRY_WARNING_DAYS,
                default=defaults.get(
                    CONF_CERT_EXPIRY_WARNING_DAYS, DEFAULT_CERT_EXPIRY_WARNING_DAYS
                ),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=0, max=365, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_ENCRYPT_DEFAULT,
                default=defaults.get(CONF_ENCRYPT_DEFAULT, DEFAULT_ENCRYPT_DEFAULT),
            ): bool,
            vol.Required(
                CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
                default=defaults.get(
                    CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
                    DEFAULT_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
                ),
            ): bool,
            vol.Required(
                CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
                default=defaults.get(
                    CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
                    DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
                ),
            ): bool,
            vol.Required(
                CONF_LOCAL_SOURCE_ENABLED,
                default=defaults.get(CONF_LOCAL_SOURCE_ENABLED, True),
            ): bool,
            vol.Required(
                CONF_LOCAL_CERT_DIR,
                default=defaults.get(CONF_LOCAL_CERT_DIR, DEFAULT_LOCAL_CERT_DIR),
            ): str,
            vol.Required(
                CONF_FILE_TYPES,
                default=", ".join(
                    defaults.get(CONF_FILE_TYPES, DEFAULT_LOCAL_FILE_TYPES)
                ),
            ): str,
            vol.Required(
                CONF_HASH_MODE, default=defaults.get(CONF_HASH_MODE, DEFAULT_HASH_MODE)
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=HASH_MODES, mode=selector.SelectSelectorMode.DROPDOWN
                )
            ),
            vol.Required(
                CONF_SOURCE_ORDER,
                default=defaults.get(CONF_SOURCE_ORDER, DEFAULT_SOURCE_ORDER),
            ): str,
            vol.Required(
                CONF_REMOTE_SOURCE_ENABLED,
                default=defaults.get(
                    CONF_REMOTE_SOURCE_ENABLED, DEFAULT_REMOTE_SOURCE_ENABLED
                ),
            ): bool,
            vol.Optional(
                CONF_REMOTE_BASE_URL, default=defaults.get(CONF_REMOTE_BASE_URL, "")
            ): str,
            vol.Required(
                CONF_REMOTE_ALLOW_INSECURE_HTTP,
                default=defaults.get(
                    CONF_REMOTE_ALLOW_INSECURE_HTTP, DEFAULT_REMOTE_ALLOW_INSECURE_HTTP
                ),
            ): bool,
            vol.Required(
                CONF_REMOTE_TIMEOUT,
                default=defaults.get(CONF_REMOTE_TIMEOUT, DEFAULT_REMOTE_TIMEOUT),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=1, max=120, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_REMOTE_CACHE_TTL_FALLBACK,
                default=defaults.get(
                    CONF_REMOTE_CACHE_TTL_FALLBACK, DEFAULT_REMOTE_CACHE_TTL_FALLBACK
                ),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=0, max=86400, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_SMIMEA_SOURCE_ENABLED,
                default=defaults.get(
                    CONF_SMIMEA_SOURCE_ENABLED, DEFAULT_SMIMEA_SOURCE_ENABLED
                ),
            ): bool,
        }
    )


def _smtp_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_SMTP_HOST, default=defaults.get(CONF_SMTP_HOST, "")): str,
            vol.Required(
                CONF_SMTP_PORT, default=defaults.get(CONF_SMTP_PORT, DEFAULT_SMTP_PORT)
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=1, max=65535, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_SMTP_ENCRYPTION,
                default=defaults.get(CONF_SMTP_ENCRYPTION, SMTP_ENCRYPTION_MODES[1]),
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=SMTP_ENCRYPTION_MODES,
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(
                CONF_SMTP_USERNAME, default=defaults.get(CONF_SMTP_USERNAME, "")
            ): str,
            vol.Optional(
                CONF_SMTP_PASSWORD, default=defaults.get(CONF_SMTP_PASSWORD, "")
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Required(
                CONF_SMTP_TIMEOUT,
                default=defaults.get(CONF_SMTP_TIMEOUT, DEFAULT_SMTP_TIMEOUT),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=5, max=300, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_TLS_VERIFY,
                default=defaults.get(CONF_TLS_VERIFY, DEFAULT_TLS_VERIFY),
            ): bool,
        }
    )


def _sender_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Optional(
                CONF_FROM_NAME, default=defaults.get(CONF_FROM_NAME, DEFAULT_FROM_NAME)
            ): str,
            vol.Required(
                CONF_FROM_EMAIL, default=defaults.get(CONF_FROM_EMAIL, "")
            ): str,
            vol.Optional(
                CONF_SENDER_IDENTITIES, default=_format_sender_identities(defaults)
            ): selector.TextSelector(selector.TextSelectorConfig(multiline=True)),
            vol.Optional(
                CONF_DEFAULT_RECIPIENT, default=defaults.get(CONF_DEFAULT_RECIPIENT, "")
            ): str,
        }
    )


def _smime_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(
                CONF_SIGN_DEFAULT,
                default=defaults.get(CONF_SIGN_DEFAULT, DEFAULT_SIGN_DEFAULT),
            ): bool,
            vol.Required(
                CONF_SIGN_CERT_PATH, default=defaults.get(CONF_SIGN_CERT_PATH, "")
            ): str,
            vol.Required(
                CONF_SIGN_KEY_PATH, default=defaults.get(CONF_SIGN_KEY_PATH, "")
            ): str,
            vol.Optional(
                CONF_SIGN_KEY_PASSWORD, default=defaults.get(CONF_SIGN_KEY_PASSWORD, "")
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Required(
                CONF_INCLUDE_CERT_CHAIN,
                default=defaults.get(
                    CONF_INCLUDE_CERT_CHAIN, DEFAULT_INCLUDE_CERT_CHAIN
                ),
            ): bool,
            vol.Required(
                CONF_CERT_EXPIRY_WARNING_DAYS,
                default=defaults.get(
                    CONF_CERT_EXPIRY_WARNING_DAYS, DEFAULT_CERT_EXPIRY_WARNING_DAYS
                ),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=0, max=365, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_ENCRYPT_DEFAULT,
                default=defaults.get(CONF_ENCRYPT_DEFAULT, DEFAULT_ENCRYPT_DEFAULT),
            ): bool,
            vol.Required(
                CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
                default=defaults.get(
                    CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
                    DEFAULT_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
                ),
            ): bool,
            vol.Required(
                CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
                default=defaults.get(
                    CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
                    DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
                ),
            ): bool,
        }
    )


def _sources_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(
                CONF_LOCAL_SOURCE_ENABLED,
                default=defaults.get(CONF_LOCAL_SOURCE_ENABLED, True),
            ): bool,
            vol.Required(
                CONF_LOCAL_CERT_DIR,
                default=defaults.get(CONF_LOCAL_CERT_DIR, DEFAULT_LOCAL_CERT_DIR),
            ): str,
            vol.Required(
                CONF_FILE_TYPES,
                default=", ".join(
                    defaults.get(CONF_FILE_TYPES, DEFAULT_LOCAL_FILE_TYPES)
                ),
            ): str,
            vol.Required(
                CONF_HASH_MODE, default=defaults.get(CONF_HASH_MODE, DEFAULT_HASH_MODE)
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=HASH_MODES, mode=selector.SelectSelectorMode.DROPDOWN
                )
            ),
            vol.Required(
                CONF_SOURCE_ORDER,
                default=defaults.get(CONF_SOURCE_ORDER, DEFAULT_SOURCE_ORDER),
            ): str,
            vol.Required(
                CONF_REMOTE_SOURCE_ENABLED,
                default=defaults.get(
                    CONF_REMOTE_SOURCE_ENABLED, DEFAULT_REMOTE_SOURCE_ENABLED
                ),
            ): bool,
            vol.Optional(
                CONF_REMOTE_BASE_URL, default=defaults.get(CONF_REMOTE_BASE_URL, "")
            ): str,
            vol.Required(
                CONF_REMOTE_ALLOW_INSECURE_HTTP,
                default=defaults.get(
                    CONF_REMOTE_ALLOW_INSECURE_HTTP, DEFAULT_REMOTE_ALLOW_INSECURE_HTTP
                ),
            ): bool,
            vol.Required(
                CONF_REMOTE_TIMEOUT,
                default=defaults.get(CONF_REMOTE_TIMEOUT, DEFAULT_REMOTE_TIMEOUT),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=1, max=120, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_REMOTE_CACHE_TTL_FALLBACK,
                default=defaults.get(
                    CONF_REMOTE_CACHE_TTL_FALLBACK, DEFAULT_REMOTE_CACHE_TTL_FALLBACK
                ),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=0, max=86400, mode=selector.NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_SMIMEA_SOURCE_ENABLED,
                default=defaults.get(
                    CONF_SMIMEA_SOURCE_ENABLED, DEFAULT_SMIMEA_SOURCE_ENABLED
                ),
            ): bool,
        }
    )


class SmimeNotifyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for S/MIME Notify."""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            self._data.update(user_input)
            return await self.async_step_sender()

        return self.async_show_form(
            step_id="user",
            data_schema=_smtp_schema({}),
            errors={},
        )

    async def async_step_sender(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            self._data.update(user_input)
            return await self.async_step_smime()

        return self.async_show_form(
            step_id="sender",
            data_schema=_sender_schema(self._data),
            errors={},
        )

    async def async_step_smime(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            self._data.update(user_input)
            return await self.async_step_sources()

        return self.async_show_form(
            step_id="smime",
            data_schema=_smime_schema(self._data),
            errors={},
        )

    async def async_step_sources(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            self._data.update(user_input)
            data = _normalize_flow_data(self._data)
            await self.async_set_unique_id(
                f"{data[CONF_FROM_EMAIL].strip().lower()}::{data[CONF_SMTP_HOST].strip().lower()}"
            )
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=f"S/MIME Notify ({data[CONF_FROM_EMAIL]})",
                data=data,
            )

        return self.async_show_form(
            step_id="sources",
            data_schema=_sources_schema(self._data),
            errors={},
        )

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        """Get options flow."""
        return SmimeNotifyOptionsFlow(config_entry)


class SmimeNotifyOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            data = _normalize_flow_data(user_input)
            return self.async_create_entry(title="", data=data)

        defaults = _merge_entry_data(self._config_entry)
        return self.async_show_form(
            step_id="init",
            data_schema=_build_schema(defaults),
            errors={},
        )
