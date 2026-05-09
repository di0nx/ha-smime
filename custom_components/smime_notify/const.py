"""Constants for the S/MIME Notify integration."""

from __future__ import annotations

DOMAIN = "smime_notify"

DEFAULT_NOTIFY_SERVICE_NAME = "smime_signed"
DEFAULT_SMTP_PORT = 587
DEFAULT_SMTP_TIMEOUT = 20
DEFAULT_TLS_VERIFY = True

DEFAULT_FROM_NAME = "Home Assistant"

DEFAULT_SIGN = True
DEFAULT_SIGN_DEFAULT = True
DEFAULT_ENCRYPT = False
DEFAULT_ENCRYPT_DEFAULT = False
DEFAULT_ALLOW_UNENCRYPTED_FALLBACK = False
DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT = False
DEFAULT_INCLUDE_CERT_CHAIN = True

DEFAULT_LOCAL_CERT_DIR = "/ssl/smime/publickeys"
DEFAULT_LOCAL_FILE_TYPES = ["pem", "crt", "cer", "der", "txt"]
HASH_MODE_RAW_EMAIL = "raw_email"
DEFAULT_HASH_MODE = HASH_MODE_RAW_EMAIL
DEFAULT_CERT_EXPIRY_WARNING_DAYS = 14

SMTP_ENCRYPTION_NONE = "none"
SMTP_ENCRYPTION_STARTTLS = "starttls"
SMTP_ENCRYPTION_SSL = "ssl"
SMTP_ENCRYPTION_MODES = [
    SMTP_ENCRYPTION_NONE,
    SMTP_ENCRYPTION_STARTTLS,
    SMTP_ENCRYPTION_SSL,
]

HASH_MODE_SHA256_EMAIL_HEX = "sha256_email_hex"
HASH_MODE_BOTH_RAW_THEN_HASH = "both_raw_then_hash"
HASH_MODE_BOTH_HASH_THEN_RAW = "both_hash_then_raw"
HASH_MODES = [
    HASH_MODE_RAW_EMAIL,
    HASH_MODE_SHA256_EMAIL_HEX,
    HASH_MODE_BOTH_RAW_THEN_HASH,
    HASH_MODE_BOTH_HASH_THEN_RAW,
]

CONF_NOTIFY_SERVICE_NAME = "notify_service_name"
CONF_SMTP_HOST = "smtp_host"
CONF_SMTP_PORT = "smtp_port"
CONF_SMTP_ENCRYPTION = "smtp_encryption"
CONF_SMTP_USERNAME = "smtp_username"
CONF_SMTP_PASSWORD = "smtp_password"
CONF_SMTP_TIMEOUT = "smtp_timeout"
CONF_TLS_VERIFY = "tls_verify"

CONF_FROM_NAME = "from_name"
CONF_FROM_EMAIL = "from_email"
CONF_DEFAULT_RECIPIENT = "default_recipient"

CONF_SIGN_DEFAULT = "sign_default"
CONF_SIGN_CERT_PATH = "sign_cert_path"
CONF_SIGN_KEY_PATH = "sign_key_path"
CONF_SIGN_KEY_PASSWORD = "sign_key_password"
CONF_INCLUDE_CERT_CHAIN = "include_cert_chain"

CONF_ENCRYPT_DEFAULT = "encrypt_default"
CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT = "allow_unencrypted_fallback_default"
CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT = "skip_recipients_without_cert_default"

CONF_LOCAL_SOURCE_ENABLED = "local_source_enabled"
CONF_LOCAL_CERT_DIR = "local_cert_dir"
CONF_FILE_TYPES = "file_types"
CONF_HASH_MODE = "hash_mode"
CONF_SOURCE_ORDER = "source_order"
CONF_REMOTE_SOURCE_ENABLED = "remote_source_enabled"
CONF_REMOTE_BASE_URL = "remote_base_url"
CONF_REMOTE_ALLOW_INSECURE_HTTP = "remote_allow_insecure_http"
CONF_REMOTE_TIMEOUT = "remote_timeout"
CONF_REMOTE_CACHE_TTL_FALLBACK = "remote_cache_ttl_fallback"
CONF_SMIMEA_SOURCE_ENABLED = "smimea_source_enabled"

CONF_CERT_EXPIRY_WARNING_DAYS = "cert_expiry_warning_days"

DATA_MANAGER = "manager"
SERVICE_SEND_TEST_EMAIL = "send_test_email"
SERVICE_TEST_RECIPIENT_CERTIFICATE = "test_recipient_certificate"
SERVICE_CLEAR_CERTIFICATE_CACHE = "clear_certificate_cache"
SERVICE_RELOAD_CERTIFICATES = "reload_certificates"
SERVICE_VALIDATE_CONFIG = "validate_config"
