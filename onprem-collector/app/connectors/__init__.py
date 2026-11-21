"""External service REST connectors (AdGuard Home, Wazuh FIM)."""

from .adguard_connector import AdGuardConnector, load_ai_domains_dictionary, match_shadow_ai_domain
from .wazuh_connector import WazuhConnector

__all__ = [
    "AdGuardConnector",
    "WazuhConnector",
    "load_ai_domains_dictionary",
    "match_shadow_ai_domain",
]
