"""netstate — read-only collection of network device state."""

__version__ = "0.2.0"

from netstate.collector import (  # noqa: E402,F401 — the public surface
    ALL_FEATURES, PROTOCOL_FEATURES, SERVICE_FEATURES, FEATURE_LABELS,
    DISCOVERY_MODES, DEFAULT_DISCOVERY_MODE,
    CommandNotAllowed, CollectionError, CommandPolicy, OsPlan,
    DeviceResult, CommandResult, Snapshot,
    run_collect, feature_label, redact, REDACTION_MARKER,
)
from netstate.naming import (  # noqa: E402,F401
    normalise_interface, normalise_hostname, natural_key, location_codes,
    site_of, site_groups, interface_capacity, is_loopback, is_physical,
)
