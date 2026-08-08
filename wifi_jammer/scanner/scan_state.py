"""Shared mutable scan state for the network scanner collaborators."""

import threading
from typing import List

from wifi_jammer.core.interfaces import NetworkInfo


class ScanState:
    """Container for state shared between scanner collaborators.

    A scan is a concurrent operation: the sniffing thread appends to
    ``networks`` while the UI reads from it.  Keeping the list, its lock,
    and the privacy counter in one place makes the threading contract
    explicit instead of scattering mutable attributes across classes.
    """

    def __init__(self) -> None:
        self.networks: List[NetworkInfo] = []
        self.lock = threading.Lock()
        self.scanning = False
        self.privacy_blocked_count = 0
