"""
Attack factory implementation.
"""

from typing import Dict, Type, List, TYPE_CHECKING

if TYPE_CHECKING:
    from wifi_jammer.core.interfaces import IAttackStrategy

from wifi_jammer.core.interfaces import IAttackFactory, AttackType
from wifi_jammer.attacks import (
    DeauthAttack,
    DisassocAttack,
    BeaconFloodAttack,
    AuthFloodAttack,
    AssocFloodAttack,
    ProbeResponseFloodAttack,
)


def _lazy_import_attack(module_name: str, class_name: str) -> "Type[IAttackStrategy]":
    """Lazily import an attack class by module and class name."""
    import importlib

    module = importlib.import_module(f"wifi_jammer.attacks.{module_name}")
    attack_class = getattr(module, class_name)
    from typing import cast

    return cast("Type[IAttackStrategy]", attack_class)


class AttackFactory(IAttackFactory):
    """Factory for creating attack strategy instances."""

    def __init__(self) -> None:
        self._attack_classes: "Dict[AttackType, Type[IAttackStrategy]]" = {
            AttackType.DEAUTH: DeauthAttack,
            AttackType.DISASSOC: DisassocAttack,
            AttackType.BEACON_FLOOD: BeaconFloodAttack,
            AttackType.AUTH_FLOOD: AuthFloodAttack,
            AttackType.ASSOC_FLOOD: AssocFloodAttack,
            AttackType.PROBE_RESPONSE: ProbeResponseFloodAttack,
        }
        self._lazy_attacks: Dict[AttackType, tuple[str, str]] = {
            AttackType.CHANNEL_HOP: ("channel_hop_attack", "ChannelHopAttack"),
            AttackType.PMKID_CAPTURE: ("pmkid_capture_attack", "PmkidCaptureAttack"),
            AttackType.EVIL_TWIN: ("evil_twin_attack", "EvilTwinAttack"),
            AttackType.NETCUT: ("netcut_attack", "NetcutAttack"),
        }

    def create_attack(self, attack_type: AttackType) -> "IAttackStrategy":
        """Create an attack strategy instance."""
        if attack_type in self._attack_classes:
            attack_class = self._attack_classes[attack_type]
        elif attack_type in self._lazy_attacks:
            module_name, class_name = self._lazy_attacks[attack_type]
            attack_class = _lazy_import_attack(module_name, class_name)
            self._attack_classes[attack_type] = attack_class
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

        return attack_class()

    def get_available_attacks(self) -> List[AttackType]:
        """Get list of available attack types."""
        registered = set(self._attack_classes) | set(self._lazy_attacks)
        return [at for at in AttackType if at in registered]

    def register_attack(
        self, attack_type: AttackType, attack_class: "Type[IAttackStrategy]"
    ) -> None:
        """Register a new attack type."""
        self._attack_classes[attack_type] = attack_class
