"""
Attack factory implementation.
"""

from typing import Dict, Type
from ..core.interfaces import IAttackFactory, IAttackStrategy, AttackType
from ..attacks import (
    DeauthAttack, DisassocAttack, BeaconFloodAttack,
    AuthFloodAttack, AssocFloodAttack, ProbeResponseFloodAttack
)


class AttackFactory(IAttackFactory):
    """Factory for creating attack strategy instances."""
    
    def __init__(self):
        self._attack_classes: Dict[AttackType, Type[IAttackStrategy]] = {
            AttackType.DEAUTH: DeauthAttack,
            AttackType.DISASSOC: DisassocAttack,
            AttackType.BEACON_FLOOD: BeaconFloodAttack,
            AttackType.AUTH_FLOOD: AuthFloodAttack,
            AttackType.ASSOC_FLOOD: AssocFloodAttack,
            AttackType.PROBE_RESPONSE: ProbeResponseFloodAttack,
        }
    
    def create_attack(self, attack_type: AttackType) -> IAttackStrategy:
        """Create an attack strategy instance."""
        if attack_type not in self._attack_classes:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        attack_class = self._attack_classes[attack_type]
        return attack_class()
    
    def get_available_attacks(self) -> list:
        """Get list of available attack types."""
        return list(self._attack_classes.keys())
    
    def register_attack(self, attack_type: AttackType, attack_class: Type[IAttackStrategy]):
        """Register a new attack type."""
        self._attack_classes[attack_type] = attack_class 