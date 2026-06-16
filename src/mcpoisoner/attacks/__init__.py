"""Attack class implementations for the 5 MCP attack vectors."""

from mcpoisoner.attacks.description_injection import DescriptionInjectionAttack
from mcpoisoner.attacks.tool_shadowing import ToolShadowingAttack
from mcpoisoner.attacks.rug_pull import RugPullAttack
from mcpoisoner.attacks.return_value_poisoning import ReturnValuePoisoningAttack
from mcpoisoner.attacks.cross_tool_escalation import CrossToolEscalationAttack

ATTACK_REGISTRY: dict[str, type] = {
    "description_injection": DescriptionInjectionAttack,
    "tool_shadowing": ToolShadowingAttack,
    "rug_pull": RugPullAttack,
    "return_value_poisoning": ReturnValuePoisoningAttack,
    "cross_tool_escalation": CrossToolEscalationAttack,
}

__all__ = [
    "ATTACK_REGISTRY",
    "DescriptionInjectionAttack",
    "ToolShadowingAttack",
    "RugPullAttack",
    "ReturnValuePoisoningAttack",
    "CrossToolEscalationAttack",
]
