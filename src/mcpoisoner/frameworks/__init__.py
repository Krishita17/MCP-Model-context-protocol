"""Agent framework runner registry."""

from __future__ import annotations

from mcpoisoner.frameworks.base import AgentRunner


def get_runner(framework: str) -> AgentRunner:
    if framework == "langchain":
        from mcpoisoner.frameworks.langchain_runner import LangChainRunner
        return LangChainRunner()
    elif framework == "crewai":
        from mcpoisoner.frameworks.crewai_runner import CrewAIRunner
        return CrewAIRunner()
    elif framework == "autogen":
        from mcpoisoner.frameworks.autogen_runner import AutoGenRunner
        return AutoGenRunner()
    else:
        raise ValueError(f"Unknown framework: {framework}. Available: langchain, crewai, autogen")
