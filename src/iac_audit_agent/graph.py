from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from .nodes import (
    compliance_check_node,
    cost_analysis_node,
    human_review_node,
    parser_node,
    report_generator_node,
    security_audit_node,
    synthesizer_node,
)
from .state import AgentState


def _dispatch_parallel_audits(state: AgentState) -> list[Send]:
    if state.get("error"):
        return [Send("report_generator", state)]
    return [
        Send("security_audit", state),
        Send("compliance_check", state),
        Send("cost_analysis", state),
    ]


def _route_after_synthesis(state: AgentState) -> str:
    if state.get("requires_human_review"):
        return "human_review"
    return "report_generator"


def build_graph(with_checkpointer: bool = True):
    builder = StateGraph(AgentState)

    builder.add_node("parser", parser_node)
    builder.add_node("security_audit", security_audit_node)
    builder.add_node("compliance_check", compliance_check_node)
    builder.add_node("cost_analysis", cost_analysis_node)
    builder.add_node("synthesizer", synthesizer_node)
    builder.add_node("human_review", human_review_node)
    builder.add_node("report_generator", report_generator_node)

    builder.add_edge(START, "parser")
    builder.add_conditional_edges(
        "parser",
        _dispatch_parallel_audits,
        ["security_audit", "compliance_check", "cost_analysis", "report_generator"],
    )
    builder.add_edge("security_audit", "synthesizer")
    builder.add_edge("compliance_check", "synthesizer")
    builder.add_edge("cost_analysis", "synthesizer")
    builder.add_conditional_edges(
        "synthesizer",
        _route_after_synthesis,
        {"human_review": "human_review", "report_generator": "report_generator"},
    )
    builder.add_edge("human_review", "report_generator")
    builder.add_edge("report_generator", END)

    checkpointer = MemorySaver() if with_checkpointer else None
    return builder.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_review"] if with_checkpointer else [],
    )
