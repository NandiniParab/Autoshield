"""Validation Agent role.

The validation node logic currently remains in security_graph.py because it
shares confidence-downgrade and evidence-merging helpers. This module marks
the agent boundary for the multi-agent architecture.
"""

AGENT_NAME = "Validation Agent"
