"""RAG Agent role.

The RAG node logic currently remains in security_graph.py because it shares
retry and quality-gate helpers. This module marks the agent boundary for the
multi-agent architecture and is ready for a later safe extraction.
"""

AGENT_NAME = "RAG Agent"
