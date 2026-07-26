"""
Governance Memory Layer for Runtime Shield AI Governance Framework.

Provides persistent short-term (per-session) and long-term (knowledge base)
memory using human-readable .md files, enabling pattern recognition, agent
profiling, and stateful governance decisions across sessions.

Components:
    - writer.py      : Records decisions to .md memory files
    - scanner.py     : Reads .md files to enrich real-time decisions
    - consolidator.py: Promotes short-term patterns to long-term memory
    - policy_advisor.py: Generates rule recommendations from memory
    - dedup_guard.py : Prevents rule duplication when switching policy engines
"""

__version__ = "1.0.0"
