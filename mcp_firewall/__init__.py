# MCP Firewall Package

"""Ensure that the local `mcp_firewall` package is used over any installed version.
This module modifies `sys.path` to prioritize the project root directory, then imports the local
`models` module so that classes like `DangerousChainConfig` are available.
"""

import os
import sys

# Add the repository root (containing this package) to the front of sys.path.
# This ensures that imports of `mcp_firewall.*` resolve to the local package first.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the local models module to make its symbols available at package level.
from . import models as _models

# Re-export key classes for convenience.
Action = _models.Action
Severity = _models.Severity
PipelineStage = _models.PipelineStage
ToolCallRequest = _models.ToolCallRequest
GatewayConfig = _models.GatewayConfig
DangerousChainConfig = getattr(_models, "DangerousChainConfig", None)

__all__ = [
    "Action",
    "Severity",
    "PipelineStage",
    "ToolCallRequest",
    "GatewayConfig",
    "DangerousChainConfig",
]
