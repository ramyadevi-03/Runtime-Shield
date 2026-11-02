"""PII detector — detect personally identifiable information in tool responses using Microsoft Presidio NLP."""

from __future__ import annotations

import logging
import json
import re
from typing import Any

from ..base import OutboundStage
from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallResponse,
)
from ...privacy.presidio_engine import get_presidio_instances

logger = logging.getLogger("pii_detector")


def redact_json_structure(data: Any, redact_fn) -> Any:
    if isinstance(data, dict):
        return {k: redact_json_structure(v, redact_fn) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_json_structure(item, redact_fn) for item in data]
    elif isinstance(data, str):
        if data.strip():
            return redact_fn(data)
        return data
    else:
        return data


def redact_text_or_json(text: str, redact_raw_fn) -> str:
    try:
        stripped = text.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            data = json.loads(stripped)
            redacted_data = redact_json_structure(data, lambda t: redact_text_or_json(t, redact_raw_fn))
            return json.dumps(redacted_data)
    except Exception:
        pass
    return redact_raw_fn(text)


class PIIDetector(OutboundStage):
    """Detect and optionally redact PII in tool responses using Microsoft Presidio NLP (no regex)."""

    stage = PipelineStage.PII_DETECTOR

    def scan(
        self, response: ToolCallResponse, config: GatewayConfig
    ) -> tuple[ToolCallResponse, PipelineDecision | None]:
        if not config.pii.enabled:
            return response, None

        findings: list[str] = []
        modified = False

        analyzer, anonymizer = get_presidio_instances()
        # Extract Presidio configuration
        cfg_entities = getattr(config.pii, "presidio_entities", [])
        entities = None
        if cfg_entities and cfg_entities != ["ALL"]:
            entities = cfg_entities

        exclude_entities = getattr(config.pii, "presidio_exclude_entities", []) or []
        raw_operators = getattr(config.pii, "presidio_operators", {}) or {}
        default_placeholder = config.pii.placeholder

        def replace_matches(text: str, pattern: str, placeholder: str) -> tuple[str, int]:
            try:
                return re.subn(pattern, placeholder, text)
            except re.error as exc:
                logger.error("Invalid configured PII regex fallback %r: %s", pattern, exc)
                return text, 0

        def redact_raw_text(text: str) -> str:
            nonlocal modified
            try:
                results = analyzer.analyze(text=text, language="en", entities=entities)
                results = [r for r in results if r.score >= 0.3]
                if exclude_entities:
                    results = [r for r in results if r.entity_type not in exclude_entities]

                if results:
                    for r in results:
                        findings.append(r.entity_type)

                    if config.pii.action == Action.REDACT:
                        operators = {
                            ent: OperatorConfig("replace", {"new_value": val})
                            for ent, val in raw_operators.items()
                        }
                        default_op = OperatorConfig("replace", {"new_value": default_placeholder})
                        for result in results:
                            if result.entity_type not in operators:
                                operators[result.entity_type] = default_op

                        anonymized = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
                        if anonymized.text != text:
                            modified = True
                            return anonymized.text
            except Exception as exc:
                logger.error("Error in Presidio scan (%s)", type(exc).__name__)
            return text

        if analyzer and anonymizer:
            from presidio_anonymizer.entities import OperatorConfig

            for i, content_item in enumerate(response.content):
                text = content_item.get("text", "")
                if not text:
                    continue

                new_text = redact_text_or_json(text, redact_raw_text)
                if new_text != text:
                    response.content[i] = {**content_item, "text": new_text}

        if config.pii.action == Action.REDACT:
            for i, content_item in enumerate(response.content):
                text = content_item.get("text", "")
                if not text:
                    continue

                for fallback in getattr(config.pii, "outbound_patterns", []):
                    pattern = fallback.get("pattern", "")
                    if not pattern:
                        continue
                    placeholder = fallback.get("placeholder", default_placeholder)
                    text, match_count = replace_matches(text, pattern, placeholder)
                    if match_count:
                        findings.append(fallback.get("name", "configured regex fallback"))
                        modified = True

                if text != content_item.get("text", ""):
                    response.content[i] = {**content_item, "text": text}

        if not findings:
            return response, None

        unique = list(dict.fromkeys(findings))
        decision = PipelineDecision(
            stage=self.stage,
            action=config.pii.action,
            reason=f"PII detected via Presidio and/or configured regex fallbacks: {', '.join(unique)}",
            severity=config.pii.severity,
            details={"pii_types": unique, "modified": modified},
        )
        return response, decision
