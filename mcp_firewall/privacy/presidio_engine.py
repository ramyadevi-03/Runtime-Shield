"""Shared Presidio engine initialization and health status."""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger("presidio_engine")

_lock = threading.Lock()
_analyzer: Any = None
_anonymizer: Any = None
_initialization_error: Exception | None = None


def get_presidio_instances() -> tuple[Any, Any]:
    global _analyzer, _anonymizer, _initialization_error

    with _lock:
        if _analyzer is not None and _anonymizer is not None:
            return _analyzer, _anonymizer
        if _initialization_error is not None:
            return None, None

        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import SpacyNlpEngine
            from presidio_anonymizer import AnonymizerEngine

            nlp_engine = SpacyNlpEngine(
                models=[{"lang_code": "en", "model_name": "en_core_web_sm"}]
            )
            _analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=["en"],
            )
            _anonymizer = AnonymizerEngine()
            logger.info("Presidio initialized successfully with en_core_web_sm.")
        except Exception as exc:
            _initialization_error = exc
            logger.exception("Presidio unavailable; regex fallback is active.")

        return _analyzer, _anonymizer


def get_pii_engine_status() -> dict[str, str]:
    if _analyzer is not None and _anonymizer is not None:
        return {
            "pii_engine": "presidio",
            "pii_status": "Presidio initialized successfully",
        }
    if _initialization_error is not None:
        return {
            "pii_engine": "regex_fallback",
            "pii_status": "Presidio unavailable - regex fallback active",
        }
    return {
        "pii_engine": "initializing",
        "pii_status": "Presidio initialization has not run",
    }
