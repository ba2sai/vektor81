"""Optional Microsoft Presidio adapter with graceful pure-stdlib fallback."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .detectors import (
    _detect_emails,
    _detect_natural_ids,
    _detect_passports,
    _detect_payment_cards,
    _detect_sensitive_health,
    _detect_swift_pa,
    analyze_text,
)

try:
    from presidio_analyzer import (
        AnalyzerEngine,
        EntityRecognizer,
        RecognizerRegistry,
        RecognizerResult,
    )
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    AnalyzerEngine = None  # type: ignore[assignment,misc]
    EntityRecognizer = object  # type: ignore[assignment,misc]
    RecognizerRegistry = None  # type: ignore[assignment,misc]
    RecognizerResult = None  # type: ignore[assignment,misc]
    NlpEngineProvider = None  # type: ignore[assignment,misc]


@dataclass
class PresidioFallbackResult:
    """Lightweight RecognizerResult-compatible object returned when Presidio is unavailable."""

    entity_type: str
    start: int
    end: int
    score: float
    recognition_metadata: dict[str, Any] = field(default_factory=dict)


def _to_recognizer_result(
    entity_type: str,
    start: int,
    end: int,
    score: float,
    metadata: dict[str, Any] | None = None,
) -> Any:
    if PRESIDIO_AVAILABLE and RecognizerResult is not None:
        return RecognizerResult(
            entity_type=entity_type,
            start=start,
            end=end,
            score=score,
            recognition_metadata=metadata or {},
        )
    return PresidioFallbackResult(
        entity_type=entity_type,
        start=start,
        end=end,
        score=score,
        recognition_metadata=metadata or {},
    )


class _BasePanamaRecognizer(EntityRecognizer):  # type: ignore[misc]
    """Base recognizer compatible with both Presidio EntityRecognizer and stdlib fallback."""

    def __init__(
        self,
        supported_entities: list[str],
        supported_language: str = "es",
        name: str | None = None,
        regulatory_profile: str = "ANTAI_LEY81",
    ) -> None:
        self.regulatory_profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
        if PRESIDIO_AVAILABLE and EntityRecognizer is not object:
            super().__init__(
                supported_entities=supported_entities,
                supported_language=supported_language,
                name=name or self.__class__.__name__,
            )
        else:
            self.supported_entities = list(supported_entities)
            self.supported_language = supported_language
            self.name = name or self.__class__.__name__

    def load(self) -> None:
        """No external NLP models required for deterministic Panama rules."""
        return None


class PanamaCedulaRucRecognizer(_BasePanamaRecognizer):
    """Detects Panama natural IDs while rejecting dates and corporate RUCs without CIP context."""

    ENTITIES = ["PA_IDENTIDAD_NATURAL"]

    def __init__(
        self,
        supported_language: str = "es",
        regulatory_profile: str = "ANTAI_LEY81",
    ) -> None:
        super().__init__(
            supported_entities=self.ENTITIES,
            supported_language=supported_language,
            name="PanamaCedulaRucRecognizer",
            regulatory_profile=regulatory_profile,
        )

    def analyze(
        self,
        text: str,
        entities: list[str] | None = None,
        nlp_artifacts: Any = None,
    ) -> list[Any]:
        if entities is not None and "PA_IDENTIDAD_NATURAL" not in entities:
            return []
        findings = _detect_natural_ids(text or "", self.regulatory_profile)
        return [
            _to_recognizer_result(
                f.entity_type,
                f.start,
                f.end,
                f.score,
                {"is_sensitive": f.is_sensitive, "context_matched": f.context_matched},
            )
            for f in findings
        ]


class PanamaPassportRecognizer(_BasePanamaRecognizer):
    """Detects Panama passport numbers only when passport context appears nearby."""

    ENTITIES = ["PA_PASAPORTE"]

    def __init__(
        self,
        supported_language: str = "es",
        regulatory_profile: str = "ANTAI_LEY81",
    ) -> None:
        super().__init__(
            supported_entities=self.ENTITIES,
            supported_language=supported_language,
            name="PanamaPassportRecognizer",
            regulatory_profile=regulatory_profile,
        )

    def analyze(
        self,
        text: str,
        entities: list[str] | None = None,
        nlp_artifacts: Any = None,
    ) -> list[Any]:
        if entities is not None and "PA_PASAPORTE" not in entities:
            return []
        findings = _detect_passports(text or "")
        return [
            _to_recognizer_result(
                f.entity_type,
                f.start,
                f.end,
                f.score,
                {"is_sensitive": f.is_sensitive, "context_matched": f.context_matched},
            )
            for f in findings
        ]


class PanamaSensitiveHealthRecognizer(_BasePanamaRecognizer):
    """Detects Ley 81 / Ley 68 sensitive health indicators paired with patient/identity terms."""

    ENTITIES = ["PA_DATO_SENSIBLE_SALUD"]

    def __init__(
        self,
        supported_language: str = "es",
        regulatory_profile: str = "ANTAI_LEY81",
    ) -> None:
        super().__init__(
            supported_entities=self.ENTITIES,
            supported_language=supported_language,
            name="PanamaSensitiveHealthRecognizer",
            regulatory_profile=regulatory_profile,
        )

    def analyze(
        self,
        text: str,
        entities: list[str] | None = None,
        nlp_artifacts: Any = None,
    ) -> list[Any]:
        if entities is not None and "PA_DATO_SENSIBLE_SALUD" not in entities:
            return []
        source = text or ""
        natural_findings = _detect_natural_ids(source, self.regulatory_profile)
        findings = _detect_sensitive_health(source, self.regulatory_profile, natural_findings)
        return [
            _to_recognizer_result(
                f.entity_type,
                f.start,
                f.end,
                f.score,
                {"is_sensitive": f.is_sensitive, "context_matched": f.context_matched},
            )
            for f in findings
        ]


class FallbackPanamaAnalyzer:
    """Pure-stdlib drop-in analyzer when Presidio or spaCy models are not installed."""

    def __init__(
        self,
        language: str = "es",
        regulatory_profile: str = "ANTAI_LEY81",
    ) -> None:
        self.language = language
        self.regulatory_profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
        self.presidio_available = False
        self.recognizers = [
            PanamaCedulaRucRecognizer(language, self.regulatory_profile),
            PanamaPassportRecognizer(language, self.regulatory_profile),
            PanamaSensitiveHealthRecognizer(language, self.regulatory_profile),
        ]

    def analyze(
        self,
        text: str,
        language: str | None = None,
        entities: list[str] | None = None,
        score_threshold: float = 0.0,
    ) -> list[PresidioFallbackResult]:
        """Analyze text using pure-Python detectors and return Presidio-shaped results."""
        findings = analyze_text(text or "", regulatory_profile=self.regulatory_profile)
        results: list[PresidioFallbackResult] = []
        allowed = set(entities) if entities is not None else None
        for finding in findings:
            if allowed is not None and finding.entity_type not in allowed:
                continue
            if finding.score < score_threshold:
                continue
            results.append(
                PresidioFallbackResult(
                    entity_type=finding.entity_type,
                    start=finding.start,
                    end=finding.end,
                    score=finding.score,
                    recognition_metadata={
                        "masked_value": finding.masked_value,
                        "value_sha256": finding.value_sha256,
                        "is_sensitive": finding.is_sensitive,
                        "context_matched": finding.context_matched,
                    },
                )
            )
        return results


def _build_auxiliary_recognizers(language: str, profile: str) -> list[Any]:
    """Build Presidio wrappers for payment cards, PA SWIFT codes, and emails."""

    class _AuxFinancialEmailRecognizer(_BasePanamaRecognizer):
        ENTITIES = ["PA_TARJETA_PAGO", "PA_SWIFT_PA", "EMAIL_PERSONAL"]

        def analyze(
            self,
            text: str,
            entities: list[str] | None = None,
            nlp_artifacts: Any = None,
        ) -> list[Any]:
            source = text or ""
            findings = [
                *_detect_swift_pa(source, self.regulatory_profile),
                *_detect_payment_cards(source, self.regulatory_profile),
                *_detect_emails(source),
            ]
            allowed = set(entities) if entities is not None else set(self.ENTITIES)
            return [
                _to_recognizer_result(f.entity_type, f.start, f.end, f.score)
                for f in findings
                if f.entity_type in allowed
            ]

    return [
        _AuxFinancialEmailRecognizer(
            supported_entities=_AuxFinancialEmailRecognizer.ENTITIES,
            supported_language=language,
            name="PanamaFinancialEmailRecognizer",
            regulatory_profile=profile,
        )
    ]


def build_panama_analyzer(
    language: str = "es",
    regulatory_profile: str = "ANTAI_LEY81",
) -> Any:
    """Build a Presidio AnalyzerEngine when available, or cleanly degrade to pure stdlib."""
    profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
    if not PRESIDIO_AVAILABLE or AnalyzerEngine is None or RecognizerRegistry is None:
        return FallbackPanamaAnalyzer(language=language, regulatory_profile=profile)

    try:
        registry = RecognizerRegistry(supported_languages=[language])
        for recognizer in (
            PanamaCedulaRucRecognizer(language, profile),
            PanamaPassportRecognizer(language, profile),
            PanamaSensitiveHealthRecognizer(language, profile),
            *_build_auxiliary_recognizers(language, profile),
        ):
            registry.add_recognizer(recognizer)

        nlp_engine = None
        if NlpEngineProvider is not None:
            for model_name in ("es_core_news_md", "es_core_news_sm", "en_core_web_sm"):
                try:
                    provider = NlpEngineProvider(
                        nlp_configuration={
                            "nlp_engine_name": "spacy",
                            "models": [{"lang_code": language, "model_name": model_name}],
                        }
                    )
                    nlp_engine = provider.create_engine()
                    break
                except (ImportError, OSError, ValueError, RuntimeError, SystemExit):
                    continue

        if nlp_engine is None:
            return FallbackPanamaAnalyzer(language=language, regulatory_profile=profile)

        return AnalyzerEngine(
            registry=registry,
            nlp_engine=nlp_engine,
            supported_languages=[language],
        )
    except (ImportError, OSError, ValueError, RuntimeError, SystemExit):
        return FallbackPanamaAnalyzer(language=language, regulatory_profile=profile)
