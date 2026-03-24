import json
import unicodedata
from importlib import resources

from transformers import pipeline


SEVERITY_ENGLISH_MODEL = "CIRCL/vulnerability-severity-classification-roberta-base"
SEVERITY_CHINESE_MODEL = "CIRCL/vulnerability-severity-classification-chinese-macbert-base"
CWE_MODEL = "CIRCL/cwe-parent-vulnerability-classification-roberta-base"

# Mapping Chinese labels to English equivalents
CHINESE_LABEL_MAP = {
    "高": "high",
    "中": "medium",
    "低": "low",
}


def _contains_chinese(text: str) -> bool:
    """Check if text contains Chinese characters."""
    for char in text:
        if "CJK" in unicodedata.name(char, ""):
            return True
    return False


class SeverityClassifier:
    """Lazy-loading wrapper around the CIRCL vulnerability severity models."""

    def __init__(self) -> None:
        self._english_pipeline = None
        self._chinese_pipeline = None

    @property
    def english_pipeline(self):
        if self._english_pipeline is None:
            self._english_pipeline = pipeline(
                "text-classification", model=SEVERITY_ENGLISH_MODEL
            )
        return self._english_pipeline

    @property
    def chinese_pipeline(self):
        if self._chinese_pipeline is None:
            self._chinese_pipeline = pipeline(
                "text-classification", model=SEVERITY_CHINESE_MODEL
            )
        return self._chinese_pipeline

    def classify(
        self, description: str, language: str | None = None
    ) -> dict:
        """Classify vulnerability severity from a text description.

        Args:
            description: The vulnerability description text.
            language: Force language selection ("en" or "zh").
                      If None, auto-detects based on text content.

        Returns:
            Dict with keys: label, score, model, language.
        """
        description = description.strip()
        if not description:
            raise ValueError("Description must not be empty.")

        if language is None:
            language = "zh" if _contains_chinese(description) else "en"

        if language == "zh":
            result = self.chinese_pipeline(description)[0]
            label = CHINESE_LABEL_MAP.get(result["label"], result["label"])
            model_used = SEVERITY_CHINESE_MODEL
        else:
            result = self.english_pipeline(description)[0]
            label = result["label"].lower()
            model_used = SEVERITY_ENGLISH_MODEL

        return {
            "label": label,
            "score": round(result["score"], 4),
            "model": model_used,
            "language": language,
        }


def _load_child_to_parent_mapping() -> dict[str, str]:
    data_files = resources.files("vulnmcp.data")
    mapping_file = data_files.joinpath("child_to_parent_mapping.json")
    return json.loads(mapping_file.read_text(encoding="utf-8"))


class CWEClassifier:
    """Lazy-loading wrapper around the CIRCL CWE classification model."""

    def __init__(self, top_k: int = 5) -> None:
        self.top_k = top_k
        self._pipeline = None
        self._child_to_parent: dict[str, str] | None = None

    @property
    def cwe_pipeline(self):
        if self._pipeline is None:
            self._pipeline = pipeline(
                "text-classification", model=CWE_MODEL
            )
        return self._pipeline

    @property
    def child_to_parent(self) -> dict[str, str]:
        if self._child_to_parent is None:
            self._child_to_parent = _load_child_to_parent_mapping()
        return self._child_to_parent

    def classify(self, description: str) -> dict:
        """Classify a vulnerability description into CWE categories.

        Args:
            description: The vulnerability description text.

        Returns:
            Dict with keys: primary_cwe, confidence, predictions, model.
        """
        description = description.strip()
        if not description:
            raise ValueError("Description must not be empty.")

        results = self.cwe_pipeline(description, top_k=self.top_k)

        predictions = []
        for r in results:
            cwe_id = r["label"]
            parent_cwe = self.child_to_parent.get(cwe_id, cwe_id)
            predictions.append({
                "cwe_id": f"CWE-{cwe_id}",
                "parent_cwe_id": f"CWE-{parent_cwe}",
                "score": round(r["score"], 4),
            })

        # Normalized confidence: gap between top and second prediction
        if len(predictions) >= 2:
            confidence = round(
                predictions[0]["score"] - predictions[1]["score"], 4
            )
        else:
            confidence = predictions[0]["score"] if predictions else 0.0

        return {
            "primary_cwe": predictions[0]["cwe_id"] if predictions else None,
            "confidence": confidence,
            "predictions": predictions,
            "model": CWE_MODEL,
        }
