import pytest

from vulnmcp.models import classifier as classifier_module
from vulnmcp.models.classifier import (
    ATTACK_MODEL,
    CWE_MODEL,
    SEVERITY_CHINESE_MODEL,
    SEVERITY_ENGLISH_MODEL,
    SEVERITY_RUSSIAN_MODEL,
    AttackTechniqueClassifier,
    CWEClassifier,
    SeverityClassifier,
    _contains_chinese,
    _contains_cyrillic,
)


def test_language_detection_helpers():
    assert _contains_chinese("缓冲区溢出漏洞")
    assert not _contains_chinese("buffer overflow")
    assert _contains_cyrillic("уязвимость переполнения")
    assert not _contains_cyrillic("buffer overflow")


def fake_pipeline(label: str, score: float):
    return lambda text, **kwargs: [{"label": label, "score": score}]


class TestSeverityClassifier:
    def test_empty_description_rejected(self):
        with pytest.raises(ValueError):
            SeverityClassifier().classify("   ")

    def test_english_route(self):
        c = SeverityClassifier()
        c._english_pipeline = fake_pipeline("CRITICAL", 0.98765)
        result = c.classify("Remote code execution")
        assert result == {
            "label": "critical",
            "score": 0.9877,
            "model": SEVERITY_ENGLISH_MODEL,
            "language": "en",
        }

    def test_chinese_route_maps_labels(self):
        c = SeverityClassifier()
        c._chinese_pipeline = fake_pipeline("高", 0.9)
        result = c.classify("缓冲区溢出漏洞")
        assert result["label"] == "high"
        assert result["language"] == "zh"
        assert result["model"] == SEVERITY_CHINESE_MODEL

    def test_russian_route_autodetected(self):
        c = SeverityClassifier()
        c._russian_pipeline = fake_pipeline("HIGH", 0.8)
        result = c.classify("уязвимость переполнения буфера")
        assert result["label"] == "high"
        assert result["language"] == "ru"
        assert result["model"] == SEVERITY_RUSSIAN_MODEL

    def test_explicit_language_overrides_detection(self):
        c = SeverityClassifier()
        c._russian_pipeline = fake_pipeline("LOW", 0.7)
        result = c.classify("plain english text", language="ru")
        assert result["language"] == "ru"


class TestCWEClassifier:
    def test_classify_maps_parents_and_confidence(self, monkeypatch):
        c = CWEClassifier()
        c._pipeline = lambda text, top_k: [
            {"label": "79", "score": 0.6},
            {"label": "89", "score": 0.2},
        ]
        c._child_to_parent = {"79": "74", "89": "74"}
        result = c.classify("XSS in a web form")
        assert result["primary_cwe"] == "CWE-79"
        assert result["confidence"] == 0.4
        assert result["predictions"][0] == {
            "cwe_id": "CWE-79",
            "parent_cwe_id": "CWE-74",
            "score": 0.6,
        }
        assert result["model"] == CWE_MODEL

    def test_single_prediction_confidence_is_its_score(self):
        c = CWEClassifier()
        c._pipeline = lambda text, top_k: [{"label": "79", "score": 0.55}]
        c._child_to_parent = {}
        result = c.classify("XSS")
        assert result["confidence"] == 0.55
        # Unmapped CWE falls back to itself as parent
        assert result["predictions"][0]["parent_cwe_id"] == "CWE-79"

    def test_empty_description_rejected(self):
        with pytest.raises(ValueError):
            CWEClassifier().classify("")


class TestAttackTechniqueClassifier:
    def _classifier(self, scores):
        c = AttackTechniqueClassifier()
        c._pipeline = lambda text, **kwargs: [
            {"label": label, "score": score} for label, score in scores
        ]
        c._technique_names = {"T1059": "Command and Scripting Interpreter"}
        return c

    def test_threshold_splits_predictions(self):
        c = self._classifier([("T1059", 0.91), ("T1190", 0.5), ("T1003", 0.12)])
        result = c.classify("some vulnerability", top_k=2)
        assert result["predicted_techniques"] == ["T1059", "T1190"]
        assert len(result["techniques"]) == 2
        assert result["techniques"][0] == {
            "technique": "T1059",
            "name": "Command and Scripting Interpreter",
            "score": 0.91,
            "predicted": True,
        }
        assert result["techniques"][1]["name"] is None  # unknown ID
        assert result["model"] == ATTACK_MODEL

    def test_title_prepended_to_text(self):
        seen = {}

        c = AttackTechniqueClassifier()

        def pipe(text, **kwargs):
            seen["text"] = text
            return []

        c._pipeline = pipe
        c._technique_names = {}
        c.classify("description", title="Title")
        assert seen["text"] == "Title\ndescription"

    def test_empty_description_rejected(self):
        with pytest.raises(ValueError):
            AttackTechniqueClassifier().classify(" ")


def test_data_files_load():
    """The packaged JSON data files parse and have the expected shape."""
    names = classifier_module._load_technique_names()
    assert names, "attack_technique_names.json is empty"
    assert all(k.startswith("T") for k in names)

    mapping = classifier_module._load_child_to_parent_mapping()
    assert mapping, "child_to_parent_mapping.json is empty"
