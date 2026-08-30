import pytest

from vulnmcp.skills import gcve

REGISTRY = [
    {"id": 1, "short_name": "CIRCL", "full_name": "CIRCL"},
    {"id": 2, "short_name": "Other", "full_name": "Other GNA"},
]


@pytest.fixture
def registry(monkeypatch):
    monkeypatch.setattr(gcve, "_ensure_registry", lambda: REGISTRY)


def test_gna_to_dict_fills_missing_fields():
    entry = gcve._gna_to_dict({"id": 1, "short_name": "CIRCL"})
    assert entry["id"] == 1
    assert entry["short_name"] == "CIRCL"
    assert entry["full_name"] == ""
    assert entry["gcve_api"] == ""


def test_list_gna_entries(registry):
    result = gcve.list_gna_entries()
    assert result["count"] == 2
    assert result["entries"][0]["short_name"] == "CIRCL"


def test_get_gna_entry_by_id(registry):
    assert gcve.get_gna_entry(id=1)["short_name"] == "CIRCL"


def test_get_gna_entry_by_short_name(registry):
    assert gcve.get_gna_entry(short_name="Other")["id"] == 2


def test_get_gna_entry_not_found(registry):
    result = gcve.get_gna_entry(id=99)
    assert result["error"] == "GNA entry not found"


def test_get_gna_entry_requires_an_argument():
    with pytest.raises(ValueError):
        gcve.get_gna_entry()
