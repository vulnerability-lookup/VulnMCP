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


PARTNERS = [
    {
        "partner": "Computer Incident Response Center Luxembourg",
        "scope": "Vulnerabilities reported to CIRCL.",
        "program_role": "Root,CNA-LR,CNA",
        "organization_type": "CERT",
        "country": "Luxembourg",
        "metadata": {"short_name": "CIRCL", "cna_id": "CNA-1", "is_root": True},
    },
    {
        "partner": "Example Software",
        "scope": "Example products only.",
        "program_role": "CNA",
        "organization_type": "Vendor",
        "country": "Czech Republic",
        "metadata": {"short_name": "example", "cna_id": "CNA-2"},
    },
]


@pytest.fixture
def partners(monkeypatch):
    monkeypatch.setattr(gcve, "_ensure_cna_partners", lambda: PARTNERS)


def test_search_cna_partners_unfiltered_returns_all_trimmed(partners):
    result = gcve.search_cna_partners()
    assert result["count"] == 2
    assert result["partners"][0] == {
        "partner": "Computer Incident Response Center Luxembourg",
        "short_name": "CIRCL",
        "country": "Luxembourg",
        "program_role": "Root,CNA-LR,CNA",
        "organization_type": "CERT",
        "scope": "Vulnerabilities reported to CIRCL.",
    }
    # metadata is deliberately left out of list results
    assert "metadata" not in result["partners"][0]


def test_search_cna_partners_by_name_matches_short_name(partners):
    result = gcve.search_cna_partners(name="circl")
    assert result["count"] == 1
    assert result["partners"][0]["short_name"] == "CIRCL"


def test_search_cna_partners_filters_combine(partners):
    assert gcve.search_cna_partners(country="luxembourg")["count"] == 1
    assert gcve.search_cna_partners(program_role="cna-lr")["count"] == 1
    assert gcve.search_cna_partners(organization_type="vendor")["count"] == 1
    assert (
        gcve.search_cna_partners(country="Luxembourg", organization_type="Vendor")[
            "count"
        ]
        == 0
    )


def test_get_cna_partner_returns_full_record(partners):
    result = gcve.get_cna_partner(" CIRCL ")
    assert result["metadata"]["cna_id"] == "CNA-1"
    assert result["metadata"]["is_root"] is True


def test_get_cna_partner_short_name_is_exact(partners):
    result = gcve.get_cna_partner("circl")  # wrong case
    assert result == {"error": "CNA partner not found", "short_name": "circl"}
