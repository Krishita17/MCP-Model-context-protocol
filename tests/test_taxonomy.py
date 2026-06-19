"""Tests for the threat taxonomy."""

from taxonomy import TAXONOMY, BY_ID, owasp_coverage


def test_taxonomy_not_empty():
    assert len(TAXONOMY) > 0


def test_by_id_lookup():
    assert len(BY_ID) > 0
    first_id = list(BY_ID.keys())[0]
    assert BY_ID[first_id].id == first_id


def test_owasp_coverage():
    coverage = owasp_coverage()
    assert isinstance(coverage, dict)
    assert len(coverage) > 0
