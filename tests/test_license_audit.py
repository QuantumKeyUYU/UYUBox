from tools.license_audit import parse_requirements


def test_parse_requirements_skips_invalid():
    text = "flask>=2.0\n# comment\ninvalid-line!\n\n"
    reqs = parse_requirements(text)
    assert [r.name for r in reqs] == ["flask"]
