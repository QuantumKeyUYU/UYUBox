from pathlib import Path


def test_contributing_sections():
    text = Path("CONTRIBUTING.md").read_text(encoding="utf-8")
    for heading in ["## Linting", "## Testing", "## Commits"]:
        assert heading in text
