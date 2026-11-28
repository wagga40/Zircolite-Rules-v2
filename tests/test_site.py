"""The documentation site: its sidebar, the files it loads, and what pages.yml publishes."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sidebar_pages():
    """The pages _sidebar.md links, in order, as paths from the repository root."""
    links = re.findall(r"\]\(([^)]+)\)", (ROOT / "_sidebar.md").read_text())
    return ["README.md" if link == "/" else link.lstrip("/") for link in links]


def test_sidebar_lists_every_page_from_the_repository_root():
    assert sidebar_pages() == ["README.md", "docs/dashboard.md", "docs/rulesets.md", "docs/sources.md",
                               "docs/maintenance.md", "experimental/README.md", "licenses/README.md"]
    assert all((ROOT / page).is_file() for page in sidebar_pages())
    # A relative link breaks under relativePath: true once you are on a page in docs/.
    assert not re.search(r"\]\((?!/)", (ROOT / "_sidebar.md").read_text())


def test_shell_loads_only_pinned_files_with_integrity():
    html = (ROOT / "index.html").read_text()
    tags = re.findall(r"<(?:script|link)\b[^>]*\b(?:src|href)=\"https?://[^>]*>", html)
    assert len(tags) == 7
    for tag in tags:
        assert re.search(r"https://cdn\.jsdelivr\.net/npm/[a-z]+@\d+\.\d+\.\d+/", tag), tag
        assert re.search(r'integrity="sha384-[A-Za-z0-9+/=]{64}"', tag), tag
        assert 'crossorigin="anonymous"' in tag, tag
