"""The documentation site: its sidebar, the files it loads, and what pages.yml publishes."""

import os
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def sidebar_pages():
    """The pages _sidebar.md links, in order, as paths from the repository root."""
    links = re.findall(r"\]\(([^)]+)\)", (ROOT / "_sidebar.md").read_text())
    return ["README.md" if link == "/" else link.lstrip("/") for link in links]


def assemble(dest):
    """Run pages.yml's own copy step into dest, as the build job does."""
    steps = yaml.safe_load((ROOT / ".github" / "workflows" / "pages.yml").read_text())["jobs"]["build"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Assemble the site")
    subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=ROOT, env={**os.environ, "SITE": str(dest)},
                   check=True)
    return dest


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


def test_shell_runs_no_inline_script_under_a_strict_policy():
    # The dashboard carries upstream text: GitHub strips its HTML, Docsify inserts it as is.
    html = (ROOT / "index.html").read_text()
    content = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', html).group(1)
    policy = {name: values for name, *values in (d.split() for d in content.split(";") if d.strip())}
    cdn = sorted(set(re.findall(r'<script\b[^>]*\bsrc="(https://cdn\.jsdelivr\.net/npm/[^/]+/)', html)))
    assert policy["script-src"] == ["'self'", *cdn]
    assert policy["object-src"] == ["'none'"] and policy["base-uri"] == ["'none'"]
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", html)


def test_site_publishes_every_docs_page_and_resolves_its_links(tmp_path):
    site = assemble(tmp_path / "site")
    assert (site / "index.html").is_file() and (site / "_sidebar.md").is_file()
    for ref in re.findall(r'(?:src|href)="(?![a-z]+:)([^"]+)"', (site / "index.html").read_text()):
        assert (site / ref).is_file(), ref
    assert all((site / page).is_file() for page in sidebar_pages())
    assert {p.name for p in (site / "docs").glob("*.md")} == {p.name for p in (ROOT / "docs").glob("*.md")}
    for page in site.rglob("*.md"):
        text = page.read_text()
        for figure in re.findall(r'(?:src|srcset)="(?![a-z]+:|/)([^"]+)"', text):
            assert (page.parent / figure).is_file(), (page, figure)
        for link in re.findall(r"\]\((?![a-z]+:|#|/)([^)#]+\.md)(?:#[^)]*)?\)", text):
            assert (page.parent / link).is_file(), (page, link)
    assert not list(site.rglob("*.json"))


def test_search_keeps_its_own_index_beside_the_zircolite_site():
    # Both sites share the wagga40.github.io origin, where Docsify keeps one search database.
    assert re.search(r"search: \{[^}]*\bnamespace: 'zircolite-rules'", (ROOT / "site.js").read_text())
