import sys

import pytest

import dependency_upgrade
from dependency_upgrade import lock_versions, pin_resolved, upgrade_changes

PYPROJECT = '''[project]
name = "rules"
dependencies = [
    "pysigma-backend-sqlite==2.1.1",
    "pysigma>=2.0.1,<3",
    "PySigma_Pipeline.Windows==2.0.0",
]

[tool.pdm.resolution.overrides]
pysigma = ">=2.0.1,<3"
'''


def lock(**versions):
    packages = "".join(f'[[package]]\nname = "{name}"\nversion = "{version}"\nsummary = "x"\n'
                       f'files = [{{file = "{name}-{version}.tar.gz", hash = "sha256:{"0" * 64}"}}]\n\n'
                       for name, version in versions.items())
    return f'[metadata]\ngroups = ["default"]\nstrategy = ["inherit_metadata"]\n\n{packages}'


LOCKED = lock(**{"pysigma-backend-sqlite": "2.1.1", "pysigma": "2.0.1", "pysigma-pipeline-windows": "2.0.0"})
RESOLVED = lock(**{"pysigma-backend-sqlite": "2.2.0", "pysigma": "2.1.0", "pysigma-pipeline-windows": "2.0.1"})


def test_only_exact_pins_move_to_the_resolved_versions():
    proposed = pin_resolved(PYPROJECT, RESOLVED)
    assert '"pysigma-backend-sqlite==2.2.0",' in proposed and '"PySigma_Pipeline.Windows==2.0.1",' in proposed
    assert '"pysigma>=2.0.1,<3",' in proposed and 'pysigma = ">=2.0.1,<3"' in proposed
    assert proposed.count("\n") == PYPROJECT.count("\n")


def test_an_upgrade_lists_its_version_changes():
    changes = upgrade_changes(PYPROJECT, pin_resolved(PYPROJECT, RESOLVED), LOCKED, RESOLVED)
    assert changes == [("pysigma", "2.0.1", "2.1.0"), ("pysigma-backend-sqlite", "2.1.1", "2.2.0"),
                       ("pysigma-pipeline-windows", "2.0.0", "2.0.1")]
    assert "| pysigma | 2.0.1 | 2.1.0 |" in dependency_upgrade.render_changes(changes)


@pytest.mark.parametrize("old,new", [
    ('"pysigma>=2.0.1,<3",', '"pysigma>=2.0.1",'),
    ('"pysigma-backend-sqlite==2.1.1",', '"pysigma-backend-sqlite @ https://example.org/x.whl",'),
    ('"pysigma-backend-sqlite==2.1.1",', '"evil==1.0",'),
    ('name = "rules"', 'name = "rules"\nscripts = {x = "y:z"}'),
    ('pysigma = ">=2.0.1,<3"', 'pysigma = ">=2.0.1"'),
])
def test_an_upgrade_that_changes_more_than_pins_is_refused(old, new):
    with pytest.raises(ValueError):
        upgrade_changes(PYPROJECT, PYPROJECT.replace(old, new), LOCKED, RESOLVED)


@pytest.mark.parametrize("old,new", [
    ('summary = "x"', 'summary = "x"\nurl = "https://example.org/pysigma.tar.gz"'),
    ('{file = "pysigma-2.1.0.tar.gz", hash', '{url = "https://example.org/a.tar.gz", file = "pysigma-2.1.0.tar.gz", hash'),
    ('strategy = ["inherit_metadata"]', 'strategy = ["static_urls"]'),
    ('version = "2.1.0"', 'version = "2.1.0 | rm -rf"'),
    ('hash = "sha256:' + "0" * 64, 'hash = "md5:' + "0" * 32),
    ('files = [{file = "pysigma-2.1.0.tar.gz"', 'files = []\nx = [{file = "pysigma-2.1.0.tar.gz"'),
])
def test_a_lock_from_outside_the_index_is_refused(old, new):
    tampered = RESOLVED.replace(old, new, 1)
    assert tampered != RESOLVED
    with pytest.raises(ValueError):
        upgrade_changes(PYPROJECT, pin_resolved(PYPROJECT, RESOLVED), LOCKED, tampered)


def test_the_cli_checks_an_upgrade_directory(tmp_path, monkeypatch, capsys):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    (tmp_path / "pdm.lock").write_text(LOCKED)
    upgrade = tmp_path / "upgrade"
    upgrade.mkdir()
    (upgrade / "pyproject.toml").write_text(pin_resolved(PYPROJECT, RESOLVED))
    (upgrade / "pdm.lock").write_text(RESOLVED)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["dependency_upgrade.py", "--check", "upgrade"])
    assert dependency_upgrade.main() == 0
    assert "| pysigma-pipeline-windows | 2.0.0 | 2.0.1 |" in capsys.readouterr().out
    (upgrade / "pdm.lock").write_text(LOCKED)
    (upgrade / "pyproject.toml").write_text(PYPROJECT)
    with pytest.raises(SystemExit, match="no package version"):
        dependency_upgrade.main()
    monkeypatch.setattr(sys, "argv", ["dependency_upgrade.py", "--same-versions", "pdm.lock", "upgrade/pdm.lock"])
    assert dependency_upgrade.main() == 0
    assert lock_versions(LOCKED) != lock_versions(RESOLVED)


def test_an_upgrade_that_adds_a_package_is_left_for_review():
    added = RESOLVED + lock(**{"typo-squat": "1.0"}).split("\n\n", 1)[1]
    with pytest.raises(ValueError, match="adds packages: typo-squat"):
        upgrade_changes(PYPROJECT, pin_resolved(PYPROJECT, RESOLVED), LOCKED, added)
