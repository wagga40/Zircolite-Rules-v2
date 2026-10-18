import io
import subprocess
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import rule_sources
from rule_sources import fetch_source, resolve_revision

REVISION = "a" * 40
SPEC = {"repository": "example/rules", "branch": "main"}


def ls_remote(monkeypatch, *results):
    """Answer each git ls-remote call with the next (returncode, stdout) pair."""
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        code, stdout = results[len(calls) - 1]
        return subprocess.CompletedProcess(command, code, stdout, "fatal: unable to access")
    monkeypatch.setattr(rule_sources.subprocess, "run", run)
    monkeypatch.setattr(rule_sources.time, "sleep", lambda seconds: None)
    return calls


def archive(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for member, data in members:
            tar.addfile(member, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def regular(name, data):
    member = tarfile.TarInfo(name)
    member.size = len(data)
    return member, data


@pytest.fixture
def server(monkeypatch):
    """Serve queued (status, body) responses at ARCHIVE_URL and count requests."""
    responses, requests = [], []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            status, body = responses.pop(0)
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setattr(rule_sources, "ARCHIVE_URL",
                        f"http://127.0.0.1:{httpd.server_port}/{{repository}}/{{revision}}")
    yield responses, requests
    httpd.shutdown()


def test_the_branch_resolves_over_git_without_the_rest_api(monkeypatch):
    calls = ls_remote(monkeypatch, (0, f"{REVISION}\trefs/heads/main\n"))
    assert resolve_revision("example/rules", "main") == REVISION
    assert calls == [["git", "ls-remote", "--exit-code", "https://github.com/example/rules.git", "refs/heads/main"]]


def test_a_missing_branch_fails_without_retrying(monkeypatch):
    calls = ls_remote(monkeypatch, (2, ""))
    with pytest.raises(ValueError, match="Branch main not found in example/rules"):
        resolve_revision("example/rules", "main")
    assert len(calls) == 1


def test_a_network_error_is_retried(monkeypatch):
    calls = ls_remote(monkeypatch, (128, ""), (0, f"{REVISION}\trefs/heads/main\n"))
    assert resolve_revision("example/rules", "main") == REVISION
    assert len(calls) == 2
    ls_remote(monkeypatch, *[(128, "")] * rule_sources.ATTEMPTS)
    with pytest.raises(RuntimeError, match="unable to access"):
        resolve_revision("example/rules", "main")


def test_only_the_exact_branch_ref_is_accepted(monkeypatch):
    ls_remote(monkeypatch, (0, f"{'b' * 40}\trefs/heads/feature/refs/heads/main\n"))
    with pytest.raises(ValueError, match="not found"):
        resolve_revision("example/rules", "main")


def test_a_malformed_revision_is_rejected_before_download(tmp_path, monkeypatch):
    ls_remote(monkeypatch, (0, "abc\trefs/heads/main\n"))
    with pytest.raises(ValueError, match="complete commit SHA"):
        fetch_source(SPEC, tmp_path)


def test_a_server_error_is_retried_and_the_snapshot_cached(tmp_path, server):
    responses, requests = server
    responses += [(503, b"busy"), (200, archive([regular("rules-main/rules/a.yml", b"title: A\n")]))]
    root, revision = fetch_source(SPEC, tmp_path, REVISION)
    assert revision == REVISION and (root / "rules" / "a.yml").read_text() == "title: A\n"
    assert (root / ".complete").read_text() == REVISION + "\n"
    assert len(requests) == 2
    # An immutable commit is downloaded once.
    assert fetch_source(SPEC, tmp_path, REVISION) == (root, REVISION)
    assert len(requests) == 2


def test_an_archive_with_links_is_rejected(tmp_path, server):
    responses, _ = server
    link = tarfile.TarInfo("rules-main/rules/link.yml")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    responses.append((200, archive([regular("rules-main/rules/a.yml", b"title: A\n"), (link, None)])))
    with pytest.raises(ValueError, match="non-regular entries"):
        fetch_source(SPEC, tmp_path, REVISION)
    assert not (tmp_path / REVISION).exists()


@pytest.mark.parametrize("name", ["rules-main/../../escaped.yml", "/tmp/escaped.yml"])
def test_an_archive_entry_outside_its_directory_is_rejected(tmp_path, server, name):
    responses, _ = server
    responses.append((200, archive([regular("rules-main/rules/a.yml", b"title: A\n"), regular(name, b"x")])))
    with pytest.raises(ValueError, match="escapes the extraction directory"):
        fetch_source(SPEC, tmp_path / "cache", REVISION)
    assert not list(tmp_path.rglob("escaped.yml")) and not (tmp_path / "cache" / REVISION).exists()
