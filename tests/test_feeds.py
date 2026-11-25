from __future__ import annotations

import json

from netwatch.feedbuild import parse
from netwatch.feeds import FeedIndex


def _index(tmp_path, domains=(), ips=()):
    b = tmp_path / "bundle"
    b.mkdir()
    (b / "p.txt").write_text("\n".join(domains) + "\n")
    (b / "c.txt").write_text("\n".join(ips) + "\n")
    (b / "manifest.json").write_text(json.dumps({"built_at": "x", "feeds": [
        {"name": "phish", "kind": "domain", "category": "phishing", "file": "p.txt"},
        {"name": "c2", "kind": "ip", "category": "c2", "file": "c.txt"},
    ]}))
    return FeedIndex.load(b, None)


def test_domain_exact_and_parent(tmp_path):
    idx = _index(tmp_path, ["evil-bank.in"])
    assert idx.match_domain("evil-bank.in").exact
    hit = idx.match_domain("Login.Secure.EVIL-bank.in.")
    assert hit.indicator == "evil-bank.in" and not hit.exact and hit.confidence == "high"
    assert idx.match_domain("not-evil-bank.in") is None
    assert idx.match_domain("bank.in") is None  # never walks above the listed name


def test_parent_walk_stops_at_registrable_domain(tmp_path):
    idx = _index(tmp_path, ["co.in"])  # a public suffix must never match everything under it
    assert idx.match_domain("anything.co.in") is None


def test_shared_platform_is_low_confidence(tmp_path):
    idx = _index(tmp_path, ["sites.google.com"])
    assert idx.match_domain("sites.google.com").confidence == "low"


def test_ip_match(tmp_path):
    idx = _index(tmp_path, ips=["198.51.100.7"])
    assert idx.match_ip("198.51.100.7").category == "c2"
    assert idx.match_ip("198.51.100.8") is None


def test_builder_parsers_drop_shared_platform_urls():
    urls = "http://evil.example.net/login\nhttps://docs.google.com/forms/d/abc\nhttp://203.0.113.9/x\n# c\n"
    domains, ips, dropped = parse(urls, "urls")
    assert domains == {"evil.example.net"} and ips == {"203.0.113.9"} and dropped == 1
    hosts = "# hosts\n127.0.0.1\tmal.example.org\n127.0.0.1 localhost\n"
    assert parse(hosts, "hosts")[0] == {"mal.example.org"}
    assert parse("1.2.3.4\nnot-an-ip\n# x\n", "ips")[1] == {"1.2.3.4"}


def test_builder_from_downloaded_files_never_fetches(tmp_path, monkeypatch):
    from netwatch import feedbuild

    def no_network(url):
        raise AssertionError(f"fetched {url}")
    monkeypatch.setattr(feedbuild, "_fetch", no_network)
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "openphish.txt").write_text("https://login.evil-bank.example/x\n")
    (raw / "feodo_c2.txt").write_text("# list\n198.51.100.7\n")
    out = feedbuild.build(tmp_path / "bundles", raw_dir=raw)
    idx = FeedIndex.load(tmp_path / "bundles" / "current", None)
    assert out.parent / "current" == tmp_path / "bundles" / "current"
    assert idx.match_domain("login.evil-bank.example").category == "phishing"
    assert idx.match_ip("198.51.100.7").category == "c2"
