"""Regression checks for live evidence, filters, paging and recovery."""
from collections import Counter
import csv
from html.parser import HTMLParser
import io
import sqlite3
import time

import pytest

from pi import db
from pi.config import load_config
from pi.dashboard import app as dashboard


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    path = tmp_path / "live.db"
    monkeypatch.setitem(dashboard.app.config, "DB_PATH", str(path))
    config = load_config() | {"REAL_PASS": "test-secret-do-not-expose", "WEIGHT_FAILED_AUTH": "17"}
    monkeypatch.setattr(dashboard, "load_config", lambda: config)
    now = time.time()
    for i in range(8):
        malicious = i % 2 == 0
        db.add_event(now - 60 + i, "192.0.2.10" if malicious else "192.0.2.20",
                     "restrict" if malicious else "allow", 45 if malicious else 0,
                     "<script>alert('unsafe')</script>", path,
                     category="Brute Force" if malicious else "",
                     signal="failed_auth" if malicious else "", points=17 if malicious else 0)
    db.start_session("192.0.2.10", "decoy", now, path, profile="smart_lock")
    db.start_session("192.0.2.20", "real", now, path)
    return dashboard.app.test_client(), path, config


def test_server_filters_apply_to_all_evidence_and_csv(evidence):
    client, _, _ = evidence
    query = "ip=192.0.2.10&category=Brute+Force&risk=HIGH&action=restrict&since=0&limit=2"
    response = client.get("/api/event-feed?" + query)
    feed = response.get_json()
    assert feed["total"] == 4
    assert len(feed["events"]) == 2
    assert feed["has_more"]
    assert response.headers["Cache-Control"] == "no-store"
    export = client.get("/api/events/export.csv?" + query)
    rows = list(csv.DictReader(io.StringIO(export.data.decode("utf-8-sig"))))
    assert len(rows) == 4  # Export is all matching records, not just the current page.
    assert all(r["ip"] == "192.0.2.10" and r["signal"] == "failed_auth" for r in rows)
    assert client.get("/api/event-feed?ip=192.0.2.99").get_json()["total"] == 0
    for since in ("NaN", "inf", "-1", "bad"):
        assert client.get(f"/api/event-feed?since={since}").status_code == 400
    assert client.get("/api/event-feed?risk=UNKNOWN").status_code == 400


def test_paging_has_no_duplicates_when_new_events_arrive(evidence):
    client, path, _ = evidence
    first = client.get("/api/event-feed?limit=3").get_json()
    db.add_event(time.time(), "192.0.2.30", "allow", 0, "new", path)
    pages = [first]
    while pages[-1]["has_more"]:
        pages.append(client.get(f"/api/event-feed?limit=3&before={pages[-1]['next_before']}").get_json())
    ids = [r["rowid"] for page in pages for r in page["events"]]
    assert len(ids) == len(set(ids)) == 8
    assert ids == sorted(ids, reverse=True)
    assert client.get("/api/event-feed?limit=1").get_json()["events"][0]["rowid"] not in ids


def test_alert_generation_handles_reused_rowids_after_clear(evidence):
    client, path, _ = evidence
    old = client.get("/api/alerts").get_json()
    db.clear_evidence(path)
    # New IDs exceed the old cursor, so cursor-only reset detection would miss events.
    for i in range(12):
        db.add_event(time.time(), "192.0.2.40", "restrict", 45, "fresh", path,
                     category="Brute Force", signal="failed_auth", points=8)
    fresh = client.get(f"/api/alerts?after={old['cursor']}&generation={old['generation']}").get_json()
    assert fresh["generation"] != old["generation"]
    assert len(fresh["events"]) == 12
    assert fresh["events"][0]["rowid"] == 1


def test_health_policy_and_detail_views_report_actual_data(evidence):
    client, path, config = evidence
    health = client.get("/api/health").get_json()
    assert health["database"] == "connected" and health["latest_event"] is not None
    policy = client.get("/api/policy").get_json()
    assert policy["config"]["WEIGHT_FAILED_AUTH"] == "17"
    assert "REAL_PASS" not in policy["config"]
    assert config["REAL_PASS"] not in str(policy)
    config["WEIGHT_FAILED_AUTH"] = "19"
    assert client.get("/api/policy").get_json()["config"]["WEIGHT_FAILED_AUTH"] == "19"
    detail = client.get("/api/attacker/192.0.2.10?limit=2").get_json()
    assert len(detail["timeline"]) == 2
    assert detail["timeline"][0]["time"] <= detail["timeline"][1]["time"]
    last_observed = detail["last_observed"]
    db.checkpoint_scores([(time.time(), "192.0.2.10", 42, "restrict")], path)
    row = next(r for r in client.get("/api/attackers").get_json() if r["ip"] == "192.0.2.10")
    assert row["last_observed"] == last_observed
    assert row["last_seen"] > row["last_observed"]
    assert len(client.get("/api/sessions?backend=decoy&ip=192.0.2.10").get_json()) == 1
    assert client.get("/api/sessions?backend=real&ip=192.0.2.10").get_json() == []
    assert client.get("/api/risk/192.0.2.99").get_json()["error"]


class Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.in_title = False
        self.title_has_markup = False

    def handle_starttag(self, tag, attrs):
        if self.in_title:
            self.title_has_markup = True
        if tag == "title":
            self.in_title = True
        self.ids.extend(value for key, value in attrs if key == "id")

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False


def test_pages_have_unique_controls_and_safe_initial_data(evidence):
    client, _, _ = evidence
    for route in ("/", "/events", "/alerts", "/attackers", "/sessions", "/honeypot", "/settings",
                  "/policy", "/attacker/192.0.2.10"):
        response = client.get(route)
        assert response.status_code == 200
        parser = Markup()
        parser.feed(response.data.decode())
        assert not parser.title_has_markup, route
        assert not [key for key, count in Counter(parser.ids).items() if count > 1], route
        assert b"<script>alert('unsafe')</script>" not in response.data
        assert b"runtime.js" in response.data and b"views.js" in response.data


def test_database_failure_has_retryable_json_and_html(evidence, monkeypatch):
    client, _, _ = evidence
    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("locked")
    monkeypatch.setattr(db, "connect", unavailable)
    response = client.get("/api/stats")
    assert response.status_code == 503
    assert "unavailable" in response.get_json()["error"]
    assert client.get("/").status_code == 503


def test_stats_reuses_one_read_connection(evidence, monkeypatch):
    client, _, _ = evidence
    calls = []
    original = db.connect
    def connect(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(db, "connect", connect)
    assert client.get("/api/stats").status_code == 200
    assert len(calls) == 1


def test_device_status_distinguishes_fresh_from_stale_telemetry(evidence):
    client, path, _ = evidence
    db.update_device_state(time.time() - 60, "192.168.1.50", True, False, "esp32", path)
    stale = client.get("/api/stats").get_json()
    assert stale["device_state"]["locked"] == 1
    assert stale["device_online"] is False
    assert stale["device_age_seconds"] >= 60
    db.update_device_state(time.time(), "192.168.1.50", False, True, "esp32", path)
    fresh = client.get("/api/stats").get_json()
    assert fresh["device_online"] is True
    assert fresh["device_state"]["led_on"] == 1
    html = client.get("/").data
    assert html.index(b'id="real-device-status"') < html.index(b'class="stats"')
