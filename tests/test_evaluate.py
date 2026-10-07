from pathlib import Path

from pi import db
from pi.analysis.evaluate import evaluate


def test_evaluation_reports_observed_data_without_fabrication():
    path = Path("work/test-evaluate.db")
    truth = Path("work/test-ground-truth.csv")
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        candidate.unlink(missing_ok=True)
    db.add_event(10, "bad", "restrict", 45, "failed auth", path,
                 category="Brute Force", signal="failed_auth", points=8)
    db.add_event(11, "good", "allow", 0, "connection opened", path)
    db.start_session("bad", "decoy", 12, path, profile="smart_lock")
    db.add_decoy_message(13, "bad", "home/door/lock", "unlock", path)
    truth.write_text("ip,label\nbad,malicious\ngood,benign\nmissing,malicious\n", encoding="utf-8")
    result = evaluate(path, truth)
    assert result["detection_rate"] == 0.5
    assert result["false_positive_rate"] == 0.0
    assert result["database"]["events"] == 2
    assert result["decoy_engagement"]["messages"] == 1
    assert result["p50_response_latency_ms"] == 0
    assert result["p95_response_latency_ms"] == 0
