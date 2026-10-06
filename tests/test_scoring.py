from pi.proxy.scoring import RiskScorer, ScoreConfig


def config(**changes):
    values = ScoreConfig().__dict__ | changes
    return ScoreConfig(**values)


def test_whitelist_always_zero():
    scorer = RiskScorer(config(whitelist=frozenset({"good"})), clock=lambda: 1.0)
    scorer.record_wildcard("good")
    scorer.record_failed_auth("good")
    scorer.record_command_publish("good")
    assert scorer.score("good") == 0
    assert scorer.action("good") == "allow"


def test_linear_decay_and_thresholds():
    scorer = RiskScorer(config(decay_per_second=1), clock=lambda: 10.0)
    scorer.record_wildcard("bad", now=10)
    assert scorer.action("bad", now=10) == "throttle"
    assert scorer.score("bad", now=14) == 21
    assert scorer.score("bad", now=15) == 20
    assert scorer.action("bad", now=15) == "allow"


def test_four_adaptive_actions():
    scorer = RiskScorer(config(decay_per_second=0, medium=21, high=41, critical=51), clock=lambda: 1.0)
    assert scorer.action("bad") == "allow"
    scorer._add("bad", 21)
    assert scorer.action("bad") == "throttle"
    scorer._add("bad", 20)
    assert scorer.action("bad") == "restrict"
    scorer._add("bad", 10)
    assert scorer.action("bad") == "decoy"


def test_connection_rate_awarded_once_per_window():
    scorer = RiskScorer(config(connection_limit=2, connection_window=10), clock=lambda: 0.1)
    assert scorer.record_connection("bad", 0.1)[1] is False
    assert scorer.record_connection("bad", 1)[1] is False
    assert scorer.record_connection("bad", 2) == (15, True)
    assert scorer.record_connection("bad", 3)[1] is False
    assert scorer.record_connection("bad", 13.1)[1] is False


def test_failed_auth_cap():
    scorer = RiskScorer(config(decay_per_second=0), clock=lambda: 1.0)
    awarded = [scorer.record_failed_auth("bad")[1] for _ in range(7)]
    assert awarded == [8, 8, 8, 8, 8, 0, 0]
    assert scorer.score("bad") == 40


def test_all_signals_and_high_threshold():
    scorer = RiskScorer(config(decay_per_second=0, blacklist=frozenset({"bad"})), clock=lambda: 1.0)
    assert scorer.apply_blacklist("bad") == (30, True)
    assert scorer.apply_blacklist("bad") == (30, False)
    assert scorer.record_wildcard("bad") == 55
    assert scorer.record_command_publish("bad") == 75
    assert scorer.action("bad") == "decoy"


def test_default_attack_flood_and_auth_reaches_high():
    scorer = RiskScorer(config(decay_per_second=0), clock=lambda: 1.0)
    for _ in range(11):
        scorer.record_connection("attacker")
    for _ in range(5):
        scorer.record_failed_auth("attacker")
    assert scorer.score("attacker") == 55
    assert scorer.action("attacker") == "decoy"


def test_forced_decoy_ignores_score():
    scorer = RiskScorer(config(force_decoy=frozenset({"demo"})), clock=lambda: 1.0)
    assert scorer.action("demo") == "decoy"


def test_enumeration_publish_rate_and_sequences():
    scorer = RiskScorer(config(
        decay_per_second=0, topic_enumeration_limit=2, publish_limit=2,
        topic_enumeration_weight=12, publish_rate_weight=15,
        command_sequence_weight=15,
    ), clock=lambda: 1.0)
    assert scorer.record_topic("bad", "a")[1] is False
    assert scorer.record_topic("bad", "b")[1] is False
    assert scorer.record_topic("bad", "c") == (12, True)
    assert scorer.record_publish("bad")[1] is False
    assert scorer.record_publish("bad")[1] is False
    assert scorer.record_publish("bad") == (27, True)
    scorer.record_wildcard("bad")
    assert scorer.record_command_sequence("bad")[1] is True
    assert scorer.record_command_sequence("bad")[1] is False


def test_malformed_short_session_decoy_feedback_and_seed():
    scorer = RiskScorer(config(decay_per_second=0, short_session_cap=6), clock=lambda: 1.0)
    assert scorer.record_malformed("bad") == 12
    assert [scorer.record_short_session("bad")[1] for _ in range(3)] == [3, 3, 0]
    assert scorer.record_decoy_engagement("bad")[1] is True
    assert scorer.record_decoy_engagement("bad")[1] is False
    restored = RiskScorer(config(decay_per_second=0), clock=lambda: 2.0)
    restored.seed("bad", scorer.score("bad"))
    assert restored.score("bad") == scorer.score("bad")

