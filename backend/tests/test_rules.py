from types import SimpleNamespace

from app.detection.rules import _detect_high_request_volume, _detect_repeated_failed_login_attempts

RULE = {"zscore_threshold": 1.5, "zscore_ceiling": 2.5, "confidence": 0.6}


def make_entries(background_count, target_respcodes):
    """`background_count` distinct IPs with 1 request each, plus one target IP
    ("10.1.1.99") with len(target_respcodes) requests. With a population of
    all-1s plus one outlier, z = sqrt(background_count) regardless of the
    outlier's request count, which makes the z-score easy to control here.
    """
    entries = [SimpleNamespace(cip=f"10.0.0.{i}", respcode="200") for i in range(background_count)]
    entries += [SimpleNamespace(cip="10.1.1.99", respcode=code) for code in target_respcodes]
    return entries


def test_flags_when_zscore_in_range_and_no_successful_responses():
    entries = make_entries(4, ["401", "403", "401"])  # z = sqrt(4) = 2.0, in (1.5, 2.5]

    result = _detect_repeated_failed_login_attempts(entries, RULE)

    assert len(result) == 3
    assert {e.cip for e, _ in result} == {"10.1.1.99"}
    assert all(confidence == 0.6 for _, confidence in result)


def test_does_not_flag_when_a_response_succeeded():
    entries = make_entries(4, ["401", "200", "401"])  # same z, but one 200 in the window

    result = _detect_repeated_failed_login_attempts(entries, RULE)

    assert result == []


def test_does_not_double_count_above_high_request_volume_ceiling():
    entries = make_entries(7, ["401", "403", "401"])  # z = sqrt(7) ~= 2.65, above the 2.5 ceiling

    result = _detect_repeated_failed_login_attempts(entries, RULE)
    assert result == []

    # Confirm the same population *is* high_request_volume's territory, so
    # this isn't just "the rule never fires" but a real handoff at 2.5.
    hrv_result = _detect_high_request_volume(entries, {"zscore_threshold": 2.5})
    assert "10.1.1.99" in {e.cip for e, _ in hrv_result}
