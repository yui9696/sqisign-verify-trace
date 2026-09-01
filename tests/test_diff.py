import copy

from sqvtrace import diff


def _mk(level, index, **over):
    v = {
        "level": level,
        "index": index,
        "E_aux": "11" * 64,
        "E_chall": "22" * 64,
        "E_chall_after_2resp": "33" * 64,
        "E_com": "44" * 64,
        "chk_chall": "55" * 32,
        "sig_chall": "55" * 32,
        "verdict": 1,
    }
    v.update(over)
    return v


def test_identical_sets_have_no_divergence():
    a = [_mk(1, i) for i in range(5)]
    b = copy.deepcopy(a)
    rep = diff.diff_sets(a, b)
    assert rep.compared == 5
    assert rep.identical == 5
    assert rep.clean
    assert not rep.divergences


def test_changed_e_com_is_first_divergence_at_right_vector():
    a = [_mk(1, i) for i in range(5)]
    b = copy.deepcopy(a)
    b[3]["E_com"] = "99" * 64  # break vector index 3 at E_com
    rep = diff.diff_sets(a, b)
    assert not rep.clean
    assert len(rep.divergences) == 1
    d = rep.divergences[0]
    assert d.key == (1, 3)
    assert d.stage == "E_com"
    assert rep.first_stage_counts.get("E_com") == 1


def test_earlier_stage_wins_when_multiple_differ():
    a = [_mk(1, 0)]
    b = copy.deepcopy(a)
    b[0]["E_chall"] = "ab" * 64  # earlier
    b[0]["E_com"] = "cd" * 64    # also different, but later
    rep = diff.diff_sets(a, b)
    assert rep.divergences[0].stage == "E_chall"


def test_missing_stage_reported():
    a = [_mk(1, 0)]
    b = copy.deepcopy(a)
    del b[0]["E_com"]  # B verifier stopped before E_com
    rep = diff.diff_sets(a, b)
    d = rep.divergences[0]
    assert d.stage == "E_com"
    assert "only" in d.note


def test_only_in_one_side():
    a = [_mk(1, 0), _mk(1, 1)]
    b = [_mk(1, 0)]
    rep = diff.diff_sets(a, b)
    assert (1, 1) in rep.only_in_a
    assert not rep.clean
