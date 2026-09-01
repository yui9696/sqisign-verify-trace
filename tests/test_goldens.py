from sqvtrace import goldens


def test_self_check_all_300_pass(all_vectors):
    rep = goldens.self_check(all_vectors)
    assert rep.total == 300
    assert rep.passed == 300
    assert rep.failed == 0
    assert rep.ok
    for lv in (1, 3, 5):
        assert rep.by_level[lv]["passed"] == 100


def test_self_check_flags_a_broken_vector(all_vectors):
    broken = [dict(v) for v in all_vectors]
    # corrupt one E_com so verdict==1 no longer means chk==sig is enough:
    # change E_com length to trip the length check
    broken[0] = dict(broken[0])
    broken[0]["E_com"] = broken[0]["E_com"][:-2]
    rep = goldens.self_check(broken)
    assert rep.failed >= 1
    assert not rep.ok


def test_every_verdict_is_accept_and_chk_matches_sig(all_vectors):
    for v in all_vectors:
        assert v["verdict"] == 1
        assert v["chk_chall"] == v["sig_chall"]
        assert "E_com" in v


def test_e_com_distinct_per_level(all_vectors):
    for lv in (1, 3, 5):
        coms = [v["E_com"] for v in all_vectors if v["level"] == lv]
        assert len(coms) == 100
        assert len(set(coms)) == 100, "commitment curves should all differ"
