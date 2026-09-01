import os

from sqvtrace import parse, schema


def test_parse_canned_trace(fixtures_dir):
    text = open(os.path.join(fixtures_dir, "trace_sample.txt")).read()
    vec = parse.parse_trace(text)
    assert vec["verdict"] == 1
    assert vec["result"] == 1
    assert len(vec["E_aux"]) // 2 == schema.J_BYTES[1]
    assert len(vec["E_com"]) // 2 == schema.J_BYTES[1]
    assert vec["chk_chall"] == vec["sig_chall"]
    # add level+index and it validates as a real level-1 vector
    vec = {"level": 1, "index": 0, **vec}
    assert schema.is_valid_vector(vec, 1), schema.validate_vector(vec, 1)


def test_parse_ignores_non_trace_lines():
    text = (
        "warning: some reference warning\n"
        "TRACE E_aux " + "ab" * 64 + "\n"
        "random noise\n"
        "TRACE verdict 1\n"
    )
    vec = parse.parse_trace(text)
    assert vec["E_aux"] == "ab" * 64
    assert vec["verdict"] == 1


def test_parse_stream_splits_on_result():
    text = (
        "TRACE E_aux " + "11" * 64 + "\n"
        "TRACE result 1\n"
        "TRACE E_aux " + "22" * 64 + "\n"
        "TRACE result 0\n"
    )
    vecs = parse.parse_trace_stream(text)
    assert len(vecs) == 2
    assert vecs[0]["E_aux"] == "11" * 64
    assert vecs[1]["result"] == 0


def test_parse_reject_stops_before_e_com():
    # a rejected verification never prints E_com/chk/sig/verdict
    text = (
        "TRACE E_aux " + "11" * 64 + "\n"
        "TRACE E_chall " + "22" * 64 + "\n"
        "TRACE E_chall_after_2resp " + "33" * 64 + "\n"
        "TRACE result 0\n"
    )
    vec = parse.parse_trace(text)
    assert "E_com" not in vec
    assert vec["result"] == 0
