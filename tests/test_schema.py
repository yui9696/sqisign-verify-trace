import os

from sqvtrace import goldens, schema


def test_all_committed_vectors_load(vectors_dir):
    files = goldens.default_vector_files(vectors_dir)
    assert len(files) == 3, "expected goldens-lvl{1,3,5}.json"
    total = 0
    for path in files:
        data = goldens.load(path)
        assert "provenance" in data
        assert data["provenance"]["reference_commit_short"] == "dd133d7"
        total += len(data["vectors"])
    assert total == 300


def test_field_lengths_per_level(vectors_dir):
    for lv in schema.LEVELS:
        path = os.path.join(vectors_dir, f"goldens-lvl{lv}.json")
        data = goldens.load(path)
        assert len(data["vectors"]) == 100
        for vec in data["vectors"]:
            assert schema.is_valid_vector(vec, lv), schema.validate_vector(vec, lv)
            assert len(vec["E_aux"]) // 2 == schema.J_BYTES[lv]
            assert len(vec["E_com"]) // 2 == schema.J_BYTES[lv]
            assert len(vec["chk_chall"]) // 2 == schema.SCALAR_BYTES[lv]


def test_validator_catches_bad_length():
    vec = {
        "E_aux": "00" * 64,
        "E_chall": "00" * 64,
        "E_com": "00" * 63,  # wrong length
        "chk_chall": "00" * 32,
        "sig_chall": "00" * 32,
        "verdict": 1,
    }
    problems = schema.validate_vector(vec, 1)
    assert any("E_com" in p for p in problems)


def test_validator_catches_verdict_inconsistency():
    vec = {
        "E_aux": "11" * 64,
        "E_chall": "22" * 64,
        "E_com": "33" * 64,
        "chk_chall": "aa" * 32,
        "sig_chall": "bb" * 32,  # differs but verdict says accept
        "verdict": 1,
    }
    problems = schema.validate_vector(vec, 1)
    assert any("chk_chall != sig_chall" in p for p in problems)


def test_validator_rejects_non_hex_and_uppercase():
    assert not schema._is_hex("ZZ")
    assert not schema._is_hex("AABB")  # uppercase forbidden (canonical lowercase)
    assert not schema._is_hex("aab")   # odd length
    assert schema._is_hex("aabb")
