import os
import sys

import pytest

# Make the package importable without installation.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

VECTORS_DIR = os.path.join(ROOT, "vectors")
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


@pytest.fixture
def vectors_dir():
    return VECTORS_DIR


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def all_vectors():
    from sqvtrace import goldens

    return goldens.load_many(goldens.default_vector_files(VECTORS_DIR))
