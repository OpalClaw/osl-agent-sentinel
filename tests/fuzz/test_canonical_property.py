"""Property-based tests for the canonical encoder."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from sentinel.utils.canonical import canonical_bytes, canonical_hash

json_atoms = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**31), max_value=2**31),
        st.text(max_size=20),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=5),
    ),
    max_leaves=10,
)


@given(json_atoms)
def test_canonical_is_deterministic(value):
    assert canonical_bytes(value) == canonical_bytes(value)
    assert canonical_hash(value) == canonical_hash(value)


@given(st.dictionaries(st.text(min_size=1, max_size=5), st.integers(), min_size=2, max_size=5))
def test_canonical_key_order_independent(d):
    reversed_d = dict(reversed(list(d.items())))
    assert canonical_bytes(d) == canonical_bytes(reversed_d)
