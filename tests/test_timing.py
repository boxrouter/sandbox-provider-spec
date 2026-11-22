"""`v1.timing.lookup`: a flag that follows the task that entered it, nests and always resets."""

import asyncio

import pytest

from sandbox_provider_spec.v1.timing import in_lookup, lookup


def test_lookup_is_set_only_inside_the_block_and_nests() -> None:
    assert not in_lookup()
    with lookup():
        assert in_lookup()
        with lookup():
            assert in_lookup()
        assert in_lookup()
    assert not in_lookup()


def test_lookup_resets_when_the_block_raises() -> None:
    with pytest.raises(RuntimeError):
        with lookup():
            raise RuntimeError("provider refused")
    assert not in_lookup()


def test_a_task_started_before_the_block_does_not_see_it() -> None:
    async def scenario() -> tuple[bool, bool]:
        gate = asyncio.Event()
        seen: list[bool] = []

        async def before() -> None:
            await gate.wait()
            seen.append(in_lookup())

        task = asyncio.create_task(before())  # copies the context now, outside the block
        with lookup():
            gate.set()
            await task
            inside = in_lookup()
        return inside, seen[0]

    inside, other_task = asyncio.run(scenario())
    assert inside and not other_task
