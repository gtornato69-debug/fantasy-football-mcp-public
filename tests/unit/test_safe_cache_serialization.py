"""Regression tests for non-executable persistent cache serialization."""

import json
import stat
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from src.agents.cache_manager import CACHE_FORMAT_VERSION, CacheEntry, CacheManagerAgent


def make_manager(tmp_path):
    settings = SimpleNamespace(cache_dir=tmp_path, cache_ttl_seconds=300)
    return CacheManagerAgent(settings)


@pytest.mark.asyncio
async def test_file_cache_round_trip_uses_owner_only_json(tmp_path):
    manager = make_manager(tmp_path)
    entry = CacheEntry(
        key="league:1",
        value={"players": ["A", "B"], "week": 4},
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        tags=["league"],
    )
    manager._entries[entry.key] = entry

    assert await manager._set_in_file_cache(entry.key, entry)
    cache_file = manager._file_cache_path / f"{manager._hash_key(entry.key)}.json"
    assert stat.S_IMODE(cache_file.stat().st_mode) == 0o600
    assert json.loads(cache_file.read_text())["format_version"] == CACHE_FORMAT_VERSION
    assert await manager._get_from_file_cache(entry.key) == entry.value


@pytest.mark.asyncio
async def test_corrupt_or_wrong_key_cache_entry_fails_closed(tmp_path):
    manager = make_manager(tmp_path)
    entry = CacheEntry(
        key="expected",
        value={"safe": True},
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    manager._entries[entry.key] = entry
    cache_file = manager._file_cache_path / f"{manager._hash_key(entry.key)}.json"
    cache_file.write_text(
        json.dumps({**manager._entry_to_payload(entry), "key": "attacker"})
    )
    assert await manager._get_from_file_cache(entry.key) is None


def test_legacy_pickle_is_quarantined_without_deserialization(tmp_path):
    manager = make_manager(tmp_path)
    legacy = manager._file_cache_path / "attacker.pkl"
    legacy.write_bytes(b"cos\\nsystem\\n(S'false'\\ntR.")

    manager._quarantine_legacy_cache_files()

    assert not legacy.exists()
    quarantined = manager._file_cache_path / "attacker.pkl.disabled"
    assert quarantined.read_bytes() == b"cos\\nsystem\\n(S'false'\\ntR."
    assert stat.S_IMODE(quarantined.stat().st_mode) == 0o600


def test_unsupported_object_type_is_rejected(tmp_path):
    manager = make_manager(tmp_path)

    class ArbitraryObject:
        pass

    with pytest.raises(TypeError, match="Unsupported cache value type"):
        manager._estimate_size(ArbitraryObject())
