# tests/worker/test_ueba_features.py
import sys, os, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest
from unittest.mock import AsyncMock
from worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS,
    update_user_counters, update_ip_counters,
    build_user_vector_dict, build_ip_vector_dict,
)

def make_redis():
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.scard = AsyncMock(return_value=0)
    r.sismember = AsyncMock(return_value=False)
    r.incr = AsyncMock(return_value=1)
    r.expire = AsyncMock()
    r.sadd = AsyncMock()
    r.set = AsyncMock()
    return r

def test_user_feature_keys_length():
    assert len(USER_FEATURE_KEYS) == 8

def test_ip_feature_keys_length():
    assert len(IP_FEATURE_KEYS) == 7

def test_build_user_vector_dict_returns_all_keys():
    redis = make_redis()
    result = asyncio.run(build_user_vector_dict(redis, "alice", 10, 2))
    assert set(result.keys()) == set(USER_FEATURE_KEYS)

def test_build_ip_vector_dict_returns_all_keys():
    redis = make_redis()
    result = asyncio.run(build_ip_vector_dict(redis, "1.2.3.4", 5, 1))
    assert set(result.keys()) == set(IP_FEATURE_KEYS)

def test_failed_ratio_is_zero_when_no_logins():
    redis = make_redis()
    result = asyncio.run(build_user_vector_dict(redis, "alice", 0, 0))
    assert result["failed_ratio"] == 0.0

def test_failed_ratio_computed_correctly():
    redis = make_redis()
    result = asyncio.run(build_user_vector_dict(redis, "alice", 4, 2))
    assert result["failed_ratio"] == pytest.approx(0.5)

def test_ip_failed_ratio_computed_correctly():
    redis = make_redis()
    result = asyncio.run(build_ip_vector_dict(redis, "1.2.3.4", 10, 3))
    assert result["failed_ratio"] == pytest.approx(0.3)
