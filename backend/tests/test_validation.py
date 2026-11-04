"""IOC 校验与白名单硬性边界单元测试。"""
from __future__ import annotations

from app.engines.validation import check_whitelist, validate_ioc
from app.database import SessionLocal


def test_reject_private_and_reserved_ip():
    for value in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.10"]:
        result = validate_ioc("IP", value)
        assert not result.ok, f"{value} 应被拒绝: {result.message}"


def test_reject_large_cidr():
    result = validate_ioc("IP", "8.0.0.0/8")
    assert not result.ok
    assert "网段过大" in result.message


def test_accept_public_ip_and_ip_bin():
    result = validate_ioc("IP", "8.8.8.8")
    assert result.ok
    assert result.normalized == "8.8.8.8"
    assert result.prefix_len == 32
    assert len(result.ip_bin) == 16


def test_domain_normalization():
    result = validate_ioc("DOMAIN", "*.Evil.Example.COM.")
    assert result.ok
    assert result.normalized == "*.evil.example.com"
    assert result.root_domain == "example.com"
    assert result.match_mode == "wildcard"


def test_reject_invalid_domain():
    assert not validate_ioc("DOMAIN", "not_a_domain").ok


def test_whitelist_contains_check():
    db = SessionLocal()
    try:
        hit, matched = check_whitelist(db, "198.51.100.10")
        assert hit
        assert matched is not None
        hit2, _ = check_whitelist(db, "8.8.8.8")
        assert not hit2
    finally:
        db.close()
