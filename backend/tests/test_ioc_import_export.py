# -*- coding: utf-8 -*-
"""黑名单导入导出：文本/文件导入的归因统计、白名单豁免、CSV 导出内容。"""
from __future__ import annotations

import csv
import io


def _login(client) -> dict:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "Admin@123456"},
    )
    token = resp.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_import_ip_text(client, auth_headers):
    text = "\n".join([
        "45.33.20.10,扫描源",
        "45.33.20.11 # 暴力破解",
        "# 注释行",
        "",
        "45.33.20.10",  # 重复 → skipped
        "192.168.1.1",   # 内网 → error
        "not-an-ip",     # 非法 → error
    ])
    resp = client.post(
        "/api/v1/ioc/ips/import", headers=auth_headers,
        data={"text": text, "dispatch": "false"},
    )
    data = resp.json()["data"]
    assert data["created"] == 2
    assert data["skipped"] == 1
    assert data["task_count"] == 0
    assert len(data["errors"]) == 2

    lst = client.get("/api/v1/ioc/ips", headers=auth_headers).json()["data"]
    values = {i["normalized_value"]: i for i in lst["items"]}
    assert "45.33.20.10" in values
    assert values["45.33.20.10"]["source_type"] == "MANUAL"
    assert values["45.33.20.10"]["source_detail"].startswith("import:")
    assert values["45.33.20.10"]["remark"] == "扫描源"


def test_import_ip_whitelist_exemption(client, auth_headers):
    # 先加白名单再导入：命中白名单的不入库，且单独计数
    client.post("/api/v1/whitelist/ips", headers=auth_headers,
                json={"ip_value": "8.8.4.0/24"})
    resp = client.post(
        "/api/v1/ioc/ips/import", headers=auth_headers,
        data={"text": "8.8.4.5\n45.33.20.99", "dispatch": "false"},
    )
    data = resp.json()["data"]
    assert data["whitelisted"] == 1
    assert data["created"] == 1


def test_import_ip_file_upload_gbk(client, auth_headers):
    content = "45.33.21.50,文件导入\n".encode("gbk")
    resp = client.post(
        "/api/v1/ioc/ips/import", headers=auth_headers,
        data={"dispatch": "false"},
        files={"file": ("block.txt", io.BytesIO(content), "text/plain")},
    )
    data = resp.json()["data"]
    assert data["created"] == 1
    assert data["errors"] == []


def test_import_domain_dispatch_false_then_export(client, auth_headers):
    resp = client.post(
        "/api/v1/ioc/domains/import", headers=auth_headers,
        data={"text": "evil.example.com\n*.bad.cn,整批备注验证", "dispatch": "false",
              "remark": ""},
    )
    data = resp.json()["data"]
    assert data["created"] == 2

    # 整批备注生效在无行内备注的行上
    lst = client.get("/api/v1/ioc/domains", headers=auth_headers).json()["data"]
    by_value = {i["normalized_value"]: i for i in lst["items"]}
    assert by_value["evil.example.com"]["remark"] == "批量导入"
    assert by_value["*.bad.cn"]["remark"] == "整批备注验证"


def test_export_ip_csv_content(client, auth_headers):
    client.post("/api/v1/ioc/ips/import", headers=auth_headers,
                data={"text": "45.33.22.77,导出验证", "dispatch": "false"})
    resp = client.get("/api/v1/ioc/ips/export", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    body = resp.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(body)))
    assert rows[0][:2] == ["ioc_value", "status"]
    assert any(r[0] == "45.33.22.77" and r[8] == "导出验证" for r in rows[1:])


def test_export_ip_respects_filters(client, auth_headers):
    client.post("/api/v1/ioc/ips/import", headers=auth_headers,
                data={"text": "45.33.22.201\n45.33.22.202", "dispatch": "false"})
    resp = client.get("/api/v1/ioc/ips/export", headers=auth_headers,
                      params={"keyword": "45.33.22.201"})
    rows = list(csv.reader(io.StringIO(resp.content.decode("utf-8-sig"))))
    values = [r[0] for r in rows[1:]]
    assert "45.33.22.201" in values
    assert "45.33.22.202" not in values


def test_export_domain_csv(client, auth_headers):
    resp = client.get("/api/v1/ioc/domains/export", headers=auth_headers)
    assert resp.status_code == 200
    rows = list(csv.reader(io.StringIO(resp.content.decode("utf-8-sig"))))
    assert rows[0][0] == "ioc_value"
    # 域名导出不含归属地列
    assert "geo_country" not in rows[0]


def test_import_empty_rejected(client, auth_headers):
    resp = client.post("/api/v1/ioc/ips/import", headers=auth_headers,
                       data={"text": "  \n# 只有注释\n"})
    assert resp.json()["code"] != 0
