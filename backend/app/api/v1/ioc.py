"""IOC 黑名单（IP / 域名）与 IP 白名单管理。

硬性规则：白名单优先、内网/保留地址禁止封禁、删除黑名单自动生成解封任务、
新增白名单自动对网段内已下发的黑名单生成解封任务。
"""
from __future__ import annotations

import csv
import io
import ipaddress
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate
from app.database import get_db, utcnow
from app.deps import get_current_user, require_perms
from app.engines.policy import (
    create_block_tasks_for_ioc,
    create_task,
    dispatch_tasks,
    unblock_existing_for_whitelist,
)
from app.engines.validation import check_whitelist, match_devices, validate_ioc
from app.models import IocDomainDetail, IocIndicator, IocIpDetail, IpWhitelist, SystemUser
from app.services import geoip
from app.schemas import (
    IocCreateIn,
    IocOut,
    IocUpdateIn,
    WhitelistCheckOut,
    WhitelistCreateIn,
    WhitelistImportIn,
    WhitelistOut,
)
from app.services.audit import write_audit

router = APIRouter(tags=["IOC 与白名单"])


def _parse_whitelist(value: str) -> tuple[str, str | None, bytes, int, int]:
    raw = (value or "").strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise BizError(f"非法白名单 IP/CIDR: {raw}")
    min_prefix = 8 if network.version == 4 else 32
    if network.prefixlen < min_prefix:
        raise BizError(f"白名单网段过大（最大允许 /{min_prefix}）: {raw}")
    is_cidr = "/" in raw
    return (
        str(network.network_address),
        str(network) if is_cidr else None,
        network.network_address.packed.ljust(16, b"\x00"),
        network.prefixlen,
        1 if is_cidr else 0,
    )


def _get_ioc(db: Session, ioc_id: int, ioc_type: str | None = None) -> IocIndicator:
    row = db.get(IocIndicator, ioc_id)
    if row is None or (ioc_type and row.ioc_type != ioc_type):
        raise BizError("IOC 记录不存在", 404, 404)
    return row


def _create_ioc(
    ioc_type: str,
    body: IocCreateIn,
    request: Request,
    db: Session,
    user: SystemUser,
):
    # 白名单优先：受保护地址先判定豁免，再进入合法性校验
    if ioc_type == "IP":
        try:
            addr = ipaddress.ip_network(body.ioc_value.strip(), strict=False).network_address
            hit, matched = check_whitelist(db, str(addr))
        except ValueError:
            hit, matched = False, None
        if hit:
            raise BizError(f"该 IP 命中白名单 {matched}，禁止加入黑名单", 403, 403)

    check = validate_ioc(ioc_type, body.ioc_value)
    if not check.ok:
        raise BizError(check.message, 400, 400)

    expire_at = body.expire_at
    if expire_at is None and body.duration_seconds:
        expire_at = utcnow() + timedelta(seconds=body.duration_seconds)

    # 手动新增与告警自动处置不同：同值只复用「仍在生效」的那条记录，
    # 已过期的历史流水保留不动，避免把历史记录改写成新的。
    row = (
        db.query(IocIndicator)
        .filter(
            IocIndicator.ioc_type == ioc_type,
            IocIndicator.normalized_value == check.normalized,
            IocIndicator.status == "active",
        )
        .order_by(IocIndicator.created_at.desc(), IocIndicator.id.desc())
        .first()
    )
    created = row is None
    if created:
        row = IocIndicator(
            ioc_type=ioc_type,
            ioc_value=check.normalized,
            normalized_value=check.normalized,
            created_by=user.username,
            source_type="MANUAL",
            source_detail=f"console:{user.username}",
            source_count=1,
        )
        db.add(row)
        db.flush()
        if ioc_type == "IP":
            db.add(
                IocIpDetail(
                    ioc_id=row.id,
                    ip_bin=check.ip_bin,
                    prefix_len=check.prefix_len,
                    address_family=check.address_family,
                    cidr=check.cidr,
                )
            )
        else:
            db.add(
                IocDomainDetail(
                    ioc_id=row.id,
                    match_mode=check.match_mode,
                    root_domain=check.root_domain,
                    is_wildcard=1 if check.is_wildcard else 0,
                )
            )
    row.status = "active"
    row.reject_reason = None
    # 归属地异步回填：入库与下发不等 geo 查询（见 app/services/geoip.schedule_fill）
    geo_pending: list[int] = [row.id] if ioc_type == "IP" else []
    row.confidence = body.confidence if body.confidence is not None else row.confidence
    row.risk_level = body.risk_level or row.risk_level
    row.expire_at = expire_at or row.expire_at
    row.tags = body.tags or row.tags
    row.remark = body.remark or row.remark
    db.flush()

    write_audit(
        db, "IOC_CREATE" if created else "IOC_UPDATE",
        operator=user.username, role_code=user.role_code,
        target_type=ioc_type, target_id=row.id,
        content={"value": check.normalized, "dispatch": body.dispatch},
        client_ip=client_ip(request),
    )

    task_ids: list[int] = []
    if body.dispatch:
        task_ids = create_block_tasks_for_ioc(
            db, row, operator=user.username, client_ip=client_ip(request)
        )
    else:
        db.commit()
    # 两种分支的提交都已完成，归属地回填交给后台线程
    geoip.schedule_fill(geo_pending)
    return ok({
        "item": IocOut.model_validate(row).model_dump(mode="json"),
        "created": created,
        "task_count": len(task_ids),
    })


def _unblock_ioc(db: Session, row: IocIndicator, request: Request, user: SystemUser) -> int:
    request_id = f"manual-{uuid.uuid4().hex[:16]}"
    task_ids: list[int] = []
    # 只有真正下发过的 active 记录才需要解封；rejected / whitelisted 只是留痕
    if row.status == "active":
        for device in match_devices(db, row.ioc_type, "UNBLOCK"):
            task = create_task(db, ioc=row, device=device, operation="UNBLOCK", request_id=request_id)
            if task:
                task_ids.append(task.id)
    row.status = "disabled"

    # 同 IP 可能有多条流水（同值不合并），设备侧按 IP 解封后其它活跃记录一并置为 disabled，
    # 否则列表会出现「仍显示 active 但设备上已经解封」的假象。
    siblings = (
        db.query(IocIndicator)
        .filter(
            IocIndicator.ioc_type == row.ioc_type,
            IocIndicator.normalized_value == row.normalized_value,
            IocIndicator.status == "active",
            IocIndicator.id != row.id,
        )
        .all()
    )
    for sibling in siblings:
        sibling.status = "disabled"
        sibling.reject_reason = f"随记录 {row.id} 一并解封"

    write_audit(
        db, "IOC_MANUAL_UNBLOCK", operator=user.username, role_code=user.role_code,
        target_type=row.ioc_type, target_id=row.id,
        content={"value": row.normalized_value, "task_count": len(task_ids), "siblings": len(siblings)},
        client_ip=client_ip(request),
    )
    db.commit()
    dispatch_tasks(task_ids)
    return len(task_ids)


def _ioc_query(
    ioc_type: str,
    db: Session,
    status: str | None,
    keyword: str | None,
    source_type: str | None = None,
    country: str | None = None,
):
    """列表与导出共用的过滤条件。"""
    stmt = select(IocIndicator).where(IocIndicator.ioc_type == ioc_type)
    if status:
        stmt = stmt.where(IocIndicator.status == status)
    if source_type:
        stmt = stmt.where(IocIndicator.source_type == source_type)
    if country:
        stmt = stmt.where(IocIndicator.geo_country == country)
    if keyword:
        stmt = stmt.where(
            or_(
                IocIndicator.normalized_value.like(f"%{keyword}%"),
                IocIndicator.remark.like(f"%{keyword}%"),
                IocIndicator.source_detail.like(f"%{keyword}%"),
                IocIndicator.alert_id.like(f"%{keyword}%"),
                IocIndicator.geo_country.like(f"%{keyword}%"),
                IocIndicator.geo_province.like(f"%{keyword}%"),
                IocIndicator.geo_city.like(f"%{keyword}%"),
            )
        )
    return stmt.order_by(IocIndicator.created_at.desc(), IocIndicator.id.desc())


def _list_ioc(
    ioc_type: str,
    db: Session,
    page: int,
    page_size: int,
    status: str | None,
    keyword: str | None,
    source_type: str | None = None,
    country: str | None = None,
):
    rows, total = paginate(_ioc_query(ioc_type, db, status, keyword, source_type, country), db, page, page_size)
    return ok({
        "items": [IocOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })


# ---------------------------------------------------------------- 导出 / 导入

_EXPORT_HEADERS_IP = [
    "ioc_value", "status", "source_type", "source_detail", "risk_level", "confidence",
    "created_at", "expire_at", "remark",
    "geo_country", "geo_province", "geo_city", "geo_isp",
]
_EXPORT_HEADERS_DOMAIN = [
    "ioc_value", "status", "source_type", "source_detail", "risk_level", "confidence",
    "created_at", "expire_at", "remark",
]


def _csv_cell(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def _export_ioc(
    ioc_type: str,
    db: Session,
    status: str | None,
    keyword: str | None,
    source_type: str | None = None,
    country: str | None = None,
) -> Response:
    """按当前筛选条件导出 CSV（UTF-8 BOM，Excel 直接打开不乱码）。"""
    rows = db.execute(_ioc_query(ioc_type, db, status, keyword, source_type, country)).scalars().all()
    headers = _EXPORT_HEADERS_IP if ioc_type == "IP" else _EXPORT_HEADERS_DOMAIN
    buf = io.StringIO()
    buf.write("\ufeff")
    writer = csv.writer(buf)
    writer.writerow(headers)
    for r in rows:
        writer.writerow([
            r.normalized_value, r.status, r.source_type or "", r.source_detail or "",
            r.risk_level or "", "" if r.confidence is None else r.confidence,
            _csv_cell(r.created_at), _csv_cell(r.expire_at), r.remark or "",
            *( [r.geo_country or "", r.geo_province or "", r.geo_city or "", r.geo_isp or ""]
               if ioc_type == "IP" else [] ),
        ])
    name = "blacklist-ip" if ioc_type == "IP" else "blacklist-domain"
    filename = f"{name}-{utcnow().strftime('%Y%m%d%H%M%S')}.csv"
    return Response(
        content=buf.getvalue().encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _read_upload_lines(file: UploadFile | None) -> list[str]:
    """读取上传文件，按行拆分；兼容 UTF-8（含 BOM）与 GBK 编码。"""
    if file is None:
        return []
    raw = file.file.read()
    if len(raw) > 2 * 1024 * 1024:
        raise BizError("导入文件过大（最大 2MB）", 400, 400)
    for encoding in ("utf-8-sig", "gbk"):
        try:
            return raw.decode(encoding).splitlines()
        except UnicodeDecodeError:
            continue
    raise BizError("无法识别文件编码，请使用 UTF-8 或 GBK 编码的文本/CSV 文件", 400, 400)


def _parse_import_line(line_no: int, line: str) -> tuple[str, str | None] | None:
    """支持三种写法：`1.2.3.4`、`1.2.3.4,备注`、`1.2.3.4 # 备注`；空行与 # 开头注释跳过。"""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    remark: str | None = None
    if "#" in text:
        text, _, tail = text.partition("#")
        remark = tail.strip() or None
    text = text.strip()
    if not text:
        return None
    if "," in text:
        value, _, tail = text.partition(",")
        value, remark = value.strip(), (tail.strip() or remark)
    else:
        parts = text.split(None, 1)
        value = parts[0]
        if len(parts) > 1:
            remark = parts[1].strip() or remark
    if not value:
        raise BizError(f"第 {line_no} 行: 值为空")
    return value, remark


def _import_ioc(
    ioc_type: str,
    db: Session,
    request: Request,
    user: SystemUser,
    file: UploadFile | None = None,
    text: str | None = None,
    dispatch: bool = True,
    duration_seconds: int | None = None,
    remark: str | None = None,
):
    lines = _read_upload_lines(file)
    if text:
        lines.extend(text.splitlines())
    if not lines or not [l for l in lines if l.strip() and not l.strip().startswith("#")]:
        raise BizError("导入内容为空：请粘贴文本或选择文件", 400, 400)
    if len(lines) > 5000:
        raise BizError("单次最多导入 5000 行", 400, 400)

    expire_at = (utcnow() + timedelta(seconds=duration_seconds)) if duration_seconds else None
    created, skipped, whitelisted, errors = 0, 0, 0, []
    new_rows: list[IocIndicator] = []
    geo_pending: list[int] = []

    for line_no, line in enumerate(lines, start=1):
        try:
            parsed = _parse_import_line(line_no, line)
        except BizError as exc:
            errors.append(exc.msg)
            continue
        if parsed is None:
            continue
        value, line_remark = parsed

        if ioc_type == "IP":
            try:
                addr = ipaddress.ip_network(value, strict=False).network_address
                hit, matched = check_whitelist(db, str(addr))
            except ValueError:
                hit, matched = False, None
            if hit:
                whitelisted += 1
                errors.append(f"第 {line_no} 行: {value} 命中白名单 {matched}，已跳过")
                continue

        check = validate_ioc(ioc_type, value)
        if not check.ok:
            errors.append(f"第 {line_no} 行: {check.message}")
            continue

        exists = (
            db.query(IocIndicator)
            .filter(
                IocIndicator.ioc_type == ioc_type,
                IocIndicator.normalized_value == check.normalized,
                IocIndicator.status == "active",
            )
            .first()
        )
        if exists:
            skipped += 1
            continue

        row = IocIndicator(
            ioc_type=ioc_type,
            ioc_value=check.normalized,
            normalized_value=check.normalized,
            created_by=user.username,
            source_type="MANUAL",
            source_detail=f"import:{user.username}",
            source_count=1,
            expire_at=expire_at,
            remark=remark or line_remark or "批量导入",
        )
        db.add(row)
        db.flush()
        if ioc_type == "IP":
            db.add(IocIpDetail(
                ioc_id=row.id, ip_bin=check.ip_bin, prefix_len=check.prefix_len,
                address_family=check.address_family, cidr=check.cidr,
            ))
            geo_pending.append(row.id)
        else:
            db.add(IocDomainDetail(
                ioc_id=row.id, match_mode=check.match_mode,
                root_domain=check.root_domain, is_wildcard=1 if check.is_wildcard else 0,
            ))
        new_rows.append(row)
        created += 1

    # 统一生成封禁任务：一次 request_id、一次提交、一次下发，避免逐行 commit
    task_ids: list[int] = []
    if dispatch and new_rows:
        request_id = f"import-{uuid.uuid4().hex[:16]}"
        for row in new_rows:
            for device in match_devices(db, row.ioc_type, "BLOCK"):
                task = create_task(
                    db, ioc=row, device=device, operation="BLOCK",
                    request_id=request_id, expire_at=row.expire_at,
                )
                if task:
                    task_ids.append(task.id)

    write_audit(
        db, "IOC_IMPORT", operator=user.username, role_code=user.role_code,
        target_type=ioc_type,
        content={"created": created, "skipped": skipped, "whitelisted": whitelisted,
                 "dispatch": dispatch, "task_count": len(task_ids), "errors": errors[:20]},
        client_ip=client_ip(request),
    )
    db.commit()
    dispatch_tasks(task_ids)
    geoip.schedule_fill(geo_pending)
    return ok({
        "created": created, "skipped": skipped, "whitelisted": whitelisted,
        "task_count": len(task_ids), "errors": errors,
    })


@router.get("/ioc/ips")
def list_ip_ioc(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    status: str | None = None,
    keyword: str | None = None,
    source_type: str | None = None,
    country: str | None = Query(None, description="按归属国家精确筛选，如 中国 / 美国"),
    db: Session = Depends(get_db),
    _=Depends(require_perms("ioc:read")),
):
    return _list_ioc("IP", db, page, page_size, status, keyword, source_type, country)


@router.get("/ioc/ips/export")
def export_ip_ioc(
    status: str | None = None,
    keyword: str | None = None,
    source_type: str | None = None,
    country: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("ioc:read")),
):
    return _export_ioc("IP", db, status, keyword, source_type, country)


@router.post("/ioc/ips/import")
def import_ip_ioc(
    request: Request,
    file: UploadFile | None = File(None),
    text: str | None = Form(None),
    dispatch: bool = Form(True),
    duration_seconds: int | None = Form(None),
    remark: str | None = Form(None),
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("ioc:*")),
):
    return _import_ioc("IP", db, request, user, file, text, dispatch, duration_seconds, remark)


@router.get("/ioc/domains/export")
def export_domain_ioc(
    status: str | None = None,
    keyword: str | None = None,
    source_type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("ioc:read")),
):
    return _export_ioc("DOMAIN", db, status, keyword, source_type)


@router.post("/ioc/domains/import")
def import_domain_ioc(
    request: Request,
    file: UploadFile | None = File(None),
    text: str | None = Form(None),
    dispatch: bool = Form(True),
    duration_seconds: int | None = Form(None),
    remark: str | None = Form(None),
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("ioc:*")),
):
    return _import_ioc("DOMAIN", db, request, user, file, text, dispatch, duration_seconds, remark)


@router.post("/ioc/ips")
def create_ip_ioc(
    body: IocCreateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("ioc:*")),
):
    return _create_ioc("IP", body, request, db, user)


@router.get("/ioc/ips/{ioc_id}")
def get_ip_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_perms("ioc:read")),
):
    return ok(IocOut.model_validate(_get_ioc(db, ioc_id, "IP")).model_dump(mode="json"))


@router.put("/ioc/ips/{ioc_id}")
def update_ip_ioc(
    ioc_id: int,
    body: IocUpdateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("ioc:*")),
):
    row = _get_ioc(db, ioc_id, "IP")
    for field in ("confidence", "risk_level", "expire_at", "tags", "remark", "status"):
        value = getattr(body, field)
        if value is not None:
            setattr(row, field, value)
    write_audit(
        db, "IOC_UPDATE", operator=user.username, role_code=user.role_code,
        target_type="IP", target_id=row.id,
        content=body.model_dump(exclude_none=True, mode="json"), client_ip=client_ip(request),
    )
    db.commit()
    return ok(IocOut.model_validate(row).model_dump(mode="json"))


@router.delete("/ioc/ips/{ioc_id}")
def delete_ip_ioc(
    ioc_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("ioc:*")),
):
    row = _get_ioc(db, ioc_id, "IP")
    task_count = _unblock_ioc(db, row, request, user)
    return ok({"id": ioc_id, "unblock_task_count": task_count})


@router.get("/ioc/domains")
def list_domain_ioc(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    status: str | None = None,
    keyword: str | None = None,
    source_type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("ioc:read")),
):
    return _list_ioc("DOMAIN", db, page, page_size, status, keyword, source_type)


@router.post("/ioc/domains")
def create_domain_ioc(
    body: IocCreateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("ioc:*")),
):
    return _create_ioc("DOMAIN", body, request, db, user)


@router.get("/ioc/domains/{ioc_id}")
def get_domain_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_perms("ioc:read")),
):
    return ok(IocOut.model_validate(_get_ioc(db, ioc_id, "DOMAIN")).model_dump(mode="json"))


@router.delete("/ioc/domains/{ioc_id}")
def delete_domain_ioc(
    ioc_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("ioc:*")),
):
    row = _get_ioc(db, ioc_id, "DOMAIN")
    task_count = _unblock_ioc(db, row, request, user)
    return ok({"id": ioc_id, "unblock_task_count": task_count})


@router.get("/whitelist/ips")
def list_whitelist(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    keyword: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("whitelist:read")),
):
    stmt = select(IpWhitelist)
    if keyword:
        stmt = stmt.where(IpWhitelist.ip_value.like(f"%{keyword}%"))
    stmt = stmt.order_by(IpWhitelist.created_at.desc())
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [WhitelistOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })


@router.get("/whitelist/ips/check")
def check_whitelist_api(
    ip: str = Query(..., min_length=2, max_length=64),
    db: Session = Depends(get_db),
    _=Depends(require_perms("whitelist:read")),
):
    hit, matched = check_whitelist(db, ip)
    return ok(WhitelistCheckOut(ip=ip, whitelisted=hit, matched=matched).model_dump())


@router.post("/whitelist/ips")
def create_whitelist(
    body: WhitelistCreateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("whitelist:*")),
):
    ip_value, cidr, ip_bin, prefix_len, cidr_flag = _parse_whitelist(body.ip_value)
    row = (
        db.query(IpWhitelist)
        .filter(IpWhitelist.ip_value == ip_value, IpWhitelist.prefix_len == prefix_len)
        .first()
    )
    created = row is None
    if created:
        row = IpWhitelist(
            ip_value=ip_value, cidr=cidr, ip_bin=ip_bin, prefix_len=prefix_len,
            cidr_flag=cidr_flag, status=1, created_by=user.username,
        )
        db.add(row)
    row.remark = body.remark or row.remark
    row.status = 1
    db.flush()

    write_audit(
        db, "WHITELIST_CREATE", operator=user.username, role_code=user.role_code,
        target_type="IP", target_id=cidr or ip_value,
        content={"unblock_existing": body.unblock_existing}, client_ip=client_ip(request),
    )
    task_count = 0
    if body.unblock_existing:
        task_count = unblock_existing_for_whitelist(
            db, cidr or ip_value, operator=user.username, client_ip=client_ip(request)
        )
    else:
        db.commit()
    return ok({
        "item": WhitelistOut.model_validate(row).model_dump(mode="json"),
        "created": created,
        "unblock_task_count": task_count,
    })


@router.post("/whitelist/ips/import")
def import_whitelist(
    body: WhitelistImportIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("whitelist:*")),
):
    created, skipped, errors = 0, 0, []
    for line_no, line in enumerate(body.text.splitlines(), start=1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            ip_value, cidr, ip_bin, prefix_len, cidr_flag = _parse_whitelist(entry)
        except BizError as exc:
            errors.append(f"第 {line_no} 行: {exc.msg}")
            continue
        exists = (
            db.query(IpWhitelist)
            .filter(IpWhitelist.ip_value == ip_value, IpWhitelist.prefix_len == prefix_len)
            .first()
        )
        if exists:
            skipped += 1
            continue
        db.add(
            IpWhitelist(
                ip_value=ip_value, cidr=cidr, ip_bin=ip_bin, prefix_len=prefix_len,
                cidr_flag=cidr_flag, status=1, created_by=user.username,
                remark="批量导入",
            )
        )
        created += 1
        unblock_existing_for_whitelist(
            db, cidr or ip_value, operator=user.username, client_ip=client_ip(request)
        )
    write_audit(
        db, "WHITELIST_IMPORT", operator=user.username, role_code=user.role_code,
        content={"created": created, "skipped": skipped, "errors": errors},
        client_ip=client_ip(request),
    )
    db.commit()
    return ok({"created": created, "skipped": skipped, "errors": errors})


@router.delete("/whitelist/ips/{wl_id}")
def delete_whitelist(
    wl_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("whitelist:*")),
):
    row = db.get(IpWhitelist, wl_id)
    if row is None:
        raise BizError("白名单记录不存在", 404, 404)
    write_audit(
        db, "WHITELIST_DELETE", operator=user.username, role_code=user.role_code,
        target_type="IP", target_id=row.cidr or row.ip_value, client_ip=client_ip(request),
    )
    db.delete(row)
    db.commit()
    return ok({"id": wl_id})
