#!/usr/bin/env python
"""给存量黑名单回填 IP 归属地（国家 / 省 / 市 / 运营商）。

默认只处理还没有归属地的 IP 记录（幂等，可反复执行）；
加 `--all` 则按当前库重新计算全部记录（换库或修数据后使用）。

用法（仓库根目录）：

    python scripts/backfill_geo.py                 # 只补空的
    python scripts/backfill_geo.py --all           # 全量重算
    python scripts/backfill_geo.py --dry-run       # 只统计不写库

数据库连接取 `DATABASE_URL` 环境变量，与后端服务一致。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import or_  # noqa: E402

from app.database import SessionLocal, init_db  # noqa: E402
from app.models import IocIndicator  # noqa: E402
from app.services import geoip  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="回填黑名单 IP 归属地")
    parser.add_argument("--all", action="store_true", help="全量重算（默认只补空的）")
    parser.add_argument("--batch", type=int, default=500, help="每批提交条数")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写库")
    args = parser.parse_args()

    health = geoip.health()
    print(f"归属地库：{health['db_path']}")
    print(f"  存在={health['db_exists']} 大小={health['db_size_kb']} KB 更新时间={health['db_mtime']}")
    if not health["db_exists"]:
        print("库文件不存在，先执行：python scripts/fetch_geoip.py")
        return 1
    if not health["enabled"]:
        print("GEOIP_ENABLED=false，归属地功能已关闭")
        return 1

    # 先把结构补齐（SQLite 老库缺 geo_* 列时自动加列，MySQL 请先跑 sql 迁移脚本）
    init_db()

    db = SessionLocal()
    try:
        query = db.query(IocIndicator).filter(IocIndicator.ioc_type == "IP")
        if not args.all:
            query = query.filter(
                or_(IocIndicator.geo_country.is_(None), IocIndicator.geo_country == "")
            )
        total = query.count()
        print(f"待处理 {total} 条（{'全量重算' if args.all else '仅补空'}）")
        if args.dry_run or total == 0:
            return 0

        done = 0
        hit = 0
        last_id = 0
        while True:
            rows = (
                query.filter(IocIndicator.id > last_id)
                .order_by(IocIndicator.id)
                .limit(args.batch)
                .all()
            )
            if not rows:
                break
            for row in rows:
                last_id = row.id
                info = geoip.lookup(row.normalized_value)
                done += 1
                if info is None:
                    continue
                row.geo_country = info.country
                row.geo_province = info.province
                row.geo_city = info.city
                row.geo_isp = info.isp
                hit += 1
            db.commit()
            print(f"  已处理 {done}/{total}，命中 {hit}")
        print(f"完成：处理 {done} 条，写入归属地 {hit} 条，未命中 {done - hit} 条")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
