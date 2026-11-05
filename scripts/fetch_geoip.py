#!/usr/bin/env python
"""下载 ip2region 离线归属地库（IPv4 xdb）。

用法（在仓库根目录执行）：

    python scripts/fetch_geoip.py            # 下载到 backend/data/ip2region_v4.xdb
    python scripts/fetch_geoip.py --force    # 忽略已存在的库，重新下载
    python scripts/fetch_geoip.py --path D:/geoip/ip2region_v4.xdb

脚本按顺序尝试多个镜像（jsdelivr 的国内节点通常最快，GitHub 原站长期不通时
会自动跳过），下载到临时文件后校验文件头与体积，通过才替换正式文件——
避免半截文件被服务当成有效库加载。

数据由 ip2region 社区维护、随开源仓库发布（代码 Apache-2.0），
内部生产使用免费；如需对外分发数据本身，请自行再确认其数据条款。
详见 docs/geoip.md。
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import requests

MIRRORS = [
    "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
    "https://fastly.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
    "https://gcore.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
    "https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
]

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = ROOT / "backend" / "data" / "ip2region_v4.xdb"
MIN_SIZE = 8 * 1024 * 1024  # 实际约 11 MB，低于 8 MB 一律视为未下载完整
CHUNK = 256 * 1024


def download(url: str, target: Path, timeout: int, use_proxy: bool) -> bool:
    tmp = target.with_suffix(target.suffix + ".part")
    session = requests.Session()
    session.trust_env = use_proxy  # False = 忽略系统代理，直连
    try:
        with session.get(url, stream=True, timeout=timeout) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            tmp.parent.mkdir(parents=True, exist_ok=True)
            with tmp.open("wb") as fh:
                for chunk in resp.iter_content(CHUNK):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = done * 100 // total
                        print(f"\r  {done / 1048576:.1f}/{total / 1048576:.1f} MB ({pct}%)",
                              end="", flush=True)
        print()
    except Exception as exc:  # noqa: BLE001 - 逐个镜像试，失败继续下一个
        print(f"  失败：{exc}")
        tmp.unlink(missing_ok=True)
        return False

    size = tmp.stat().st_size
    valid_header = tmp.open("rb").read(2) == b"\x03\x00"
    if size < MIN_SIZE or not valid_header:
        print(f"  校验不通过：size={size} header_ok={valid_header}")
        tmp.unlink(missing_ok=True)
        return False

    shutil.move(str(tmp), str(target))
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="下载 ip2region IPv4 离线库")
    parser.add_argument("--path", default=str(DEFAULT_TARGET), help="保存路径")
    parser.add_argument("--force", action="store_true", help="已存在也重新下载")
    parser.add_argument("--timeout", type=int, default=300, help="单镜像超时秒数")
    args = parser.parse_args()

    target = Path(args.path).expanduser().resolve()
    if target.exists() and not args.force:
        print(f"已存在，跳过：{target}（{target.stat().st_size // 1024} KB）")
        print("需要更新请加 --force")
        return 0

    print(f"目标文件：{target}")
    for idx, url in enumerate(MIRRORS, 1):
        for use_proxy in (False, True):
            label = "直连" if not use_proxy else "代理"
            print(f"[{idx}/{len(MIRRORS)}] {label} {url}")
            if download(url, target, args.timeout, use_proxy):
                print(f"完成：{target.stat().st_size // 1024} KB")
                print("提示：服务运行中也会自动热加载，无需重启")
                return 0
    print("\n所有镜像均失败。可手工下载后放到目标路径：")
    print("  https://github.com/lionsoul2014/ip2region/tree/master/data")
    return 1


if __name__ == "__main__":
    sys.exit(main())
