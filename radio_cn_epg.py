"""
云视听（radio.cn）EPG 节目表爬虫脚本（并发优化版）
参考 https://www.radio.cn/pc-portal/js/api.js?062 中的 getProgramList 接口
根据给定的电台列表 CSV，爬取指定日期范围内每个电台的节目单

接口说明：
  - 节目单: GET /web/appProgram/listByDate
    参数: broadcastId（电台ID，对应电台列表 CSV 的"电台ID"列）、date（YYYY-MM-DD）

签名规则（同 crawl_radio_cn.py，来自 api.js）：
  signText = sortedParams + '&timestamp=' + tm + '&key=' + KEY
  sign = MD5(signText).upper()

用法:
  # 用默认电台列表 list/radio_cn_channels.csv，爬取今天，输出 epg/radio_cn.xml.gz
  python radio_cn_epg.py

  # 指定电台列表 CSV
  python radio_cn_epg.py --input list/radio_cn_channels.csv

  # 爬取最近 3 天（今天 + 未来 2 天）
  python radio_cn_epg.py --days 3

  # 指定起止日期
  python crawl_radio_cn_epg.py --start 2026-10-12 --end 2026-10-14

  # 调整并发数（默认 10）
  python radio_cn_epg.py --workers 20

  # 强制重爬所有电台（忽略已完成进度）
  python radio_cn_epg.py --no-resume

  # 额外保留未压缩的 XML
  python radio_cn_epg.py --keep-xml
"""

import argparse
import csv
import gzip
import hashlib
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import requests

# ===== 配置 =====
KEY = "f0fc4c668392f9f9a447e48584c214ee"  # 来自 api.js
BASE_URL = "https://ytmsout.radio.cn"
EPG_URL = "/web/appProgram/listByDate"

CST = timezone(timedelta(hours=8))  # 统一按北京时间输出

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
LIST_DIR = os.path.join(PROJECT_DIR, "list")
EPG_DIR = os.path.join(PROJECT_DIR, "epg")

DEFAULT_INPUT_CSV = os.path.join(LIST_DIR, "radio_cn_channels.csv")
DEFAULT_OUTPUT_XML = os.path.join(EPG_DIR, "radio_cn.xml")
DEFAULT_OUTPUT_GZ = os.path.join(EPG_DIR, "radio_cn.xml.gz")

REQUEST_DELAY = 0.05  # 每个 worker 内的请求间隔（秒）
MAX_RETRY = 2         # 单次请求失败重试次数
OUTPUT_DIR = os.path.join(PROJECT_DIR, "output")  # 进度文件目录（不入库）
DEFAULT_INPUT_PATTERN = "radio_cn_channels_"

# 请求头（同 crawl_radio_cn.py）
BASE_HEADERS = {
    "Content-Type": "application/json",
    "equipmentId": "0000",
    "platformCode": "WEB",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Referer": "https://www.radio.cn/",
    "Origin": "https://www.radio.cn",
}

# 线程本地存储：每个线程一个独立 Session，避免连接池竞争
_thread_local = threading.local()
# 全局结果写入锁
_print_lock = threading.Lock()
_rows_lock = threading.Lock()


def get_session():
    """每个线程一个独立 Session"""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update(BASE_HEADERS)
        _thread_local.session = s
    return _thread_local.session


def make_sign(params, timestamp):
    """根据 api.js 中的算法生成签名"""
    if params:
        sorted_keys = sorted(params.keys())
        param_str = "&".join(f"{k}={params[k]}" for k in sorted_keys)
        sign_text = f"{param_str}&timestamp={timestamp}&key={KEY}"
    else:
        sign_text = f"timestamp={timestamp}&key={KEY}"
    return hashlib.md5(sign_text.encode("utf-8")).hexdigest().upper()


def fetch_epg(broadcast_id, date_str):
    """获取指定电台在指定日期的节目单"""
    params = {"broadcastId": broadcast_id, "date": date_str}
    session = get_session()

    for attempt in range(1, MAX_RETRY + 2):
        tm = int(time.time() * 1000)
        sign = make_sign(params, tm)
        headers = {"timestamp": str(tm), "sign": sign}

        try:
            resp = session.get(BASE_URL + EPG_URL, params=params,
                                headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data.get("code") != 0:
                # 1001 等参数错误，重试也没用
                return []
            return data.get("data", []) or []
        except requests.RequestException as e:
            if attempt <= MAX_RETRY:
                time.sleep(1.0)
                continue
            with _print_lock:
                print(f"    [错误] 请求失败: broadcastId={broadcast_id} "
                      f"date={date_str}, 原因: {e}")
            return []
        except ValueError as e:
            with _print_lock:
                print(f"    [错误] JSON解析失败: broadcastId={broadcast_id} "
                      f"date={date_str}, 原因: {e}")
            return []
    return []


def read_radios_from_csv(csv_path):
    """从电台列表 CSV 读取电台ID和名称"""
    radios = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = (row.get("电台ID") or "").strip()
            cname = (row.get("电台名称") or "").strip()
            if cid:
                radios.append({"id": cid, "name": cname})
    return radios


def flatten_program(prog, broadcast_id, broadcast_name, date_str):
    """将节目数据扁平化为一行字典（不含码流相关字段）"""
    def ts_to_str(ts):
        if not ts:
            return ""
        try:
            return datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    start_ts = prog.get("startTime")
    end_ts = prog.get("endTime")

    return {
        "电台ID": broadcast_id,
        "电台名称": broadcast_name,
        "日期": date_str,
        "节目ID": prog.get("id") or "",
        "栏目ID": prog.get("columnId") or "",
        "节目名称": prog.get("programName") or "",
        "节目描述": prog.get("des") or "",
        "开始时间": ts_to_str(start_ts),
        "结束时间": ts_to_str(end_ts),
        "开始时间戳(ms)": start_ts or "",
        "结束时间戳(ms)": end_ts or "",
        "节目时长(分)": round((end_ts - start_ts) / 60000) if start_ts and end_ts else "",
        "封面图": prog.get("image") or "",
        "长封面图": prog.get("imageLong") or "",
        "内容类型": prog.get("contentType") or "",
        "播放标志": prog.get("playFlag") or "",
    }


def save_to_csv(rows, filepath):
    """保存为 CSV（不含码流相关字段）"""
    if not rows:
        print(f"没有数据可保存到 {filepath}")
        return
    fieldnames = [
        "电台ID", "电台名称", "日期", "节目ID", "栏目ID",
        "节目名称", "节目描述", "开始时间", "结束时间",
        "开始时间戳(ms)", "结束时间戳(ms)", "节目时长(分)",
        "封面图", "长封面图", "内容类型", "播放标志",
    ]
    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"已保存 {len(rows)} 条节目数据到: {filepath}")


# ===== XMLTV 标准 EPG 输出 =====
# 参考: https://github.com/XMLTV/xmltv/blob/master/xmltv.dtd
_INVALID_XML_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def _xml_escape(s):
    """XML 特殊字符转义 + 去除非法控制字符"""
    if s is None:
        return ""
    s = _INVALID_XML_CHARS.sub("", str(s)).strip()
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))


def _xmltv_datetime(ts_ms):
    """毫秒时间戳 -> XMLTV 时间格式 'YYYYMMDDhhmmss +0800'（统一北京时间）"""
    if not ts_ms:
        return ""
    try:
        dt = datetime.fromtimestamp(int(ts_ms) / 1000, CST)
        return dt.strftime("%Y%m%d%H%M%S") + " +0800"
    except Exception:
        return ""


def save_to_xmltv(rows, filepath):
    """保存为 XMLTV 标准 EPG XML 文件

    参考 XMLTV DTD:
      <tv>
        <channel id="...">
          <display-name>...</display-name>
          <icon src="..."/>
        </channel>
        <programme channel="..." start="..." stop="...">
          <title>...</title>
          <desc>...</desc>
          <icon src="..."/>
        </programme>
      </tv>
    """
    if not rows:
        print(f"没有数据可保存到 {filepath}")
        return False

    # 收集唯一频道（保留首条出现的电台名称与封面）
    channels = {}
    for r in rows:
        cid = r.get("电台ID") or ""
        if cid and cid not in channels:
            channels[cid] = {
                "name": r.get("电台名称") or cid,
                "icon": r.get("封面图") or r.get("长封面图") or "",
            }

    with open(filepath, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<!DOCTYPE tv SYSTEM "xmltv.dtd">\n')
        f.write('<tv generator-info-name="crawl_radio_cn_epg" '
                'generator-info-url="https://www.radio.cn">\n')

        # 频道定义
        for cid, info in channels.items():
            f.write(f'  <channel id="{_xml_escape(cid)}">\n')
            f.write(f'    <display-name lang="zh">'
                    f'{_xml_escape(info["name"])}</display-name>\n')
            if info["icon"]:
                f.write(f'    <icon src="{_xml_escape(info["icon"])}"/>\n')
            f.write('  </channel>\n')

        # 节目单
        for r in rows:
            cid = r.get("电台ID") or ""
            start_str = _xmltv_datetime(r.get("开始时间戳(ms)"))
            stop_str = _xmltv_datetime(r.get("结束时间戳(ms)"))
            title = r.get("节目名称") or ""
            desc = r.get("节目描述") or ""
            icon = r.get("封面图") or r.get("长封面图") or ""

            if not (cid and start_str and stop_str and title):
                continue

            f.write(f'  <programme channel="{_xml_escape(cid)}" '
                    f'start="{start_str}" stop="{stop_str}">\n')
            f.write(f'    <title lang="zh">{_xml_escape(title)}</title>\n')
            if desc:
                f.write(f'    <desc lang="zh">{_xml_escape(desc)}</desc>\n')
            if icon:
                f.write(f'    <icon src="{_xml_escape(icon)}"/>\n')
            f.write('  </programme>\n')

        f.write('</tv>\n')

    print(f"已保存 {len(channels)} 个频道 / {len(rows)} 条节目到 XMLTV: {filepath}")
    return True


def gzip_file(src_path, gz_path):
    """把 XML 压缩为 .xml.gz，返回压缩后字节数"""
    os.makedirs(os.path.dirname(gz_path) or ".", exist_ok=True)
    with open(src_path, "rb") as f_in, gzip.open(gz_path, "wb", compresslevel=9) as f_out:
        f_out.write(f_in.read())
    gz_size = os.path.getsize(gz_path)
    src_size = os.path.getsize(src_path) or 1
    ratio = (1 - gz_size / src_size) * 100
    print(f"已压缩: {gz_path} ({gz_size / 1024:.1f} KB, 压缩率 {ratio:.1f}%)")
    return gz_size


def save_epg_gz(rows, xml_path, gz_path, keep_xml=False):
    """生成 XMLTV 的 XML 并压缩为 xml.gz（默认删除未压缩的 XML）"""
    if not rows:
        print("没有节目数据，未生成 EPG 文件")
        return False

    os.makedirs(os.path.dirname(xml_path) or ".", exist_ok=True)
    if not save_to_xmltv(rows, xml_path):
        return False

    if not gz_path:
        return True

    gzip_file(xml_path, gz_path)

    if not keep_xml and os.path.isfile(xml_path):
        try:
            os.remove(xml_path)
            print(f"已删除未压缩的临时文件: {xml_path}")
        except OSError as e:
            print(f"[警告] 删除未压缩文件失败: {e}")
    return True


def find_default_input_csv():
    """在 OUTPUT_DIR 下找最新的 radio_cn_channels_*.csv"""
    if not os.path.isdir(OUTPUT_DIR):
        return None
    candidates = [
        f for f in os.listdir(OUTPUT_DIR)
        if f.startswith(DEFAULT_INPUT_PATTERN) and f.endswith(".csv")
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda x: os.path.getmtime(os.path.join(OUTPUT_DIR, x)),
        reverse=True,
    )
    return os.path.join(OUTPUT_DIR, candidates[0])


def date_range(start_date, end_date):
    """生成 [start, end] 区间内的日期列表（含两端）"""
    dates = []
    d = start_date
    while d <= end_date:
        dates.append(d)
        d += timedelta(days=1)
    return dates


# ===== 进度管理（断点续爬） =====
def load_progress(progress_file):
    """读取已完成的 (broadcastId, date) 集合"""
    if not os.path.isfile(progress_file):
        return set()
    try:
        with open(progress_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(tuple(x) for x in data.get("done", []))
    except Exception:
        return set()


def save_progress(progress_file, done_set, all_rows):
    """保存进度 + 已收集的行数据"""
    payload = {
        "done": sorted([list(x) for x in done_set]),
        "rows": all_rows,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    tmp = progress_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    os.replace(tmp, progress_file)


def load_progress_rows(progress_file):
    """读取进度文件里已收集的行数据

    若旧进度中的行包含已被移除的码流字段（如"低码流地址"），
    则判定为不兼容，返回空列表，让用户用 --no-resume 重新爬。
    """
    if not os.path.isfile(progress_file):
        return []
    try:
        with open(progress_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        rows = data.get("rows", []) or []
        if rows and isinstance(rows[0], dict) and "低码流地址" in rows[0]:
            print(f"  [提示] 旧进度文件包含已弃用的码流字段，"
                  f"忽略历史行，建议用 --no-resume 重爬")
            return []
        return rows
    except Exception:
        return []


# ===== 单任务（线程内执行） =====
def worker_task(radio, date_str, done_set, done_lock, all_rows,
                progress_file, done_counter, total_calls):
    """拉取一个电台一天的节目，写进度并追加结果"""
    bid = radio["id"]
    bname = radio["name"]

    programs = fetch_epg(bid, date_str)
    rows = [flatten_program(p, bid, bname, date_str) for p in programs]

    with done_lock:
        done_set.add((bid, date_str))
        all_rows.extend(rows)
        done_counter[0] += 1
        cur = done_counter[0]

        # 每 50 个任务保存一次进度，避免文件 IO 过频
        if cur % 50 == 0:
            save_progress(progress_file, done_set, all_rows)

    with _print_lock:
        print(f"  [{cur}/{total_calls}] {bname} (id={bid}) "
              f"{date_str}: {len(rows)} 条")

    # 单 worker 内稍微缓一下，避免对服务端造成冲击
    time.sleep(REQUEST_DELAY)


def main():
    parser = argparse.ArgumentParser(
        description="云视听 EPG 节目表爬虫（并发 + 断点续爬）"
    )
    parser.add_argument(
        "--input", "-i", default=DEFAULT_INPUT_CSV,
        help=f"电台列表 CSV 路径（默认 {DEFAULT_INPUT_CSV}）",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT_XML,
        help=f"输出的 XML 文件路径（默认 {DEFAULT_OUTPUT_XML}）",
    )
    parser.add_argument(
        "--output-gz", default=DEFAULT_OUTPUT_GZ,
        help=f"输出的 xml.gz 文件路径（默认 {DEFAULT_OUTPUT_GZ}，传空字符串禁用压缩）",
    )
    parser.add_argument(
        "--keep-xml", action="store_true",
        help="压缩后保留未压缩的 XML 文件（默认删除）",
    )
    parser.add_argument(
        "--save-csv", action="store_true",
        help="额外输出一份节目 CSV（默认只输出 xml.gz）",
    )
    parser.add_argument(
        "--start",
        help="起始日期 YYYY-MM-DD（默认今天）",
    )
    parser.add_argument(
        "--end",
        help="结束日期 YYYY-MM-DD（默认与起始相同）",
    )
    parser.add_argument(
        "--days", type=int, default=1,
        help="从起始日期开始连续爬取的天数（默认 1）",
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=10,
        help="并发线程数（默认 10，建议 5-20）",
    )
    parser.add_argument(
        "--no-resume", action="store_true",
        help="忽略已有进度，强制全部重新爬",
    )
    args = parser.parse_args()

    # 1. 定位输入 CSV
    csv_path = args.input
    if not os.path.isfile(csv_path):
        fallback = find_default_input_csv()
        if fallback:
            print(f"[提示] 未找到 {csv_path}，改用 {fallback}")
            csv_path = fallback
        else:
            print(f"[错误] 找不到电台列表 CSV: {csv_path}")
            print("请确认 list/radio_cn_channels.csv 存在，或用 --input 指定路径。")
            return
    print(f"输入电台列表: {csv_path}")

    # 2. 计算日期范围
    today = datetime.now().date()
    if args.start:
        try:
            start_date = datetime.strptime(args.start, "%Y-%m-%d").date()
        except ValueError:
            print(f"[错误] --start 日期格式不合法，应为 YYYY-MM-DD")
            return
    else:
        start_date = today

    if args.end:
        try:
            end_date = datetime.strptime(args.end, "%Y-%m-%d").date()
        except ValueError:
            print(f"[错误] --end 日期格式不合法，应为 YYYY-MM-DD")
            return
    else:
        end_date = start_date + timedelta(days=args.days - 1)

    if end_date < start_date:
        print(f"[错误] 结束日期 {end_date} 早于起始日期 {start_date}")
        return

    dates = [d.strftime("%Y-%m-%d") for d in date_range(start_date, end_date)]
    print(f"爬取日期范围: {dates[0]} ~ {dates[-1]}（共 {len(dates)} 天）")

    # 3. 读取电台列表
    radios = read_radios_from_csv(csv_path)
    print(f"共 {len(radios)} 个电台待爬取")
    if not radios:
        print("[错误] CSV 中没有有效的电台ID")
        return

    # 4. 准备进度文件
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    date_tag = start_date.strftime("%Y%m%d")
    if end_date != start_date:
        date_tag += f"_{end_date.strftime('%Y%m%d')}"
    progress_file = os.path.join(
        OUTPUT_DIR, f"radio_cn_epg_{date_tag}.progress.json"
    )

    if args.no_resume and os.path.isfile(progress_file):
        os.remove(progress_file)
        print(f"已删除旧进度文件（--no-resume）: {progress_file}")

    done_set = load_progress(progress_file)
    all_rows = load_progress_rows(progress_file)
    if done_set:
        print(f"已恢复进度: 完成 {len(done_set)} 个任务, "
              f"已有 {len(all_rows)} 行数据")

    # 5. 构建待执行任务列表
    pending = []
    for date_str in dates:
        for radio in radios:
            if (radio["id"], date_str) in done_set:
                continue
            pending.append((radio, date_str))

    total_calls = len(pending) + len(done_set)
    print("=" * 60)
    print("  云视听 EPG 节目表爬虫（并发 + 断点续爬）")
    print(f"  开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  电台数: {len(radios)}, 天数: {len(dates)}, "
          f"总任务: {len(radios) * len(dates)}, "
          f"待执行: {len(pending)}, 已完成: {len(done_set)}")
    print(f"  并发数: {args.workers}")
    print("=" * 60)

    if not pending:
        print("所有任务已完成，无需重新爬取。")
    else:
        done_lock = threading.Lock()
        done_counter = [0]  # 用 list 让闭包可写
        start_ts = time.time()

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(
                    worker_task,
                    radio, date_str,
                    done_set, done_lock, all_rows,
                    progress_file, done_counter,
                    len(pending),
                ): (radio["id"], date_str)
                for radio, date_str in pending
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    rid, ds = futures[future]
                    with _print_lock:
                        print(f"  [异常] broadcastId={rid} date={ds}: {e}")

        # 最后一次保存进度
        with done_lock:
            save_progress(progress_file, done_set, all_rows)

        elapsed = time.time() - start_ts
        print(f"\n并发爬取耗时: {elapsed:.1f} 秒")

    # 6. 输出 EPG（xml.gz）
    if args.save_csv:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_csv = os.path.join(
            OUTPUT_DIR, f"radio_cn_epg_{date_tag}_{timestamp}.csv"
        )
        save_to_csv(all_rows, out_csv)

    ok = save_epg_gz(all_rows, args.output, args.output_gz, args.keep_xml)

    print(f"\n{'=' * 60}")
    print(f"  爬取完成！" if ok else "  爬取完成，但未生成 EPG 文件！")
    print(f"  结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if ok:
        print(f"  EPG 文件: {os.path.abspath(args.output_gz or args.output)}")
    print(f"  进度文件: {os.path.abspath(progress_file)}")
    print(f"{'=' * 60}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
