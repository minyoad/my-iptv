#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
蜻蜓FM电台 EPG 生成器

读取 list/qingtingfm_channels.csv 中的电台ID，调用蜻蜓FM移动端接口获取节目单：
    https://webapi.qingting.fm/api/mobile/radio/channels/{电台ID}/
生成标准 XMLTV 格式的 EPG 文件（xml + xml.gz）。

用法：
    python qingtingfm_epg.py                      # 处理全部电台
    python qingtingfm_epg.py --limit 10           # 只处理前10个（调试用）
    python qingtingfm_epg.py --workers 32         # 提高并发数
    python qingtingfm_epg.py --include-yesterday  # 同时输出昨天的节目
"""

import argparse
import csv
import gzip
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import requests
import xml.etree.ElementTree as ET
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------------------ 配置 ------------------------------

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
LIST_DIR = os.path.join(PROJECT_DIR, 'list')
EPG_DIR = os.path.join(PROJECT_DIR, 'epg')

DEFAULT_CSV = os.path.join(LIST_DIR, 'qingtingfm_channels.csv')
DEFAULT_OUTPUT_XML = os.path.join(EPG_DIR, 'qingtingfm.xml')
DEFAULT_OUTPUT_GZ = os.path.join(EPG_DIR, 'qingtingfm.xml.gz')

API_URL = 'https://webapi.qingting.fm/api/mobile/radio/channels/{cid}/'
CHANNEL_URL = 'https://www.qingting.fm/channels/{cid}'

HEADERS = {
    'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'),
    'Referer': 'https://www.qingting.fm/',
    'Accept': 'application/json, text/plain, */*',
}

# 接口的 from / mediaParams 字段均为北京时间
CST = timezone(timedelta(hours=8))
ISO_FORMATS = ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('qingtingfm_epg')

_thread_local = threading.local()


# ------------------------------ 工具函数 ------------------------------

def get_session():
    """每个线程一个 requests.Session"""
    session = getattr(_thread_local, 'session', None)
    if session is None:
        session = requests.Session()
        session.headers.update(HEADERS)
        retry = Retry(total=2, connect=2, read=2, backoff_factor=0.5,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset(['GET']))
        adapter = HTTPAdapter(max_retries=retry, pool_connections=64, pool_maxsize=64)
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        _thread_local.session = session
    return session


def clean_text(text):
    """清理文本中的非法 XML 字符"""
    if text is None:
        return ''
    text = str(text)
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    return text.strip()


def load_channels(csv_path):
    """从CSV读取电台列表，返回 [{id, name, desc, cover, category}]"""
    if not os.path.exists(csv_path):
        logger.error(f'电台列表文件不存在: {csv_path}')
        return []

    channels = []
    seen_ids = set()
    seen_names = set()
    duplicated_names = set()

    with open(csv_path, 'r', encoding='utf-8-sig', newline='') as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            logger.error('电台列表文件为空')
            return []

        def col_index(*names):
            for name in names:
                if name in header:
                    return header.index(name)
            return None

        idx_id = col_index('电台ID', '电台id', 'id')
        idx_name = col_index('电台名称', '名称', 'name')
        idx_desc = col_index('电台描述', '描述')
        idx_cover = col_index('封面图', '封面')
        idx_cat = col_index('所属分类', '分类')

        if idx_id is None or idx_name is None:
            logger.error('未能识别电台列表的电台ID/电台名称列')
            return []

        for row in reader:
            if not row or len(row) <= max(idx_id, idx_name):
                continue

            def get(idx):
                return row[idx].strip() if idx is not None and idx < len(row) else ''

            cid = get(idx_id)
            name = clean_text(get(idx_name))
            if not cid or not cid.isdigit() or not name:
                continue
            if cid in seen_ids:
                continue
            seen_ids.add(cid)

            if name in seen_names:
                duplicated_names.add(name)
            seen_names.add(name)

            channels.append({
                'id': cid,
                'name': name,
                'desc': clean_text(get(idx_desc)),
                'cover': get(idx_cover),
                'category': clean_text(get(idx_cat)),
            })

    if duplicated_names:
        logger.warning(f'电台名称存在重名（共 {len(duplicated_names)} 个），它们的节目会写入同一个频道id')

    logger.info(f'已从 {os.path.basename(csv_path)} 加载 {len(channels)} 个电台')
    return channels


def load_aliases(alias_file):
    """加载频道别名映射，格式与 config/channel_alias.txt 一致（每行第一个为规范名）"""
    aliases = {}
    if not alias_file:
        return aliases
    if not os.path.exists(alias_file):
        logger.warning(f'别名文件不存在，忽略: {alias_file}')
        return aliases
    try:
        with open(alias_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = [p.strip() for p in line.split(',') if p.strip()]
                if len(parts) >= 2:
                    for p in parts:
                        aliases[p] = parts[0]
        logger.info(f'已加载 {len(aliases)} 个频道别名映射')
    except Exception as e:
        logger.warning(f'加载别名文件失败: {e}')
    return aliases


def fetch_playbill(channel_id, timeout=15, retries=3):
    """获取某个电台的节目单，返回 (channelInfo, playBill) 或 None"""
    url = API_URL.format(cid=channel_id)
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            resp = get_session().get(url, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                raise ValueError('返回结果不是JSON对象')
            # 部分代理/网关会把数据包在 result 里，这里兼容两种结构
            result = data.get('result') if isinstance(data.get('result'), dict) else data
            if not result.get('playBill'):
                raise ValueError('返回结果缺少 playBill 字段')
            return result
        except Exception as e:
            last_error = e
            if attempt < retries:
                time.sleep(0.5 * attempt)
    logger.warning(f'获取电台 {channel_id} 节目单失败: {last_error}')
    return None


# ------------------------------ 时间处理 ------------------------------

def parse_iso_local(value):
    """解析 UTC ISO 时间并转换为北京时间"""
    if not value:
        return None
    value = str(value).strip()
    for fmt in ISO_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(CST)
        except ValueError:
            continue
    try:  # 兜底：处理带时区偏移的格式
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(CST)
    except Exception:
        return None


def parse_local_str(value):
    """解析 YYYYMMDDHHMMSS 形式的北京时间"""
    if not value:
        return None
    value = str(value).strip()
    if len(value) == 14 and value.isdigit():
        try:
            return datetime.strptime(value, '%Y%m%d%H%M%S').replace(tzinfo=CST)
        except ValueError:
            return None
    return None


def get_start(item):
    """节目开始时间（北京时间 aware datetime）"""
    start = parse_local_str(item.get('from'))
    if start is None:
        start = parse_iso_local(item.get('startTime'))
    return start


def get_stop(item, start):
    """节目结束时间（北京时间 aware datetime）"""
    stop = None
    params = item.get('mediaParams') or {}
    if isinstance(params, dict) and params.get('date') and params.get('endTime'):
        stop = parse_local_str(f"{params.get('date')}{params.get('endTime')}")
    if stop is None:
        stop = parse_iso_local(item.get('endTime'))
    if stop is None and start is not None:
        stop = start + timedelta(hours=1)
    if start is not None and stop is not None and stop <= start:
        stop = stop + timedelta(days=1)
    return stop


def xmltv_time(dt):
    """转换为 XMLTV 时间格式：YYYYMMDDHHMMSS +0800"""
    return dt.strftime('%Y%m%d%H%M%S') + ' +0800'


# ------------------------------ XML 构建 ------------------------------

def build_programmes(play_bill, channel_name, cover, category, start_limit):
    """把一个电台的三天节目单转换为 programme 列表"""
    programmes = []
    for day in ('yesterday', 'today', 'tomorrow'):
        for item in (play_bill.get(day) or []):
            if not isinstance(item, dict):
                continue
            start = get_start(item)
            if start is None:
                continue
            if start_limit is not None and start < start_limit:
                continue
            stop = get_stop(item, start)
            if stop is None:
                continue

            title = clean_text(item.get('title'))
            if not title:
                continue

            hosts = [clean_text(h) for h in re.split(r'[,、;；/|]', str(item.get('broadcasterNames') or '')) if clean_text(h)]
            desc_parts = []
            if hosts:
                desc_parts.append('主持人：' + '、'.join(hosts))
            duration_str = clean_text(item.get('durationStr'))
            if duration_str:
                desc_parts.append(duration_str)

            programmes.append({
                'start': start,
                'stop': stop,
                'title': title,
                'hosts': hosts,
                'desc': '；'.join(desc_parts),
                'duration': max(int((stop - start).total_seconds()), 0),
                'program_id': item.get('programId'),
            })

    # 按开始时间排序，避免相邻节目时间重叠
    programmes.sort(key=lambda p: p['start'])
    for i in range(len(programmes) - 1):
        if programmes[i]['stop'] > programmes[i + 1]['start']:
            programmes[i]['stop'] = programmes[i + 1]['start']
            programmes[i]['duration'] = max(
                int((programmes[i]['stop'] - programmes[i]['start']).total_seconds()), 0)

    # 去重
    programmes = [p for p in programmes if p['stop'] > p['start']]

    elements = []
    for p in programmes:
        prog = ET.Element('programme', {
            'start': xmltv_time(p['start']),
            'stop': xmltv_time(p['stop']),
            'channel': channel_name,
        })
        ET.SubElement(prog, 'title', {'lang': 'zh'}).text = p['title']
        if p['desc']:
            ET.SubElement(prog, 'desc', {'lang': 'zh'}).text = p['desc']
        if p['hosts']:
            credits = ET.SubElement(prog, 'credits')
            for host in p['hosts']:
                ET.SubElement(credits, 'presenter').text = host
        if category:
            ET.SubElement(prog, 'category', {'lang': 'zh'}).text = category
        ET.SubElement(prog, 'length', {'units': 'seconds'}).text = str(p['duration'])
        if cover:
            ET.SubElement(prog, 'icon', {'src': cover})
        if p['program_id']:
            ET.SubElement(prog, 'episode-num', {'system': 'onscreen'}).text = str(p['program_id'])
        elements.append(prog)

    return elements


def save_xml(root, output_xml, output_gz, keep_xml=False):
    """保存 XML 并生成 gzip 压缩包"""
    xml_bytes = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    parser = ET.XMLParser(encoding='utf-8')
    ET.fromstring(xml_bytes, parser=parser)  # 简单校验

    os.makedirs(os.path.dirname(output_xml), exist_ok=True)
    with open(output_xml, 'wb') as f:
        f.write(xml_bytes)
    logger.info(f'已生成 EPG: {output_xml} ({len(xml_bytes) / 1024:.1f} KB)')

    if output_gz:
        with open(output_xml, 'rb') as f_in, gzip.open(output_gz, 'wb', compresslevel=9) as f_out:
            f_out.write(f_in.read())
        gz_size = os.path.getsize(output_gz)
        ratio = (1 - gz_size / max(len(xml_bytes), 1)) * 100
        logger.info(f'已压缩: {output_gz} ({gz_size / 1024:.1f} KB, 压缩率 {ratio:.1f}%)')

        # 未压缩的 XML 体积很大，默认压缩后删除，仅保留 gz
        if not keep_xml:
            try:
                os.remove(output_xml)
                logger.info(f'已删除未压缩的临时文件: {output_xml}')
            except OSError as e:
                logger.warning(f'删除未压缩文件失败: {e}')
    return True


# ------------------------------ 主流程 ------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description='根据蜻蜓FM电台ID生成 XMLTV 格式 EPG')
    parser.add_argument('--csv', default=DEFAULT_CSV, help='电台列表CSV文件')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_XML, help='输出的XML文件路径')
    parser.add_argument('--output-gz', default=DEFAULT_OUTPUT_GZ, help='输出的gz文件路径，传空字符串可禁用')
    parser.add_argument('--keep-xml', action='store_true', help='压缩后保留未压缩的XML文件（默认删除）')
    parser.add_argument('--workers', type=int, default=16, help='并发请求数（默认16）')
    parser.add_argument('--limit', type=int, default=0, help='只处理前N个电台，0表示全部')
    parser.add_argument('--timeout', type=int, default=15, help='单个请求超时时间（秒）')
    parser.add_argument('--retries', type=int, default=3, help='单个请求重试次数')
    parser.add_argument('--include-yesterday', action='store_true', help='同时输出昨天的节目')
    parser.add_argument('--alias-file', default='', help='频道别名映射文件（可选）')
    parser.add_argument('--log-level', default='INFO', help='日志级别')
    return parser.parse_args()


def main():
    args = parse_args()
    logger.setLevel(getattr(logging, args.log_level.upper(), logging.INFO))

    channels = load_channels(args.csv)
    if not channels:
        return False
    if args.limit > 0:
        channels = channels[:args.limit]
        logger.info(f'限制处理前 {len(channels)} 个电台')

    aliases = load_aliases(args.alias_file)

    now = datetime.now(CST)
    start_limit = None if args.include_yesterday else now.replace(hour=0, minute=0, second=0, microsecond=0)

    # 1. 并发拉取节目单
    results = {}
    logger.info(f'开始获取 {len(channels)} 个电台的节目单（并发 {args.workers}）...')
    with ThreadPoolExecutor(max_workers=max(args.workers, 1)) as executor:
        futures = {
            executor.submit(fetch_playbill, ch['id'], args.timeout, args.retries): ch
            for ch in channels
        }
        done = 0
        for future in as_completed(futures):
            ch = futures[future]
            done += 1
            try:
                results[ch['id']] = future.result()
            except Exception as e:
                logger.warning(f"电台 {ch['id']} {ch['name']} 处理异常: {e}")
                results[ch['id']] = None
            if done % 100 == 0 or done == len(channels):
                logger.info(f'已处理 {done}/{len(channels)} 个电台')

    # 2. 构建 XMLTV
    tv = ET.Element('tv', {
        'source-info-name': '蜻蜓FM',
        'source-info-url': 'https://www.qingting.fm/',
        'generator-info-name': 'qingtingfm_epg',
        'generator-info-url': 'https://github.com/minyoad/my-iptv',
        'date': now.strftime('%Y-%m-%d'),
    })

    total_programmes = 0
    ok_channels = 0
    written_channels = set()

    for ch in channels:
        result = results.get(ch['id'])
        if not result:
            continue
        play_bill = result.get('playBill') or {}
        if not isinstance(play_bill, dict):
            continue
        info = result.get('channelInfo') or {}

        ok_channels += 1
        # 若有别名映射，统一使用规范名称作为频道id
        channel_id = aliases.get(ch['name'], ch['name'])
        cover = ch['cover'] or info.get('cover') or ''
        desc = ch['desc'] or clean_text(info.get('desc'))

        elements = build_programmes(play_bill, channel_id, cover, ch['category'], start_limit)
        if not elements:
            continue

        if channel_id not in written_channels:
            written_channels.add(channel_id)
            channel_elem = ET.SubElement(tv, 'channel', {'id': channel_id})
            ET.SubElement(channel_elem, 'display-name', {'lang': 'zh'}).text = channel_id
            if cover:
                ET.SubElement(channel_elem, 'icon', {'src': cover})
            if desc:
                ET.SubElement(channel_elem, 'desc', {'lang': 'zh'}).text = desc
            url = info.get('url') or CHANNEL_URL.format(cid=ch['id'])
            ET.SubElement(channel_elem, 'url').text = url

        for elem in elements:
            tv.append(elem)
        total_programmes += len(elements)

    success_channels = len(written_channels)
    logger.info(f'获取成功 {ok_channels}/{len(channels)} 个电台，写入频道 {success_channels} 个，'
                f'节目 {total_programmes} 条')

    if success_channels == 0:
        logger.error('没有可用的节目数据，未生成文件')
        return False

    try:
        save_xml(tv, args.output, args.output_gz, args.keep_xml)
    except Exception as e:
        logger.error(f'保存EPG文件失败: {e}')
        return False
    return True


if __name__ == '__main__':
    start_time = datetime.now()
    ok = main()
    cost = (datetime.now() - start_time).total_seconds()
    if ok:
        logger.info(f'处理完成，耗时 {cost:.2f} 秒')
        sys.exit(0)
    logger.error(f'处理失败，耗时 {cost:.2f} 秒')
    sys.exit(1)
