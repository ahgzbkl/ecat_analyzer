# /// script
# requires-python = ">=3.8"
# dependencies = ["matplotlib", "numpy"]
# ///
# -*- coding: utf-8 -*-
"""EtherCAT PDO 曲线分析工具 v7
跨平台: Windows / Linux / macOS
运行: python ecat_pdo_analyzer.py  或  uv run ecat_pdo_analyzer.py
v7 性能优化: LTTB降采样 + 懒加载渲染 + 拖拽限帧 + matplotlib加速
"""
import os, sys, struct, threading, platform, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import xml.etree.ElementTree as ET

# ══════════════════════════════════════════════════════════
# 0. 依赖自检（跨平台）
# ══════════════════════════════════════════════════════════
def _ensure_deps():
    try:
        import matplotlib, numpy  # noqa
        return
    except ImportError:
        pass
    # 尝试同目录 .venv
    _sd = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(_sd, ".venv", "Lib", "site-packages"),          # Windows
        os.path.join(_sd, ".venv", "lib", "python3", "site-packages"), # Linux/Mac
    ]
    import glob as _glob
    for pat in [os.path.join(_sd, ".venv", "lib", "python3.*", "site-packages")]:
        candidates += _glob.glob(pat)
    for _p in candidates:
        if os.path.isdir(_p) and _p not in sys.path:
            sys.path.insert(0, _p)
            try:
                import matplotlib, numpy  # noqa
                return
            except ImportError:
                sys.path.remove(_p)
    import subprocess
    for flag in [[], ["--break-system-packages"]]:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "matplotlib", "numpy"] + flag,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except Exception:
            pass

_ensure_deps()

import numpy as np
import matplotlib
matplotlib.use("TkAgg")
matplotlib.rcParams['path.simplify'] = False
matplotlib.rcParams['path.simplify_threshold'] = 0.0
matplotlib.rcParams['agg.path.chunksize'] = 0
matplotlib.rcParams['path.snap'] = False
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk

def _setup_font():
    from matplotlib import font_manager as fm
    _IS_WIN = platform.system() == "Windows"
    _IS_MAC = platform.system() == "Darwin"
    if _IS_WIN:
        cands = ["Microsoft YaHei", "SimHei", "SimSun"]
        paths = [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simhei.ttf"]
    elif _IS_MAC:
        cands = ["PingFang SC", "Heiti SC", "STHeiti"]
        paths = ["/System/Library/Fonts/PingFang.ttc"]
    else:
        cands = ["WenQuanYi Micro Hei", "Noto Sans CJK SC", "DejaVu Sans"]
        paths = ["/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"]
    for name in cands:
        if any(f.name == name for f in fm.fontManager.ttflist):
            plt.rcParams["font.family"] = name
            break
    for p in paths:
        if os.path.exists(p):
            fm.fontManager.addfont(p)
            plt.rcParams["font.family"] = fm.FontProperties(fname=p).get_name()
            break
    plt.rcParams["axes.unicode_minus"] = False
_setup_font()

# ══════════════════════════════════════════════════════════
# 1. 数据包迭代器（pcap / pcap-ng）
# ══════════════════════════════════════════════════════════
ECAT_ETYPE = 0x88A4
CMD_LRW    = 0x0C

def iter_packets(path):
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
    if magic in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
        yield from _iter_pcap(path)
    elif magic == 0x0A0D0D0A:
        yield from _iter_pcapng(path)
    else:
        raise ValueError(f"不支持的文件格式 magic=0x{magic:08X}")

def _iter_pcap(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
    magic = struct.unpack_from("<I", hdr)[0]
    le = magic in (0xA1B2C3D4, 0xA1B23C4D)
    ns = magic in (0xA1B23C4D, 0x4D3CB2A1)
    e  = "<" if le else ">"
    with open(path, "rb") as f:
        f.read(24)
        while True:
            ph = f.read(16)
            if len(ph) < 16: break
            s, frac, inc, _ = struct.unpack(e + "IIII", ph)
            data = f.read(inc)
            if len(data) < inc: break
            yield s + frac * (1e-9 if ns else 1e-6), data

def _iter_pcapng(path):
    with open(path, "rb") as f:
        content = f.read()
    off = 0; iface_factor = {0: 1e-6}; iface_idx = 0
    while off + 8 <= len(content):
        bt, bl = struct.unpack_from("<II", content, off)
        if bl < 12 or off + bl > len(content): break
        body = content[off+8: off+bl-4]
        if bt == 0x00000001:  # IDB
            tsresol = 6; o2 = 4
            while o2 + 4 <= len(body):
                oc, ol = struct.unpack_from("<HH", body, o2); o2 += 4
                if oc == 9 and ol >= 1: tsresol = body[o2]
                o2 += (ol + 3) & ~3
                if oc == 0: break
            b = tsresol & 0x7F
            iface_factor[iface_idx] = (2**-b) if (tsresol & 0x80) else (10**-b)
            iface_idx += 1
        elif bt == 0x00000006 and len(body) >= 20:  # EPB
            iid = struct.unpack_from("<I", body)[0]
            th, tl, cap = struct.unpack_from("<III", body, 4)
            ts = ((th << 32) | tl) * iface_factor.get(iid, 1e-6)
            yield ts, body[20:20+cap]
        elif bt == 0x00000002 and len(body) >= 20:  # OPB
            _, th, tl, cap, _ = struct.unpack_from("<IIIII", body)
            ts = ((th << 32) | tl) * iface_factor.get(0, 1e-6)
            yield ts, body[20:20+cap]
        off += bl

def _extract_lrw(frame):
    if len(frame) < 16: return None
    eth_off = 12
    etype = struct.unpack_from(">H", frame, eth_off)[0]
    if etype == 0x8100 and len(frame) > 16:
        etype = struct.unpack_from(">H", frame, eth_off + 4)[0]
        ec_start = 18
    else:
        ec_start = 14
    if etype != ECAT_ETYPE: return None
    ec = frame[ec_start:]
    off = 2
    while off + 10 <= len(ec):
        cmd = ec[off]
        lf  = struct.unpack_from("<H", ec, off+6)[0]
        dl  = lf & 0x07FF
        last= (lf >> 15) & 1
        if off + 10 + dl + 2 > len(ec): break
        wkc = struct.unpack_from("<H", ec, off+10+dl)[0]
        if cmd == CMD_LRW:
            return wkc, bytes(ec[off+10: off+10+dl])
        off += 10 + dl + 2
        if last: break
    return None

# EtherCAT 命令类型表
_CMD_NAMES = {
    0x00:"NOP",  0x01:"APRD", 0x02:"APWR", 0x03:"APRW",
    0x04:"FPRD", 0x05:"FPWR", 0x06:"FPRW", 0x07:"BRD",
    0x08:"BWR",  0x09:"BRW",  0x0A:"LRD",  0x0B:"LWR",
    0x0C:"LRW",  0x0D:"ARMW", 0x0E:"FRMW",
}

def parse_ecat_frame(ts, frame, frame_no, layout=None):
    """解析原始以太网帧，返回用于显示的结构化字典。"""
    if len(frame) < 16: return None
    etype = struct.unpack_from(">H", frame, 12)[0]
    if etype == 0x8100 and len(frame) > 16:
        etype = struct.unpack_from(">H", frame, 16)[0]
        ec_start = 18
    else:
        ec_start = 14
    if etype != ECAT_ETYPE: return None
    dst_mac = ":".join(f"{b:02x}" for b in frame[0:6])
    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    ec = frame[ec_start:]
    if len(ec) < 2: return None
    ec_hdr = struct.unpack_from("<H", ec, 0)[0]
    ec_len  = ec_hdr & 0x7FF
    ec_type = (ec_hdr >> 12) & 0xF
    # 解析所有数据报
    datagrams = []
    off = 2
    while off + 10 <= len(ec):
        cmd = ec[off]; idx = ec[off+1]
        addr = struct.unpack_from("<I", ec, off+2)[0]
        lf   = struct.unpack_from("<H", ec, off+6)[0]
        dlen = lf & 0x07FF
        more = (lf >> 15) & 1
        if off + 10 + dlen + 2 > len(ec): break
        irq  = struct.unpack_from("<H", ec, off+8)[0]
        data = bytes(ec[off+10: off+10+dlen])
        wkc  = struct.unpack_from("<H", ec, off+10+dlen)[0]
        datagrams.append({"cmd":cmd,"idx":idx,"addr":addr,
                           "dlen":dlen,"irq":irq,"data":data,"wkc":wkc})
        off += 10 + dlen + 2
        if not more: break
    if not datagrams: return None
    # 方向：第一个 LRW 的 WKC 决定
    direction = "—"
    for dg in datagrams:
        if dg["cmd"] == CMD_LRW:
            direction = "Input" if dg["wkc"] == 0 else "Output"; break
    # Info 字符串
    info_parts = []
    for dg in datagrams:
        cn = _CMD_NAMES.get(dg["cmd"], f"CMD{dg['cmd']:02x}")
        if dg["cmd"] == CMD_LRW:
            if dg["wkc"] == 0:
                parts = ["LRW REQ"]
                if layout:
                    for ax in layout["axes"]:
                        o = ax["target_off"]
                        if o+4 <= len(dg["data"]):
                            parts.append(f"{ax['name']}={struct.unpack_from('<i',dg['data'],o)[0]}")
                info_parts.append("  ".join(parts))
            else:
                parts = [f"LRW RSP (WKC={dg['wkc']})"]
                if layout:
                    for ax in layout["axes"]:
                        o = ax["actual_off"]
                        if o+4 <= len(dg["data"]):
                            parts.append(f"{ax['name']}={struct.unpack_from('<i',dg['data'],o)[0]}")
                info_parts.append("  ".join(parts))
        else:
            info_parts.append(f"{cn} addr=0x{dg['addr']:08X} len={dg['dlen']} wkc={dg['wkc']}")
    return {"frame_no":frame_no,"ts":ts,"src":src_mac,"dst":dst_mac,
            "frame_len":len(frame),"ec_len":ec_len,"ec_type":ec_type,
            "ec_start":ec_start,
            "datagrams":datagrams,"direction":direction,
            "info":"  ".join(info_parts),"raw":bytes(frame)}


# ══════════════════════════════════════════════════════════
def auto_detect(path, progress_cb=None):
    from numpy.lib.stride_tricks import as_strided
    plen = None
    for _, frame in iter_packets(path):
        r = _extract_lrw(frame)
        if r is None: continue
        _, pl = r
        plen = len(pl)
        break
    if plen is None or plen < 8:
        return None
    n_offs = plen - 3
    BIG = 1e18
    rx_min = np.full(n_offs,  BIG, dtype=np.float64)
    rx_max = np.full(n_offs, -BIG, dtype=np.float64)
    tx_min = np.full(n_offs,  BIG, dtype=np.float64)
    tx_max = np.full(n_offs, -BIG, dtype=np.float64)
    delta_min = np.full(n_offs,  BIG, dtype=np.float64)
    delta_max = np.full(n_offs, -BIG, dtype=np.float64)
    last_rx = None; n_pairs = 0

    def _vals(pl):
        raw = np.frombuffer(pl[:plen], dtype=np.uint8).copy()
        win = as_strided(raw, shape=(n_offs, 4), strides=(1, 1))
        u32 = (win[:,0].astype(np.uint32) | (win[:,1].astype(np.uint32)<<8)
               | (win[:,2].astype(np.uint32)<<16) | (win[:,3].astype(np.uint32)<<24))
        return u32.view(np.int32).astype(np.float64)

    for _, frame in iter_packets(path):
        r = _extract_lrw(frame)
        if r is None: continue
        wkc, pl = r
        if len(pl) < plen: continue
        v = _vals(pl)
        if wkc == 0:
            np.minimum(rx_min, v, out=rx_min); np.maximum(rx_max, v, out=rx_max)
            last_rx = v
        else:
            np.minimum(tx_min, v, out=tx_min); np.maximum(tx_max, v, out=tx_max)
            if last_rx is not None:
                d = v - last_rx
                np.minimum(delta_min, d, out=delta_min); np.maximum(delta_max, d, out=delta_max)
                n_pairs += 1
    if n_pairs < 5: return None

    rx_range = rx_max - rx_min; tx_range = tx_max - tx_min
    delta_range = delta_max - delta_min
    rx_valid = rx_min < BIG*0.5; tx_valid = tx_min < BIG*0.5
    delta_valid = delta_min < BIG*0.5
    max_rng = float(max(rx_range.max(), tx_range.max())) if (rx_valid.any() or tx_valid.any()) else 1.0
    abs_thresh = max(max_rng * 0.02, 50.0)

    tgt_mask = rx_valid & delta_valid & (rx_range >= abs_thresh) & (delta_range < 2)
    act_mask  = tx_valid & delta_valid & (tx_range >= abs_thresh) & (delta_range >= 2)
    if not np.any(tgt_mask):
        tgt_mask = rx_valid & delta_valid & (rx_range >= abs_thresh*0.1) & (delta_range < 5)
    if not np.any(act_mask):
        act_mask = tx_valid & delta_valid & (tx_range >= abs_thresh*0.1) & (delta_range >= 1)

    tgt_offs = np.where(tgt_mask)[0].tolist()
    act_offs  = np.where(act_mask)[0].tolist()
    if not tgt_offs or not act_offs: return None

    def deoverlap(offs, rng):
        offs = sorted(offs, key=lambda o: -rng[o]); kept = []
        for o in offs:
            if not any(abs(o-k) < 4 for k in kept): kept.append(o)
        return sorted(kept)

    tgt_offs = deoverlap(tgt_offs, rx_range)
    act_offs  = deoverlap(act_offs,  tx_range)
    axes, used_act = [], set()
    for toff in tgt_offs:
        best = None; best_score = -1.0
        r_t = float(rx_range[toff]); m_t = float((rx_max[toff]+rx_min[toff])/2)
        for aoff in act_offs:
            if aoff in used_act: continue
            r_a = float(tx_range[aoff]); m_a = float((tx_max[aoff]+tx_min[aoff])/2)
            score = (min(r_t,r_a)/(max(r_t,r_a)+1))*0.6 + max(0.,1.-abs(m_t-m_a)/(max(r_t,r_a)+1))*0.4
            if score > best_score: best_score = score; best = aoff
        if best is not None:
            axes.append(dict(target_off=int(toff), actual_off=int(best),
                             range=float(rx_range[toff]),
                             mean=float((rx_max[toff]+rx_min[toff])/2),
                             match=round(best_score,3)))
            used_act.add(best)
    if not axes: return None
    axes.sort(key=lambda a: -a["range"])

    act_pos_set = {a["actual_off"] for a in axes}
    vel_torq = [dict(offset=int(o), range=float(tx_range[o]), score=float(delta_range[o]))
                for o in act_offs if not any(abs(o-p)<4 for p in act_pos_set)]
    vel_torq.sort(key=lambda x: -x["range"])

    AXIS_NAMES = ["X","Y","Z","B","C"] + [f"轴{i+6}" for i in range(20)]
    for i,a in enumerate(axes): a["name"] = AXIS_NAMES[i] if i < len(AXIS_NAMES) else f"轴{i+1}"
    ROLE_NAMES = ["速度","转矩"] + [f"辅助{i+1}" for i in range(20)]
    for i,ch in enumerate(vel_torq[:8]): ch["name"] = ROLE_NAMES[i]
    return dict(axes=axes, vel_torq=vel_torq[:8], payload_len=plen,
                confidence=float(np.mean([a["match"] for a in axes])))

# ══════════════════════════════════════════════════════════
# 3. 全量解析
# ══════════════════════════════════════════════════════════
def parse_data(path, layout, progress_cb=None):
    axes = layout["axes"]; vel_torq = layout["vel_torq"]; plen = layout["payload_len"]
    rx_offs = {a["name"]+"-target": a["target_off"] for a in axes}
    tx_offs = {a["name"]+"-actual": a["actual_off"] for a in axes}
    for ch in vel_torq: tx_offs[ch["name"]] = ch["offset"]
    series = {"ts_rx": [], "ts_tx": []}
    for k in rx_offs: series[k] = []
    for k in tx_offs: series[k] = []
    fsize = os.path.getsize(path); processed = 0

    def read_i32(pl, off):
        return struct.unpack_from("<i", pl, off)[0] if off+4 <= len(pl) else None

    for ts, frame in iter_packets(path):
        processed += len(frame)+16
        if progress_cb and len(series["ts_rx"]) % 5000 == 0:
            progress_cb(min(processed/fsize, 0.99))
        r = _extract_lrw(frame)
        if r is None: continue
        wkc, pl = r
        if len(pl) < plen: continue
        if wkc == 0:
            vals = {k: read_i32(pl, off) for k, off in rx_offs.items()}
            if any(v is None for v in vals.values()): continue
            series["ts_rx"].append(ts)
            for k,v in vals.items(): series[k].append(v)
        else:
            vals = {k: read_i32(pl, off) for k, off in tx_offs.items()}
            if any(v is None for v in vals.values()): continue
            series["ts_tx"].append(ts)
            for k,v in vals.items(): series[k].append(v)

    t0 = min(series["ts_rx"][0] if series["ts_rx"] else 0,
             series["ts_tx"][0] if series["ts_tx"] else 0)
    series["ts_rx"] = [t-t0 for t in series["ts_rx"]]
    series["ts_tx"] = [t-t0 for t in series["ts_tx"]]
    if progress_cb: progress_cb(1.0)
    return series

# ══════════════════════════════════════════════════════════
# 3b. 通信质量分析（发送间隔 + 接收间隔 + 回环时延 + 丢帧）
# ══════════════════════════════════════════════════════════
def compute_jitter(series):
    result = {}
    for key, label in [("ts_rx", "主站发送(RxPDO)"), ("ts_tx", "主站接收(TxPDO)")]:
        ts_list = series.get(key, [])
        if len(ts_list) < 10: continue
        ts = np.array(ts_list, dtype=np.float64)
        intervals = np.diff(ts) * 1e6
        nominal = float(np.median(intervals))
        jitter  = intervals - nominal
        lost_events = []
        for i in range(len(intervals)):
            if intervals[i] > nominal * 1.8:
                n_lost = max(0, int(round(intervals[i]/nominal)) - 1)
                lost_events.append(dict(time_s=float(ts[i+1]),
                                        gap_us=float(intervals[i]),
                                        n_lost=n_lost))
        result[key] = dict(
            label=label, nominal_us=nominal,
            mean_us=float(np.mean(intervals)), std_us=float(np.std(intervals)),
            max_jitter_us=float(np.max(jitter)), min_jitter_us=float(np.min(jitter)),
            intervals=intervals, jitter=jitter, ts=ts[1:],
            lost_events=lost_events,
            n_lost_total=sum(e["n_lost"] for e in lost_events),
        )

    # ── 从站回环时延 = ts_tx[i] - ts_rx[i] ──
    ts_rx_list = series.get("ts_rx", [])
    ts_tx_list = series.get("ts_tx", [])
    if len(ts_rx_list) >= 10 and len(ts_tx_list) >= 10:
        n = min(len(ts_rx_list), len(ts_tx_list))
        arr_rx = np.array(ts_rx_list[:n], dtype=np.float64)
        arr_tx = np.array(ts_tx_list[:n], dtype=np.float64)
        delays = (arr_tx - arr_rx) * 1e6
        valid  = (delays > 0) & (delays < 5000)   # 0 ~ 5 ms 合理范围
        if valid.sum() >= 5:
            result["roundtrip"] = dict(
                label="从站回环时延",
                ts=arr_rx[valid],
                delays_us=delays[valid],
                mean_us=float(np.mean(delays[valid])),
                max_us=float(np.max(delays[valid])),
                min_us=float(np.min(delays[valid])),
                std_us=float(np.std(delays[valid])),
            )
    return result

# ══════════════════════════════════════════════════════════
# 3c. 延迟分析
# ══════════════════════════════════════════════════════════
def compute_response_delay(ts_tgt, tgt, y_query, t_query):
    ts_arr = np.array(ts_tgt, dtype=np.float64)
    v_arr  = np.array(tgt,    dtype=np.float64)
    mask = (ts_arr >= max(ts_arr[0], t_query-3.0)) & (ts_arr <= t_query+0.2)
    if mask.sum() < 2: return None
    t_seg = ts_arr[mask]; v_seg = v_arr[mask]; diff = v_seg - y_query
    crossings = []
    for i in range(len(diff)-1):
        if diff[i]*diff[i+1] <= 0:
            denom = diff[i]-diff[i+1]
            frac = abs(diff[i])/abs(denom) if abs(denom) > 1e-10 else 0.5
            crossings.append(t_seg[i]+frac*(t_seg[i+1]-t_seg[i]))
    if not crossings: return None
    before = [c for c in crossings if c <= t_query+1e-6]
    t_tgt = max(before) if before else min(crossings, key=lambda x: abs(x-t_query))
    return t_tgt, t_query, (t_query-t_tgt)*1000.0

def compute_xcorr_lag(ts_tgt, tgt, ts_act, act, t_start, t_end):
    ts_t = np.array(ts_tgt, dtype=np.float64); v_t = np.array(tgt, dtype=np.float64)
    ts_a = np.array(ts_act, dtype=np.float64); v_a = np.array(act, dtype=np.float64)
    m_t = (ts_t >= t_start) & (ts_t <= t_end)
    m_a = (ts_a >= t_start) & (ts_a <= t_end)
    if m_t.sum() < 5 or m_a.sum() < 5: return None, None
    dt = float(np.median(np.diff(ts_t[m_t])))
    if dt <= 0: return None, None
    t_grid = np.arange(t_start, t_end, dt)
    if len(t_grid) < 5: return None, None
    tgt_r = np.interp(t_grid, ts_t[m_t], v_t[m_t])
    act_r = np.interp(t_grid, ts_a[m_a], v_a[m_a])
    tgt_n = tgt_r - np.mean(tgt_r); act_n = act_r - np.mean(act_r)
    norm = np.linalg.norm(tgt_n)*np.linalg.norm(act_n)
    if norm < 1e-10: return None, None
    corr = np.correlate(act_n, tgt_n, mode="full")
    lags = np.arange(-(len(tgt_n)-1), len(tgt_n))*dt
    idx = int(np.argmax(corr))
    return float(lags[idx])*1000.0, float(corr[idx]/norm)

# ══════════════════════════════════════════════════════════
# 4. XML layout（可选）
# ══════════════════════════════════════════════════════════
def layout_from_xml(path):
    tree = ET.parse(path); root = tree.getroot()
    rx_entries, tx_entries = [], []
    def parse_entry(e):
        name = (e.findtext("Name") or "").strip(); bo = e.findtext("BitOffset"); bl = e.findtext("BitLen")
        if not name or not bo: return None
        try: return dict(name=name, byte_off=int(bo)//8, bit_len=int(bl) if bl else 32)
        except ValueError: return None
    def collect(root):
        for module in root.iter("Module"):
            for rx in module.findall("RxPdo"):
                for e in rx.findall("Entry"):
                    v = parse_entry(e)
                    if v: rx_entries.append(v)
            for tx in module.findall("TxPdo"):
                for e in tx.findall("Entry"):
                    v = parse_entry(e)
                    if v: tx_entries.append(v)
        if not rx_entries:
            for rx in root.iter("RxPdo"):
                for e in rx.findall("Entry"):
                    v = parse_entry(e); v and rx_entries.append(v)
            for tx in root.iter("TxPdo"):
                for e in tx.findall("Entry"):
                    v = parse_entry(e); v and tx_entries.append(v)
    collect(root)
    rx_map = {e["name"].lower(): e for e in rx_entries}
    tx_map = {e["name"].lower(): e for e in tx_entries}
    TARGET_KW = ("target","cmd","command","setpoint","set")
    ACTUAL_KW  = ("actual","feedback","position","pos")
    VEL_KW     = ("velocity","speed","vel")
    TORQ_KW    = ("torque","force","current")
    # Fallback：若 tx_map 为空但 rx_map 中同时包含 target 和 actual 条目
    # （用户把所有字段都放进了 RxPdo），将 actual/vel/torq 条目从 rx_map 迁到 tx_map
    if not tx_map:
        for k in list(rx_map.keys()):
            is_tgt  = any(w in k for w in TARGET_KW)
            is_act  = any(w in k for w in ACTUAL_KW) and not is_tgt
            is_v    = any(w in k for w in VEL_KW)
            is_t    = any(w in k for w in TORQ_KW)
            if is_act or is_v or is_t:
                tx_map[k] = rx_map.pop(k)
    axes, vel_torq = [], []
    used_tx = set()
    for rname, re in rx_map.items():
        axis = rname.split("-")[0].split(" ")[0].upper(); matched = None
        for tname, te in tx_map.items():
            if tname in used_tx or not tname.startswith(axis.lower()): continue
            if any(k in tname for k in VEL_KW+TORQ_KW): continue
            if any(k in tname for k in ACTUAL_KW) or (
               any(k in rname for k in TARGET_KW) and not any(k in tname for k in TARGET_KW)):
                matched = (tname, te); break
        if matched:
            tname, te = matched; used_tx.add(tname)
            axes.append(dict(name=axis, target_off=re["byte_off"],
                             actual_off=te["byte_off"], range=0, mean=0, match=1.0))
    for tname, te in tx_map.items():
        if tname in used_tx: continue
        axis = tname.split("-")[0].split(" ")[0].upper()
        if any(k in tname for k in VEL_KW):
            vel_torq.append(dict(name=f"{axis}-速度", offset=te["byte_off"], range=0, score=1.0))
        elif any(k in tname for k in TORQ_KW):
            vel_torq.append(dict(name=f"{axis}-转矩", offset=te["byte_off"], range=0, score=1.0))
    if not axes: raise ValueError("XML 中未找到有效的 target/actual 配对")
    all_offs = [a["target_off"] for a in axes]+[a["actual_off"] for a in axes]+[ch["offset"] for ch in vel_torq]
    return dict(axes=axes, vel_torq=vel_torq, payload_len=max(all_offs)+4, confidence=1.0)

# ══════════════════════════════════════════════════════════
# 5. 颜色 & 绘图
# ══════════════════════════════════════════════════════════
C_TARGET = "#e53e3e"   # 红 — 目标/发送
C_ACTUAL = "#3182ce"   # 蓝 — 实际/接收
C_RT     = "#38a169"   # 绿 — 回环时延
C_ERROR  = "#718096"
C_VEL    = "#38a169"
C_TORQ   = "#d69e2e"
EXTRA_C    = ["#9b59b6","#1abc9c","#e67e22","#3498db","#f39c12"]
AXIS_COLORS= ["#e53e3e","#3182ce","#38a169","#805ad5","#dd6b20","#d69e2e","#00b5d8","#e91e63"]
# 波形比较专用：每轴 [目标色, 实际色, 误差色]，全部实线，15色不重复
COMPARE_PALETTE = [
    ("#e53e3e", "#2b6cb0", "#276749"),   # X: 红, 蓝, 深绿
    ("#dd6b20", "#553c9a", "#0987a0"),   # Y: 橙, 深紫, 深青
    ("#d53f8c", "#b7791f", "#285e61"),   # Z: 粉红, 金棕, 深蓝绿
    ("#38a169", "#9b2335", "#805ad5"),   # B: 绿, 深红, 紫
    ("#744210", "#1a365d", "#1abc9c"),   # C: 棕, 深蓝, 青绿
]

# ══════════════════════════════════════════════════════════
# 5a. LTTB 降采样（Largest Triangle Three Buckets）
#     保持波形视觉特征，同时大幅减少渲染点数
# ══════════════════════════════════════════════════════════
_MAX_PTS = 8000   # 每条曲线最多渲染点数（超过时自动降采样）

def _lttb(ts, vals, threshold=_MAX_PTS):
    """LTTB 降采样：O(threshold) 时间，视觉失真极小。"""
    ts   = np.asarray(ts,   dtype=np.float64)
    vals = np.asarray(vals, dtype=np.float64)
    n = len(ts)
    if n <= threshold:
        return ts, vals
    every = (n - 2) / (threshold - 2)
    sampled = np.empty(threshold, dtype=np.intp)
    sampled[0] = 0
    a = 0
    for i in range(1, threshold - 1):
        avg_s = int((i + 1) * every) + 1
        avg_e = min(int((i + 2) * every) + 1, n)
        avg_x = float(np.mean(ts[avg_s:avg_e]))
        avg_y = float(np.mean(vals[avg_s:avg_e]))
        rng_s = int(i * every) + 1
        rng_e = min(int((i + 1) * every) + 1, n)
        ax_v = float(ts[a]); ay_v = float(vals[a])
        r_ts = ts[rng_s:rng_e]; r_vs = vals[rng_s:rng_e]
        areas = np.abs((ax_v - avg_x) * (r_vs - ay_v)
                       - (ax_v - r_ts) * (avg_y - ay_v)) * 0.5
        sampled[i] = rng_s + int(np.argmax(areas))
        a = int(sampled[i])
    sampled[threshold - 1] = n - 1
    return ts[sampled], vals[sampled]

def _fmt_ax(ax):
    ax.grid(True, alpha=0.25, linewidth=0.7)
    ax.xaxis.set_major_formatter(mticker.FormatStrFormatter("%.3f"))
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%d"))
    ax.tick_params(labelsize=9)

def plot_position(fig, axis_name, series, style="line"):
    fig.clear()
    ax = fig.add_subplot(111)

    ts_rx = series["ts_rx"]; ts_tx = series["ts_tx"]
    tgt = series.get(axis_name+"-target", []); act = series.get(axis_name+"-actual", [])
    n = min(len(ts_rx), len(ts_tx), len(tgt), len(act))

    if n == 0:
        ax.text(0.5, 0.5, "无数据", ha="center", va="center", transform=ax.transAxes)
        fig.tight_layout()
        return

    if style == "line":
        ax.plot(ts_rx[:n], tgt[:n], color=C_TARGET, lw=0.8, label=f"{axis_name}-目标", rasterized=True)
        ax.plot(ts_tx[:n], act[:n], color=C_ACTUAL, lw=0.8, label=f"{axis_name}-实际", rasterized=True)
    else:
        ax.scatter(ts_rx[:n], tgt[:n], s=1, color=C_TARGET, label=f"{axis_name}-目标", rasterized=True)
        ax.scatter(ts_tx[:n], act[:n], s=1, color=C_ACTUAL, label=f"{axis_name}-实际", rasterized=True)

    ax.set_title(f"{axis_name} 轴  目标 vs 实际位置", fontsize=13)
    ax.set_xlabel("时间 (s)", fontsize=10)
    ax.set_ylabel("位置 (counts)", fontsize=10)
    ax.legend(loc="best", fontsize=9)
    _fmt_ax(ax)
    fig.tight_layout()

def plot_error(fig, axis_name, series):
    fig.clear(); ax = fig.add_subplot(111)
    tgt = series.get(axis_name+"-target", []); act = series.get(axis_name+"-actual", [])
    ts_rx = series["ts_rx"]; ts_tx = series["ts_tx"]
    n = min(len(ts_rx), len(ts_tx), len(tgt), len(act))
    if n > 0:
        err = np.asarray(act[:n], dtype=np.float64) - np.asarray(tgt[:n], dtype=np.float64)
        ts_e = np.asarray(ts_tx[:n], dtype=np.float64)
        ax.fill_between(ts_e, err, 0, color=C_ERROR, alpha=0.35, linewidth=0)
        ax.plot(ts_e, err, color=C_ERROR, lw=0.5, rasterized=True)
        ax.axhline(0, color="black", lw=0.6, ls="--")
    ax.set_title(f"{axis_name} 轴  跟随误差 (实际 - 目标)", fontsize=13)
    ax.set_xlabel("时间 (s)", fontsize=10); ax.set_ylabel("误差 (counts)", fontsize=10)
    _fmt_ax(ax); fig.tight_layout()

def plot_velocity(fig, layout, series):
    fig.clear()
    vel_chs = [ch for ch in layout["vel_torq"]
               if "速度" in ch["name"] or "velocity" in ch["name"].lower()]
    if not vel_chs:
        ax = fig.add_subplot(111)
        ax.text(0.5, 0.5, "未检测到速度信号", ha="center", va="center",
                transform=ax.transAxes, fontsize=14, color="#aaa")
        fig.tight_layout(); return
    ts_tx = series["ts_tx"]
    gs = fig.add_gridspec(len(vel_chs), 1, hspace=0.45)
    for i, ch in enumerate(vel_chs):
        ax = fig.add_subplot(gs[i]); vals = series.get(ch["name"], [])
        if ts_tx and vals:
            m = min(len(ts_tx), len(vals))
            ax.plot(ts_tx[:m], vals[:m], color=EXTRA_C[i%len(EXTRA_C)], lw=0.5, rasterized=True)
        ax.set_title(ch["name"], fontsize=11)
        ax.set_xlabel("时间 (s)", fontsize=9); ax.set_ylabel("速度", fontsize=9); _fmt_ax(ax)
    fig.tight_layout()

def plot_overview(fig, layout, series, style="line"):
    fig.clear(); axes_list = layout["axes"]; n = len(axes_list)
    if n == 0: return
    gs = fig.add_gridspec(n, 1, hspace=0.55)

    from matplotlib.ticker import FuncFormatter

    for i, a in enumerate(axes_list):
        ax = fig.add_subplot(gs[i])
        ts_rx = series["ts_rx"]; ts_tx = series["ts_tx"]
        tgt = series.get(a["name"]+"-target", []); act = series.get(a["name"]+"-actual", [])

        m = min(len(ts_rx), len(ts_tx), len(tgt), len(act))

        if m > 0 and tgt:
            ts_arr = np.array(ts_rx[:m], dtype=np.float64)
            val_arr = np.array(tgt[:m], dtype=np.float64)
            ax.plot(ts_arr, val_arr, color=C_TARGET, lw=0, marker=',', markersize=0.8,
                   label="目标", linestyle='None', rasterized=False)
        if m > 0 and act:
            ts_arr = np.array(ts_tx[:m], dtype=np.float64)
            val_arr = np.array(act[:m], dtype=np.float64)
            ax.plot(ts_arr, val_arr, color=C_ACTUAL, lw=0, marker=',', markersize=0.8,
                   label="实际", linestyle='None', rasterized=False)

        ax.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{x:.7f}'))
        ax.set_title(f"{a['name']} 轴", fontsize=9, loc="left", pad=2)
        ax.set_ylabel("counts", fontsize=8)
        if i == n-1: ax.set_xlabel("时间 (s)", fontsize=9)
        ax.legend(fontsize=7, loc="upper right"); _fmt_ax(ax)
    fig.tight_layout(pad=1.2)

# ══════════════════════════════════════════════════════════
# 5b. 通信质量图绘制（单图 + 三线可选）
# ══════════════════════════════════════════════════════════
def draw_comm_chart(ax, jitter_data, show_tx=True, show_rx=True, show_rt=True):
    """在已有 axes 上绘制通信质量三线图，调用者负责 canvas.draw()。"""
    ax.clear()
    if not jitter_data:
        ax.text(0.5, 0.5, "无通信质量数据", ha="center", va="center",
                transform=ax.transAxes, fontsize=14, color="#aaa")
        return

    d_tx = jitter_data.get("ts_rx")       # 主站发送间隔
    d_rx = jitter_data.get("ts_tx")       # 主站接收间隔
    d_rt = jitter_data.get("roundtrip")   # 从站回环时延
    plotted = False

    if show_tx and d_tx is not None:
        ax.plot(d_tx["ts"], d_tx["intervals"], color=C_TARGET, lw=0.7,
                label=f"主站发送间隔  标称={d_tx['nominal_us']:.1f}µs  σ={d_tx['std_us']:.2f}µs",
                rasterized=True, alpha=0.9)
        ax.axhline(d_tx["nominal_us"], color=C_TARGET, lw=0.8, ls="--", alpha=0.35)
        plotted = True

    if show_rx and d_rx is not None:
        ax.plot(d_rx["ts"], d_rx["intervals"], color=C_ACTUAL, lw=0.7,
                label=f"主站接收间隔  标称={d_rx['nominal_us']:.1f}µs  σ={d_rx['std_us']:.2f}µs",
                rasterized=True, alpha=0.9)
        ax.axhline(d_rx["nominal_us"], color=C_ACTUAL, lw=0.8, ls="--", alpha=0.35)
        plotted = True

    if show_rt and d_rt is not None:
        ax.plot(d_rt["ts"], d_rt["delays_us"], color=C_RT, lw=0.7,
                label=f"从站回环时延  均值={d_rt['mean_us']:.1f}µs  最大={d_rt['max_us']:.1f}µs",
                rasterized=True, alpha=0.9)
        ax.axhline(d_rt["mean_us"], color=C_RT, lw=0.8, ls="--", alpha=0.35)
        plotted = True

    # 丢帧事件：红色竖线
    for src_d in [d_tx, d_rx]:
        if src_d is None: continue
        for ev in src_d.get("lost_events", []):
            ax.axvline(ev["time_s"], color="#e74c3c", lw=1.1, alpha=0.7, zorder=5)

    if not plotted:
        ax.text(0.5, 0.5, "请勾选至少一项", ha="center", va="center",
                transform=ax.transAxes, fontsize=12, color="#aaa")

    ax.set_xlabel("时间 (s)", fontsize=10)
    ax.set_ylabel("间隔 / 时延 (µs)", fontsize=10)
    ax.set_title("通信周期分析  （红色竖线 = 丢帧事件位置）", fontsize=11)
    if plotted: ax.legend(fontsize=9, loc="upper right")
    ax.grid(True, alpha=0.22, linewidth=0.7)
    ax.xaxis.set_major_formatter(mticker.FormatStrFormatter("%.3f"))
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f"))
    ax.tick_params(labelsize=9)
    ax.figure.tight_layout()

# ══════════════════════════════════════════════════════════
# 6. 鼠标交互
# ══════════════════════════════════════════════════════════
def add_interactions(canvas, delay_info=None, plot_style_var=None, two_point_mode=None):
    fig = canvas.figure
    _drag  = {"active": False, "x": 0, "y": 0, "ax": None}
    _annot = {"obj": None, "vline": None, "hline": None, "ax": None}
    _delay_annot = []
    _two_point = {"points": [], "arts": []}  # 两点测量
    _last_draw   = [0.0]   # 拖拽帧率限制（~30 fps）

    def on_scroll(ev):
        if ev.inaxes is None: return
        ax = ev.inaxes; factor = 0.80 if ev.button=="up" else 1.0/0.80
        xd,yd = ev.xdata, ev.ydata
        if xd is None or yd is None: return
        x0,x1 = ax.get_xlim(); y0,y1 = ax.get_ylim()
        ax.set_xlim(xd-(xd-x0)*factor, xd+(x1-xd)*factor)
        ax.set_ylim(yd-(yd-y0)*factor, yd+(y1-yd)*factor)
        canvas.draw_idle()

    def on_press(ev):
        if ev.button==1 and ev.inaxes:
            _drag.update(active=True, x=ev.x, y=ev.y, ax=ev.inaxes)

    def on_release(ev):
        if ev.button==1: _drag["active"] = False

    def on_motion(ev):
        if not _drag["active"]: return
        ax = _drag["ax"]; dx = ev.x-_drag["x"]; dy = ev.y-_drag["y"]
        _drag["x"]=ev.x; _drag["y"]=ev.y
        x0,x1=ax.get_xlim(); y0,y1=ax.get_ylim(); w=x1-x0; h=y1-y0
        fw,fh = fig.get_size_inches()*fig.dpi
        # 平移：保持坐标范围不变，只移动位置
        ax.set_xlim(x0-dx/fw*w, x1-dx/fw*w)
        ax.set_ylim(y0-dy/fh*h, y1-dy/fh*h)
        now = time.monotonic()
        if now - _last_draw[0] >= 0.033:   # 限制约 30 fps，避免低配机卡顿
            canvas.draw_idle()
            _last_draw[0] = now

    def _clear_annot():
        for k in ("obj","vline","hline"):
            if _annot[k] is not None:
                try: _annot[k].remove()
                except: pass
                _annot[k] = None
        _annot["ax"] = None

    def _clear_delay_annot():
        for art in _delay_annot:
            try: art.remove()
            except: pass
        _delay_annot.clear()

    def _clear_two_point():
        for art in _two_point["arts"]:
            try: art.remove()
            except: pass
        _two_point["arts"].clear()
        _two_point["points"].clear()

    def _do_delay_measure(ax, x_click, y_click):
        info   = delay_info; series = info["get_series"]()
        aname  = info["axis_name"]() if callable(info["axis_name"]) else info["axis_name"]
        if not series: return
        ts_act = series.get("ts_tx",[]); act = series.get(aname+"-actual",[])
        ts_tgt = series.get("ts_rx",[]); tgt = series.get(aname+"-target",[])
        if not ts_act or not act or not ts_tgt or not tgt: return
        idx = int(np.argmin(np.abs(np.array(ts_act)-x_click)))
        t_actual = float(ts_act[idx]); y_actual = float(act[idx])
        result = compute_response_delay(ts_tgt, tgt, y_actual, t_actual)
        _clear_delay_annot()
        if result is None:
            info["result_var"].set("未找到对应目标位置穿越点")
            _delay_annot.append(ax.axvline(t_actual, color="#e53e3e", lw=1.2, ls=":", alpha=0.9))
            canvas.draw_idle(); return
        t_tgt, t_act, delay_ms = result
        arts = [
            ax.axhline(y_actual, color="#f39c12", lw=0.8, ls="--", alpha=0.7),
            ax.axvline(t_tgt,    color=C_TARGET,  lw=1.4, ls="--", alpha=0.85),
            ax.axvline(t_act,    color=C_ACTUAL,  lw=1.4, ls="--", alpha=0.85),
            ax.scatter([t_tgt], [y_actual], color=C_TARGET, s=40, zorder=10),
            ax.scatter([t_act], [y_actual], color=C_ACTUAL, s=40, zorder=10),
        ]
        mid_t=(t_tgt+t_act)/2; _,_,y0a,y1a=(*ax.get_xlim(),*ax.get_ylim())
        va_txt = "bottom" if y_actual < (y0a+y1a)/2 else "top"
        sign = "滞后" if delay_ms >= 0 else "超前"
        arts.append(ax.annotate(
            f"  响应{sign}  Δt = {abs(delay_ms):.2f} ms  ",
            xy=(mid_t,y_actual), xytext=(mid_t,y_actual),
            fontsize=10, ha="center", va=va_txt, color="white",
            bbox=dict(boxstyle="round,pad=0.4", fc="#2c3e50", ec="#f39c12", lw=1.5, alpha=0.93)))
        try:
            arts.append(ax.annotate("", xy=(t_act,y_actual), xytext=(t_tgt,y_actual),
                arrowprops=dict(arrowstyle="<->", color="#f39c12", lw=1.5)))
        except: pass
        _delay_annot.extend(arts); canvas.draw_idle()
        info["result_var"].set(
            f"t_目标={t_tgt:.4f}s  t_实际={t_act:.4f}s  "
            f"响应{'滞后' if delay_ms>=0 else '超前'} {abs(delay_ms):.2f} ms")

    def on_right_click(ev):
        if ev.button!=3 or ev.inaxes is None: return
        ax=ev.inaxes; xd,yd=ev.xdata,ev.ydata
        if xd is None or yd is None: return

        # 自动吸附到最近的数据点（目标位置或实际位置）
        min_dist,best_x,best_y,best_label=float("inf"),xd,yd,None
        style = plot_style_var.get() if plot_style_var else "line"

        if style == "scatter":
            # 散点图模式：从scatter对象中查找
            for collection in ax.collections:
                if hasattr(collection, 'get_offsets') and hasattr(collection, 'get_label'):
                    label = collection.get_label()
                    if not label or label.startswith("_"): continue
                    offsets = collection.get_offsets()
                    if len(offsets)==0: continue
                    xdata, ydata = offsets[:, 0], offsets[:, 1]
                    dists=((xdata-xd)**2+(ydata-yd)**2)**0.5
                    idx=dists.argmin()
                    if dists[idx]<min_dist:
                        min_dist,best_x,best_y,best_label=dists[idx],xdata[idx],ydata[idx],label
        else:
            # 曲线图模式：从line对象中查找
            for line in ax.get_lines():
                label = line.get_label()
                if not label or label.startswith("_"): continue
                xdata, ydata = line.get_xdata(), line.get_ydata()
                if len(xdata)==0: continue
                dists=((xdata-xd)**2+(ydata-yd)**2)**0.5
                idx=dists.argmin()
                if dists[idx]<min_dist:
                    min_dist,best_x,best_y,best_label=dists[idx],xdata[idx],ydata[idx],label

        xd,yd=best_x,best_y

        # 两点测量模式
        if two_point_mode and two_point_mode["active"].get():
            _clear_annot(); _clear_delay_annot()
            pts = _two_point["points"]
            pts.append((xd, yd))
            _two_point["arts"].append(ax.scatter([xd], [yd], color="#e74c3c", s=60, zorder=15, marker="x", linewidths=2))
            if len(pts) == 2:
                t1,y1 = pts[0]; t2,y2 = pts[1]
                dt = abs(t2-t1); dy = abs(y2-y1)
                mode = two_point_mode.get("mode", "position")
                if mode == "velocity":
                    _two_point["arts"].extend([
                        ax.plot([t1,t2], [y1,y2], color="#e74c3c", lw=1.5, ls="--", alpha=0.8)[0],
                        ax.annotate(f"Δt={dt*1000:.2f}ms\nΔv={dy:.1f}\na={dy/dt if dt>0 else 0:.1f}/s²",
                                    xy=((t1+t2)/2, (y1+y2)/2), fontsize=9, color="white", ha="center",
                                    bbox=dict(boxstyle="round,pad=0.5", fc="#e74c3c", alpha=0.9))
                    ])
                    two_point_mode["result_var"].set(f"Δt={dt*1000:.2f}ms  Δ速度={dy:.1f}  平均加速度={dy/dt if dt>0 else 0:.1f}/s²")
                else:
                    _two_point["arts"].extend([
                        ax.plot([t1,t2], [y1,y2], color="#e74c3c", lw=1.5, ls="--", alpha=0.8)[0],
                        ax.annotate(f"Δt={dt*1000:.2f}ms\nΔy={int(dy):,}\nv={dy/dt if dt>0 else 0:.1f}/s",
                                    xy=((t1+t2)/2, (y1+y2)/2), fontsize=9, color="white", ha="center",
                                    bbox=dict(boxstyle="round,pad=0.5", fc="#e74c3c", alpha=0.9))
                    ])
                    two_point_mode["result_var"].set(f"Δt={dt*1000:.2f}ms  Δ位置={int(dy):,}  平均速度={dy/dt if dt>0 else 0:.1f}/s")
                _two_point["points"].clear()
            canvas.draw_idle()
            return

        if delay_info and delay_info["active"].get():
            _clear_annot(); _do_delay_measure(ax,xd,yd); return
        _clear_delay_annot(); _clear_annot(); _clear_two_point()
        _annot["vline"]=ax.axvline(xd,color="#e67e22",lw=1.0,ls="--",alpha=0.8)
        _annot["hline"]=ax.axhline(yd,color="#e67e22",lw=1.0,ls="--",alpha=0.8)
        x0,x1=ax.get_xlim(); y0,y1=ax.get_ylim()
        ha="left" if xd<(x0+x1)/2 else "right"; va="bottom" if yd<(y0+y1)/2 else "top"
        label_text = f"  {best_label}\n" if best_label else ""
        _annot["obj"]=ax.annotate(
            f"{label_text}  t = {xd:.4f} s\n  y = {int(round(yd)):,}  ",
            xy=(xd,yd), xytext=(xd,yd), fontsize=10, ha=ha, va=va, color="white",
            bbox=dict(boxstyle="round,pad=0.4",fc="#2c3e50",ec="#e67e22",lw=1.2,alpha=0.92))
        _annot["ax"]=ax; canvas.draw_idle()

    def on_left_click_clear(ev):
        if ev.button==1 and (_annot["obj"] is not None or _delay_annot or _two_point["arts"]):
            _clear_annot(); _clear_delay_annot(); _clear_two_point(); canvas.draw_idle()

    canvas.mpl_connect("scroll_event",         on_scroll)
    canvas.mpl_connect("button_press_event",   on_press)
    canvas.mpl_connect("button_press_event",   on_right_click)
    canvas.mpl_connect("button_press_event",   on_left_click_clear)
    canvas.mpl_connect("button_release_event", on_release)
    canvas.mpl_connect("motion_notify_event",  on_motion)

# ══════════════════════════════════════════════════════════
# 7. GUI
# ══════════════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EtherCAT PDO 曲线分析工具  v7")
        self.geometry("1400x900")
        self.minsize(900, 600)
        self._layout      = None
        self._series      = {}
        self._jitter      = {}
        self._figs        = {}
        self._canvases    = {}
        self._delay_infos = {}
        self._comm_state    = {}
        self._compare_vars  = {}
        self._compare_state = {}
        self._vel_vars      = {}
        self._vel_state     = {}
        self._frame_analysis_state = {}
        self._xml_loaded    = False
        self._plot_style  = tk.StringVar(value="line")
        self._drawn_tabs  = set()    # 已渲染过的标签页 key 集合
        self._tab_order   = []       # 标签页顺序（与 notebook 顺序一致）
        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=(6,4)); top.pack(fill=tk.X)
        ttk.Button(top, text="打开数据文件 (.pcap/.ncap/.pcapng)",
                   command=self._open_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="加载 XML 配置（可选，更精确）",
                   command=self._load_xml).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="导出 CSV",
                   command=self._export_csv).pack(side=tk.LEFT, padx=4)
        ttk.Separator(top, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=2)
        ttk.Label(top, text="图表样式:").pack(side=tk.LEFT)
        ttk.Radiobutton(top, text="曲线图", variable=self._plot_style,
                        value="line",    command=self._on_style_change).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(top, text="散点图", variable=self._plot_style,
                        value="scatter", command=self._on_style_change).pack(side=tk.LEFT, padx=2)
        self._lbl_cfg  = ttk.Label(top, text="[自动检测模式]", foreground="#2980b9")
        self._lbl_cfg.pack(side=tk.LEFT, padx=10)
        self._lbl_stat = ttk.Label(top, text="请打开数据文件", foreground="#555")
        self._lbl_stat.pack(side=tk.RIGHT, padx=8)
        self._pbar = ttk.Progressbar(self, mode="determinate", maximum=100)
        self._pbar.pack(fill=tk.X, padx=6, pady=2)
        ttk.Label(self,
            text="操作：滚轮缩放  |  左键拖拽平移  |  右键显示坐标  |  Home/R 键复位视图  |  +/- 键缩放",
            foreground="#888", font=("",9)).pack(anchor=tk.W, padx=8)
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        # 键盘快捷键：Home/r = 重置视图，+/- = 缩放
        self.bind("<Home>",    self._reset_view)
        self.bind("<r>",       self._reset_view)
        self.bind("<R>",       self._reset_view)
        self.bind("<equal>",   lambda e: self._kb_zoom(0.8))
        self.bind("<minus>",   lambda e: self._kb_zoom(1.25))
        self.bind("<KP_Add>",  lambda e: self._kb_zoom(0.8))
        self.bind("<KP_Subtract>", lambda e: self._kb_zoom(1.25))
        frm = ttk.Frame(self._nb); self._nb.add(frm, text="  欢迎  ")
        ttk.Label(frm,
            text="请点击左上角「打开数据文件」\n\n"
                 "• 无 XML 时自动扫描检测 PDO 布局\n"
                 "• 图表样式：曲线图 / 散点图\n"
                 "• 通信质量页：发送(红) / 接收(蓝) / 回环(绿) 三线可独立勾选\n"
                 "• 丢帧事件列表：点击「跳转▶」直接定位到发生时刻\n"
                 "• 位置页：「延迟测量」→ 右键实际曲线测响应延迟",
            font=("Microsoft YaHei",12), justify=tk.CENTER,
            foreground="#555").pack(expand=True)

    # ── 样式切换 ──
    def _on_style_change(self):
        if not self._series or not self._layout: return
        # 清空已渲染标记，重新渲染当前可见标签页
        self._drawn_tabs.clear()
        self._draw_active_tab()

    def _find_xml_near(self, data_path):
        d = os.path.dirname(os.path.abspath(data_path))
        xmls = [os.path.join(d,f) for f in os.listdir(d) if f.lower().endswith(".xml")]
        if len(xmls)==1: return xmls[0]
        if len(xmls)>1:
            return filedialog.askopenfilename(
                title="同目录发现多个XML，请选择",initialdir=d,
                filetypes=[("XML配置","*.xml"),("所有文件","*.*")])
        return None

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="选择 EtherCAT 数据文件",
            filetypes=[("数据包文件","*.pcap *.ncap *.pcapng *.cap"),("所有文件","*.*")])
        if not path: return
        self._path = path
        if not self._xml_loaded:
            self._layout = None
            xml_path = self._find_xml_near(path)
            if xml_path:
                try:
                    self._layout = layout_from_xml(xml_path)
                    self._lbl_cfg.config(text=f"[自动加载XML: {os.path.basename(xml_path)}]",
                                         foreground="#27ae60")
                except Exception:
                    self._layout = None
                    self._lbl_cfg.config(text="[XML解析失败，改用自动检测]", foreground="#e67e22")
            else:
                self._lbl_cfg.config(text="[自动检测模式]", foreground="#2980b9")
        if self._layout is not None:
            self._lbl_stat.config(text=f"已加载XML配置（{len(self._layout['axes'])}个轴），正在解析…")
        else:
            self._lbl_stat.config(text="未找到XML，正在全文件扫描检测PDO布局…")
        self._pbar.config(mode="indeterminate"); self._pbar.start(12)
        threading.Thread(target=self._worker, args=(path,), daemon=True).start()

    def _worker(self, path):
        try:
            if self._layout is None:
                layout = auto_detect(path)
                if layout is None:
                    self.after(0, lambda: messagebox.showerror(
                        "自动检测失败",
                        "未能在文件中找到 EtherCAT LRW PDO 帧。\n\n"
                        "可能原因：\n• 文件不含 EtherType=0x88A4 数据\n"
                        "• 机器完全静止（各轴无运动）\n\n"
                        "解决方法：点击「加载 XML 配置」手动指定偏移"))
                    self.after(0, self._pbar.stop); return
                self._layout = layout
                self.after(0, lambda: self._lbl_stat.config(
                    text=f"自动检测到 {len(layout['axes'])} 个轴（置信度 {layout.get('confidence',0):.0%}），正在解析…"))
            self.after(0, self._pbar.stop)
            self.after(0, lambda: self._pbar.config(mode="determinate"))
            series = parse_data(path, self._layout,
                                progress_cb=lambda p: self.after(0, lambda p=p: self._set_pbar(p)))
            jitter = compute_jitter(series)
            self.after(0, lambda: self._on_loaded(series, jitter, path))
        except Exception as ex:
            import traceback; tb=traceback.format_exc()
            self.after(0, lambda: messagebox.showerror("错误", str(ex)+"\n\n"+tb[:800]))
            self.after(0, self._pbar.stop)

    def _set_pbar(self, p): self._pbar["value"] = int(p*100)

    def _on_loaded(self, series, jitter, path):
        self._pbar["value"] = 100
        self._series = series; self._jitter = jitter
        nrx=len(series["ts_rx"]); ntx=len(series["ts_tx"])
        dur=series["ts_tx"][-1] if series["ts_tx"] else 0
        axes=self._layout["axes"]; conf=self._layout.get("confidence",1.0)
        comm_info=""
        if "ts_rx" in jitter:
            d=jitter["ts_rx"]; lost=d["n_lost_total"]
            comm_info=(f"  |  周期={d['nominal_us']:.1f}µs (平均={d['mean_us']:.1f}µs)"
                       f"  抖动σ={d['std_us']:.2f}µs (平均={abs(d.get('jitter',[])).mean() if len(d.get('jitter',[]))>0 else 0:.2f}µs)"
                       f"  丢帧={'⚠'+str(lost) if lost else '✓0'}")
        self._lbl_stat.config(
            text=f"{os.path.basename(path)}  |  {nrx} 请求  {ntx} 响应"
                 f"  |  时长 {dur:.2f}s  |  {len(axes)} 轴  |  置信 {conf:.0%}"
                 + comm_info
                 + (f"  |  渲染上限 {_MAX_PTS} pts/线" if max(nrx,ntx)>_MAX_PTS else ""))
        self._rebuild_tabs()
        self._update_comm_display()
        # 懒加载：50ms 后渲染首个可见标签页（让 Tkinter 先完成布局）
        self.after(50, self._draw_active_tab)

    def _load_xml(self):
        path = filedialog.askopenfilename(title="选择 PDO XML 配置文件",
                                          filetypes=[("XML","*.xml"),("所有文件","*.*")])
        if not path: return
        try:
            self._layout     = layout_from_xml(path)
            self._xml_loaded = True
            self._lbl_cfg.config(text=f"[XML: {os.path.basename(path)}]", foreground="#27ae60")
            # 若已有数据文件，直接用新 XML 重新解析，无需用户再次打开文件
            if hasattr(self, "_path") and self._path:
                self._lbl_stat.config(
                    text=f"已加载 XML（{len(self._layout['axes'])} 轴），正在重新解析当前数据文件…")
                self._pbar.config(mode="indeterminate"); self._pbar.start(12)
                threading.Thread(target=self._worker, args=(self._path,), daemon=True).start()
            else:
                messagebox.showinfo("成功",
                    f"XML 已加载，检测到 {len(self._layout['axes'])} 个轴\n请打开数据文件开始分析")
        except Exception as e:
            messagebox.showerror("XML 解析错误", str(e))

    def _rebuild_tabs(self):
        for tid in self._nb.tabs(): self._nb.forget(tid)
        self._figs.clear(); self._canvases.clear()
        self._delay_infos.clear(); self._comm_state.clear()
        self._compare_vars.clear(); self._compare_state.clear()
        self._vel_vars.clear(); self._vel_state.clear()
        self._drawn_tabs.clear(); self._tab_order.clear()
        self._insp_state = {}   # 重置帧检查器状态
        self._frame_analysis_state = {}  # 重置数据帧分析状态
        layout=self._layout; axes_list=layout["axes"]
        self._add_tab("总览","overview",(12,max(3*len(axes_list),6))); self._tab_order.append("overview")
        self._add_compare_tab(); self._tab_order.append("compare")
        vel=[ch for ch in layout["vel_torq"]
             if "速度" in ch["name"] or "velocity" in ch["name"].lower()]
        if vel: self._add_vel_tab(vel); self._tab_order.append("velocity")
        self._add_comm_tab(); self._tab_order.append("comm")
        self._add_frame_analysis_tab(); self._tab_order.append("frame_analysis")
        self._add_pdo_inspector_tab(); self._tab_order.append("inspector")

    def _add_tab(self, label, key, figsize=(13,5.5)):
        frm=ttk.Frame(self._nb); self._nb.add(frm, text=f"  {label}  ")
        fig=plt.Figure(figsize=figsize, dpi=100)
        canvas=FigureCanvasTkAgg(fig, master=frm)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        nav_frm=ttk.Frame(frm); nav_frm.pack(fill=tk.X)
        NavigationToolbar2Tk(canvas, nav_frm)
        add_interactions(canvas)
        self._figs[key]=fig; self._canvases[key]=canvas

    def _add_position_tab(self, label, key, axis_name):
        frm=ttk.Frame(self._nb); self._nb.add(frm, text=f"  {label}  ")
        fig=plt.Figure(figsize=(13,5.2), dpi=100)
        canvas=FigureCanvasTkAgg(fig, master=frm)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        ctrl=ttk.Frame(frm); ctrl.pack(fill=tk.X, pady=(0,1))
        delay_active=tk.BooleanVar(value=False)
        two_point_active=tk.BooleanVar(value=False)
        result_var=tk.StringVar(value="")
        btn=ttk.Button(ctrl, text="延迟测量 ○", width=18)
        btn.pack(side=tk.LEFT, padx=6)
        def _toggle():
            v=not delay_active.get(); delay_active.set(v)
            if v: two_point_active.set(False); btn2.config(text="两点测量 ○")
            btn.config(text="延迟测量 ● [右键点实际曲线]" if v else "延迟测量 ○")
            result_var.set("已开启 — 请右键单击实际位置曲线上的点" if v else "")
        btn.config(command=_toggle)
        btn2=ttk.Button(ctrl, text="两点测量 ○", width=18)
        btn2.pack(side=tk.LEFT, padx=4)
        def _toggle2():
            v=not two_point_active.get(); two_point_active.set(v)
            if v: delay_active.set(False); btn.config(text="延迟测量 ○"); result_var.set("")
            btn2.config(text="两点测量 ● [右键选2点]" if v else "两点测量 ○")
            if v: result_var.set("已开启 — 右键选择两个点")
            elif not delay_active.get(): result_var.set("")
        btn2.config(command=_toggle2)
        ttk.Button(ctrl, text="区间延迟分析",
                   command=lambda k=key,nm=axis_name: self._xcorr_delay(k,nm)
                   ).pack(side=tk.LEFT, padx=4)
        ttk.Label(ctrl, textvariable=result_var, foreground="#2980b9",
                  font=("Consolas",9)).pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        nav_frm=ttk.Frame(frm); nav_frm.pack(fill=tk.X)
        NavigationToolbar2Tk(canvas, nav_frm)
        delay_info={"active":delay_active,"get_series":lambda: self._series,
                    "axis_name":axis_name,"result_var":result_var}
        two_point_info={"active":two_point_active,"result_var":result_var}
        add_interactions(canvas, delay_info=delay_info, plot_style_var=self._plot_style, two_point_mode=two_point_info)
        self._figs[key]=fig; self._canvases[key]=canvas; self._delay_infos[key]=delay_info

    # ── 波形比较标签页 ──
    def _add_compare_tab(self):
        key = "compare"
        frm = ttk.Frame(self._nb)
        self._nb.add(frm, text="  位置波形  ")
        bg = self.cget("bg")
        axes_list = self._layout["axes"]

        # ── 下方通道面板（先 pack，让图表 expand 时不遮住它）──
        bottom = ttk.Frame(frm)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=4, pady=(0, 3))

        # 快速按钮行
        btn_row = ttk.Frame(bottom)
        btn_row.pack(fill=tk.X, pady=(2, 2))

        def _redraw():
            self._redraw_compare(self._compare_state["ax"],
                                 self._compare_state["canvas"])
        def _sel_tgt():
            for d in self._compare_vars.values(): d["target"].set(True);  _redraw()
        def _sel_act():
            for d in self._compare_vars.values(): d["actual"].set(True);  _redraw()
        def _sel_err():
            for d in self._compare_vars.values(): d["error"].set(True);   _redraw()
        def _sel_all():
            for d in self._compare_vars.values():
                d["target"].set(True); d["actual"].set(True); d["error"].set(True)
            _redraw()
        def _clr():
            for d in self._compare_vars.values():
                d["target"].set(False); d["actual"].set(False); d["error"].set(False)
            _redraw()

        for txt, cmd in [("全选目标", _sel_tgt), ("全选实际", _sel_act),
                         ("全选误差", _sel_err), ("全 选", _sel_all), ("清  空", _clr)]:
            ttk.Button(btn_row, text=txt, command=cmd, width=10).pack(side=tk.LEFT, padx=3)
        ttk.Label(btn_row, text="  各轴目标/实际/误差均采用独立颜色（见图例）",
                  foreground="#888", font=("", 8)).pack(side=tk.LEFT, padx=6)

        # 延迟测量控制行
        delay_row    = ttk.Frame(bottom)
        delay_row.pack(fill=tk.X, pady=(0, 2))
        axis_names   = [a["name"] for a in axes_list]
        axis_var     = tk.StringVar(value=axis_names[0] if axis_names else "")
        delay_active = tk.BooleanVar(value=False)
        two_point_active = tk.BooleanVar(value=False)
        result_var   = tk.StringVar(value="")
        ttk.Label(delay_row, text="延迟分析轴:").pack(side=tk.LEFT, padx=(3, 2))
        ttk.Combobox(delay_row, textvariable=axis_var, values=axis_names,
                     width=4, state="readonly").pack(side=tk.LEFT, padx=(0, 6))
        delay_btn = ttk.Button(delay_row, text="延迟测量 ○", width=22)
        delay_btn.pack(side=tk.LEFT, padx=3)
        def _toggle_delay():
            v = not delay_active.get(); delay_active.set(v)
            if v: two_point_active.set(False); two_point_btn.config(text="两点测量 ○")
            delay_btn.config(text="延迟测量 ● [右键实际曲线]" if v else "延迟测量 ○")
            result_var.set("已开启 — 选择轴后右键单击实际位置曲线" if v else "")
        delay_btn.config(command=_toggle_delay)
        two_point_btn = ttk.Button(delay_row, text="两点测量 ○", width=18)
        two_point_btn.pack(side=tk.LEFT, padx=3)
        def _toggle_two_point():
            v = not two_point_active.get(); two_point_active.set(v)
            if v: delay_active.set(False); delay_btn.config(text="延迟测量 ○"); result_var.set("")
            two_point_btn.config(text="两点测量 ● [右键选2点]" if v else "两点测量 ○")
            if v: result_var.set("已开启 — 右键选择两个点")
            elif not delay_active.get(): result_var.set("")
        two_point_btn.config(command=_toggle_two_point)
        ttk.Button(delay_row, text="区间延迟分析",
                   command=lambda: self._xcorr_delay("compare", axis_var.get())
                   ).pack(side=tk.LEFT, padx=4)
        ttk.Label(delay_row, textvariable=result_var, foreground="#2980b9",
                  font=("Consolas", 9)).pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)

        # 通道选择区（横向可滚动，网格排列：列=轴，行=类型）
        ch_lf = ttk.LabelFrame(bottom, text="  通道选择（可横向滚动）  ", padding=(4, 2))
        ch_lf.pack(fill=tk.X)
        ch_cvs = tk.Canvas(ch_lf, height=110, bg=bg, highlightthickness=0)
        ch_cvs.pack(side=tk.TOP, fill=tk.X)
        hscr = ttk.Scrollbar(ch_lf, orient=tk.HORIZONTAL, command=ch_cvs.xview)
        hscr.pack(side=tk.BOTTOM, fill=tk.X)
        ch_cvs.configure(xscrollcommand=hscr.set)
        inner = tk.Frame(ch_cvs, bg=bg)
        ch_cvs.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: ch_cvs.configure(scrollregion=ch_cvs.bbox("all")))

        # 网格布局：行0=轴名，行1=目标，行2=实际，行3=误差；列=各轴
        for i, a in enumerate(axes_list):
            nm    = a["name"]
            p     = COMPARE_PALETTE[i % len(COMPARE_PALETTE)]
            v_tgt = tk.BooleanVar(value=False)
            v_act = tk.BooleanVar(value=True)
            v_err = tk.BooleanVar(value=False)
            self._compare_vars[nm] = {"target": v_tgt, "actual": v_act, "error": v_err}

            col = i
            # 行0：轴名标题（用目标色）
            tk.Label(inner, text=f"—{nm}—", fg=p[0], bg=bg,
                     font=("", 11, "bold")).grid(row=0, column=col, padx=10, pady=(4, 1))
            # 行1：目标复选框（目标色）
            tk.Checkbutton(inner, text="目标", variable=v_tgt, command=_redraw,
                           fg=p[0], bg=bg, selectcolor=bg,
                           activebackground=bg, activeforeground=p[0],
                           font=("", 9)).grid(row=1, column=col, padx=10, pady=1, sticky="w")
            # 行2：实际复选框（实际色）
            tk.Checkbutton(inner, text="实际", variable=v_act, command=_redraw,
                           fg=p[1], bg=bg, selectcolor=bg,
                           activebackground=bg, activeforeground=p[1],
                           font=("", 9)).grid(row=2, column=col, padx=10, pady=1, sticky="w")
            # 行3：误差复选框（误差色）
            tk.Checkbutton(inner, text="误差", variable=v_err, command=_redraw,
                           fg=p[2], bg=bg, selectcolor=bg,
                           activebackground=bg, activeforeground=p[2],
                           font=("", 9)).grid(row=3, column=col, padx=10, pady=1, sticky="w")

        # ── 上方：图表区（占满剩余空间）──
        chart_frm = ttk.Frame(frm)
        chart_frm.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        fig = plt.Figure(figsize=(13, 4.8), dpi=100)
        ax  = fig.add_subplot(111)
        canvas = FigureCanvasTkAgg(fig, master=chart_frm)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        nav_frm = ttk.Frame(chart_frm)
        nav_frm.pack(fill=tk.X)
        NavigationToolbar2Tk(canvas, nav_frm)
        delay_info = {"active": delay_active, "get_series": lambda: self._series,
                      "axis_name": axis_var.get, "result_var": result_var}
        two_point_info = {"active": two_point_active, "result_var": result_var}
        add_interactions(canvas, delay_info=delay_info, plot_style_var=self._plot_style, two_point_mode=two_point_info)
        self._figs[key]   = fig
        self._canvases[key] = canvas
        self._compare_state = {"ax": ax, "canvas": canvas}

    def _redraw_compare(self, ax, canvas):
        ax.clear()
        if not self._series or not self._layout or not self._compare_vars:
            ax.text(0.5, 0.5, "请先加载数据文件",
                    ha="center", va="center", transform=ax.transAxes,
                    fontsize=14, color="#aaa")
            canvas.draw_idle(); return
        series = self._series; axes_list = self._layout["axes"]; plotted = False
        style = self._plot_style.get()
        for i, a in enumerate(axes_list):
            nm = a["name"]; vars_ = self._compare_vars.get(nm)
            if not vars_: continue
            p = COMPARE_PALETTE[i % len(COMPARE_PALETTE)]
            if vars_["target"].get():
                ts = series.get("ts_rx", []); vals = series.get(nm+"-target", [])
                if ts and vals:
                    n = min(len(ts), len(vals))
                    if style == "scatter":
                        # 散点图：显示全部原始点
                        ax.scatter(ts[:n], vals[:n], color=p[0], s=8,
                                   label=f"{nm}-目标", rasterized=True, linewidths=0, alpha=0.8)
                    else:
                        # 曲线图：全量数据连线
                        ax.plot(ts[:n], vals[:n], color=p[0], lw=1.0, ls="-",
                                label=f"{nm}-目标", rasterized=True, alpha=0.9)
                    plotted = True
            if vars_["actual"].get():
                ts = series.get("ts_tx", []); vals = series.get(nm+"-actual", [])
                if ts and vals:
                    n = min(len(ts), len(vals))
                    if style == "scatter":
                        # 散点图：显示全部原始点
                        ax.scatter(ts[:n], vals[:n], color=p[1], s=8,
                                   label=f"{nm}-实际", rasterized=True, linewidths=0, alpha=0.8)
                    else:
                        # 曲线图：全量数据连线
                        ax.plot(ts[:n], vals[:n], color=p[1], lw=1.0, ls="-",
                                label=f"{nm}-实际", rasterized=True, alpha=0.9)
                    plotted = True
            if vars_["error"].get():
                ts_rx = series.get("ts_rx",[]); ts_tx = series.get("ts_tx",[])
                tgt = series.get(nm+"-target",[]); act = series.get(nm+"-actual",[])
                n = min(len(ts_rx), len(ts_tx), len(tgt), len(act))
                if n > 0:
                    err = np.asarray(act[:n], dtype=np.float64) - np.asarray(tgt[:n], dtype=np.float64)
                    if style == "scatter":
                        # 散点图：显示全部原始点
                        ax.scatter(ts_tx[:n], err, color=p[2], s=8,
                                   label=f"{nm}-误差", rasterized=True, linewidths=0, alpha=0.8)
                    else:
                        # 曲线图：全量数据连线
                        ax.plot(ts_tx[:n], err, color=p[2], lw=1.0, ls="-",
                                label=f"{nm}-误差", rasterized=True, alpha=0.9)
                    plotted = True
        if not plotted:
            ax.text(0.5, 0.5, "请在下方勾选要显示的轴和数据类型",
                    ha="center", va="center", transform=ax.transAxes,
                    fontsize=13, color="#aaa")
        else:
            n_leg = sum(
                (d["target"].get()) + (d["actual"].get()) + (d["error"].get())
                for d in self._compare_vars.values())
            ax.legend(fontsize=9, loc="upper right",
                      ncol=max(1, n_leg // 8 + 1))
        ax.set_title("位置波形  （各轴目标/实际/误差均用独立颜色）", fontsize=11)
        ax.set_xlabel("时间 (s)", fontsize=10)
        ax.set_ylabel("位置 / 误差 (counts)", fontsize=10)
        _fmt_ax(ax); ax.figure.tight_layout(); canvas.draw_idle()

    # ── 速度波形标签页 ──
    def _add_vel_tab(self, vel_chs):
        key = "velocity"
        frm = ttk.Frame(self._nb)
        self._nb.add(frm, text="  速度波形  ")
        bg = self.cget("bg")

        bottom = ttk.Frame(frm)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=4, pady=(0, 3))

        btn_row = ttk.Frame(bottom)
        btn_row.pack(fill=tk.X, pady=(2, 2))

        def _redraw():
            self._redraw_vel(self._vel_state["ax"], self._vel_state["canvas"])
        def _sel_all():
            for v in self._vel_vars.values(): v.set(True); _redraw()
        def _clr():
            for v in self._vel_vars.values(): v.set(False); _redraw()

        ttk.Button(btn_row, text="全 选", command=_sel_all, width=8).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="清 空", command=_clr,     width=8).pack(side=tk.LEFT, padx=3)

        # 两点测量控制
        two_point_active = tk.BooleanVar(value=False)
        result_var = tk.StringVar(value="")
        two_point_btn = ttk.Button(btn_row, text="两点测量 ○", width=18)
        two_point_btn.pack(side=tk.LEFT, padx=6)
        def _toggle_two_point():
            v = not two_point_active.get(); two_point_active.set(v)
            two_point_btn.config(text="两点测量 ● [右键选2点]" if v else "两点测量 ○")
            result_var.set("已开启 — 右键选择两个点" if v else "")
        two_point_btn.config(command=_toggle_two_point)
        ttk.Label(btn_row, textvariable=result_var, foreground="#2980b9",
                  font=("Consolas", 9)).pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)

        ch_lf = ttk.LabelFrame(bottom, text="  速度通道选择  ", padding=(4, 2))
        ch_lf.pack(fill=tk.X)
        ch_cvs = tk.Canvas(ch_lf, height=72, bg=bg, highlightthickness=0)
        ch_cvs.pack(side=tk.TOP, fill=tk.X)
        hscr = ttk.Scrollbar(ch_lf, orient=tk.HORIZONTAL, command=ch_cvs.xview)
        hscr.pack(side=tk.BOTTOM, fill=tk.X)
        ch_cvs.configure(xscrollcommand=hscr.set)
        inner = tk.Frame(ch_cvs, bg=bg)
        ch_cvs.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: ch_cvs.configure(scrollregion=ch_cvs.bbox("all")))

        for i, ch in enumerate(vel_chs):
            nm    = ch["name"]
            color = AXIS_COLORS[i % len(AXIS_COLORS)]
            v     = tk.BooleanVar(value=True)
            self._vel_vars[nm] = v
            col = i
            tk.Label(inner, text=f"—{nm}—", fg=color, bg=bg,
                     font=("", 10, "bold")).grid(row=0, column=col, padx=12, pady=(4, 1))
            tk.Checkbutton(inner, text="显示", variable=v, command=_redraw,
                           fg=color, bg=bg, selectcolor=bg,
                           activebackground=bg, activeforeground=color,
                           font=("", 9)).grid(row=1, column=col, padx=12, pady=2, sticky="w")

        chart_frm = ttk.Frame(frm)
        chart_frm.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        fig = plt.Figure(figsize=(13, 4.8), dpi=100)
        ax  = fig.add_subplot(111)
        canvas = FigureCanvasTkAgg(fig, master=chart_frm)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        nav_frm = ttk.Frame(chart_frm)
        nav_frm.pack(fill=tk.X)
        NavigationToolbar2Tk(canvas, nav_frm)
        two_point_info = {"active": two_point_active, "result_var": result_var, "mode": "velocity"}
        add_interactions(canvas, plot_style_var=self._plot_style, two_point_mode=two_point_info)
        self._figs[key]    = fig
        self._canvases[key] = canvas
        self._vel_state = {"ax": ax, "canvas": canvas, "vel_chs": vel_chs}

    def _redraw_vel(self, ax, canvas):
        ax.clear()
        if not self._series or not self._vel_state or not self._vel_vars:
            ax.text(0.5, 0.5, "请先加载数据文件",
                    ha="center", va="center", transform=ax.transAxes,
                    fontsize=14, color="#aaa")
            canvas.draw_idle(); return
        series   = self._series
        vel_chs  = self._vel_state.get("vel_chs", [])
        style    = self._plot_style.get()
        ts_tx    = series.get("ts_tx", [])
        plotted  = False
        for i, ch in enumerate(vel_chs):
            nm = ch["name"]
            v  = self._vel_vars.get(nm)
            if not v or not v.get(): continue
            vals = series.get(nm, [])
            if not ts_tx or not vals: continue
            color = AXIS_COLORS[i % len(AXIS_COLORS)]
            m = min(len(ts_tx), len(vals))
            if style == "scatter":
                # 散点图：显示全部原始点
                ax.scatter(ts_tx[:m], vals[:m], color=color, s=8,
                           label=nm, rasterized=True, linewidths=0, alpha=0.8)
            else:
                # 曲线图：全量数据连线
                ax.plot(ts_tx[:m], vals[:m], color=color, lw=1.0,
                        label=nm, rasterized=True, alpha=0.9)
            plotted = True
        if not plotted:
            ax.text(0.5, 0.5, "请在下方勾选要显示的速度通道",
                    ha="center", va="center", transform=ax.transAxes,
                    fontsize=13, color="#aaa")
        else:
            ax.legend(fontsize=9, loc="upper right")
        ax.set_title("速度波形  （各轴速度用独立颜色显示）", fontsize=11)
        ax.set_xlabel("时间 (s)", fontsize=10)
        ax.set_ylabel("速度", fontsize=10)
        _fmt_ax(ax); ax.figure.tight_layout(); canvas.draw_idle()

    # ── 通信质量专用标签页 ──
    def _add_comm_tab(self):
        key="comm"
        frm=ttk.Frame(self._nb); self._nb.add(frm, text="  通信质量  ")

        # 图表区（大图，占主要空间）
        fig=plt.Figure(figsize=(13,5.5), dpi=100)
        ax=fig.add_subplot(111)
        canvas=FigureCanvasTkAgg(fig, master=frm)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # 勾选框控件行
        ctrl=ttk.Frame(frm); ctrl.pack(fill=tk.X, padx=8, pady=(2,0))
        v_tx=tk.BooleanVar(value=True)
        v_rx=tk.BooleanVar(value=True)
        v_rt=tk.BooleanVar(value=True)

        def _redraw():
            if not self._jitter: return
            draw_comm_chart(ax, self._jitter, v_tx.get(), v_rx.get(), v_rt.get())
            canvas.draw_idle()

        # 彩色勾选框（使用原生 tk.Checkbutton 以支持 fg 颜色）
        tk.Checkbutton(ctrl, text="■ 主站发送间隔",
                       variable=v_tx, command=_redraw,
                       fg=C_TARGET, activeforeground=C_TARGET,
                       selectcolor=self.cget("bg"),
                       font=("",10,"bold")).pack(side=tk.LEFT, padx=10)
        tk.Checkbutton(ctrl, text="■ 主站接收间隔",
                       variable=v_rx, command=_redraw,
                       fg=C_ACTUAL, activeforeground=C_ACTUAL,
                       selectcolor=self.cget("bg"),
                       font=("",10,"bold")).pack(side=tk.LEFT, padx=10)
        tk.Checkbutton(ctrl, text="■ 从站回环时延",
                       variable=v_rt, command=_redraw,
                       fg=C_RT, activeforeground=C_RT,
                       selectcolor=self.cget("bg"),
                       font=("",10,"bold")).pack(side=tk.LEFT, padx=10)

        stats_var=tk.StringVar(value=""); ttk.Label(ctrl, textvariable=stats_var,
            font=("Consolas",8), foreground="#555").pack(side=tk.LEFT, padx=12)

        # 丢帧事件面板
        lost_lf=ttk.LabelFrame(frm, text="  丢帧事件  ", padding=(4,2))
        lost_lf.pack(fill=tk.X, padx=6, pady=(2,2))

        lost_cvs=tk.Canvas(lost_lf, height=54, bg="#f8f9fa", highlightthickness=0)
        lost_cvs.pack(side=tk.TOP, fill=tk.X)
        hscroll=ttk.Scrollbar(lost_lf, orient=tk.HORIZONTAL, command=lost_cvs.xview)
        hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        lost_cvs.configure(xscrollcommand=hscroll.set)
        lost_inner=ttk.Frame(lost_cvs)
        lost_cvs.create_window((0,0), window=lost_inner, anchor="nw")
        lost_inner.bind("<Configure>",
            lambda e: lost_cvs.configure(scrollregion=lost_cvs.bbox("all")))

        # 占位文字（数据加载后替换）
        ttk.Label(lost_inner, text="（加载数据后显示）",
                  foreground="#aaa").pack(side=tk.LEFT, padx=8, pady=8)

        # Toolbar
        nav_frm=ttk.Frame(frm); nav_frm.pack(fill=tk.X)
        NavigationToolbar2Tk(canvas, nav_frm)
        add_interactions(canvas)

        self._figs[key]=fig; self._canvases[key]=canvas
        self._comm_state={
            "v_tx":v_tx,"v_rx":v_rx,"v_rt":v_rt,
            "redraw":_redraw,"stats_var":stats_var,
            "lost_inner":lost_inner,"lost_cvs":lost_cvs,
            "ax":ax,"canvas":canvas,"key":key,
        }

    def _update_comm_display(self):
        """数据加载后刷新通信质量统计文字和丢帧事件列表。"""
        if not self._comm_state or not self._jitter: return
        state=self._comm_state; jitter=self._jitter

        # 统计摘要文字
        parts=[]
        for src,name in [("ts_rx","发送"),("ts_tx","接收")]:
            d=jitter.get(src)
            if d: parts.append(
                f"{name}: 标称={d['nominal_us']:.2f}µs  σ={d['std_us']:.3f}µs  "
                f"丢帧={'⚠'+str(d['n_lost_total']) if d['n_lost_total'] else '✓0'}")
        d_rt=jitter.get("roundtrip")
        if d_rt: parts.append(f"回环: 均值={d_rt['mean_us']:.2f}µs  最大={d_rt['max_us']:.2f}µs")
        state["stats_var"].set("    ".join(parts))

        # 丢帧事件列表
        inner=state["lost_inner"]
        for w in inner.winfo_children(): w.destroy()

        all_lost=[]
        for src_key,lbl in [("ts_rx","TX"),("ts_tx","RX")]:
            d=jitter.get(src_key)
            if d:
                for ev in d["lost_events"]:
                    all_lost.append((ev["time_s"],lbl,ev["gap_us"],ev["n_lost"]))
        all_lost.sort(key=lambda x: x[0])

        if not all_lost:
            ttk.Label(inner, text="✓ 未检测到丢帧事件",
                      foreground="#27ae60", font=("",10)).pack(side=tk.LEFT, padx=8, pady=6)
            return

        nominal_s=0
        if "ts_rx" in jitter: nominal_s=jitter["ts_rx"]["nominal_us"]/1e6

        ttk.Label(inner, text=f"共 {len(all_lost)} 个:",
                  font=("",9,"bold"), foreground="#e74c3c").pack(side=tk.LEFT, padx=(6,8), pady=6)

        for t_ev, typ, gap_us, n_lost in all_lost:
            ev_frm=ttk.Frame(inner, relief="solid", borderwidth=1)
            ev_frm.pack(side=tk.LEFT, padx=3, pady=4)
            ttk.Label(ev_frm,
                text=f"t={t_ev:.4f}s  [{typ}]  {gap_us/1000:.2f}ms  ~{n_lost}帧",
                font=("Consolas",8), foreground="#c0392b").pack(side=tk.LEFT, padx=4)

            def _make_jump(t, nom_s):
                def _jump():
                    ax = state["ax"]; w = max(nom_s * 25, 0.25)
                    ax.set_xlim(t - w, t + w); state["canvas"].draw_idle()
                    for i, tab in enumerate(self._nb.tabs()):
                        if "通信质量" in self._nb.tab(tab, "text"):
                            self._nb.select(i); break
                return _jump

            ttk.Button(ev_frm, text="跳转▶", width=5,
                       command=_make_jump(t_ev, nominal_s)).pack(side=tk.LEFT, padx=2, pady=2)

    def _xcorr_delay(self, key, axis_name):
        if not self._series: messagebox.showinfo("提示","请先加载数据文件"); return
        fig=self._figs.get(key)
        if fig is None or not fig.axes: return
        t_start,t_end=fig.axes[0].get_xlim()
        series=self._series
        ts_tgt=series.get("ts_rx",[]); tgt=series.get(axis_name+"-target",[])
        ts_act=series.get("ts_tx",[]); act=series.get(axis_name+"-actual",[])
        if not tgt or not act: messagebox.showinfo("提示","无位置数据"); return
        lag_ms,corr=compute_xcorr_lag(ts_tgt,tgt,ts_act,act,t_start,t_end)
        if lag_ms is None:
            messagebox.showwarning("分析失败",f"区间 [{t_start:.3f}s ~ {t_end:.3f}s] 内数据点不足"); return
        sign="滞后" if lag_ms>=0 else "超前"
        messagebox.showinfo(f"{axis_name} 轴  区间延迟分析结果",
            f"分析区间:   {t_start:.3f} s  ~  {t_end:.3f} s\n"
            f"──────────────────────────────\n"
            f"跟随响应延迟:  {lag_ms:+.2f} ms\n"
            f"  → 实际位置{sign}目标位置  {abs(lag_ms):.2f} ms\n\n"
            f"互相关系数:   {corr:.4f}\n"
            f"  （越接近 1 表示波形相关性越好）\n\n"
            f"说明:\n  正值 = 实际位置滞后（常见）\n  负值 = 实际位置超前（需检查）")

    def _draw_all(self):
        """废弃旧的全量绘制；改为清空缓存后重绘当前可见标签页。"""
        self._drawn_tabs.clear()
        self._draw_active_tab()

    def _draw_active_tab(self):
        """仅渲染当前可见标签页（如未渲染过）。"""
        if not self._layout or not self._series: return
        tabs = self._nb.tabs()
        if not tabs: return
        try:
            idx = self._nb.index(self._nb.select())
        except tk.TclError:
            idx = 0
        if 0 <= idx < len(self._tab_order):
            key = self._tab_order[idx]
            if key not in self._drawn_tabs:
                self._draw_tab(key)
                self._drawn_tabs.add(key)

    def _on_tab_changed(self, event):
        """切换标签页时按需渲染。"""
        self.after(10, self._draw_active_tab)

    def _draw_tab(self, key):
        """渲染指定标签页的图表。"""
        if not self._layout or not self._series: return
        style = self._plot_style.get()
        if key == "overview":
            plot_overview(self._figs["overview"], self._layout, self._series, style)
            self._canvases["overview"].draw_idle()
        elif key == "compare" and self._compare_state:
            self._redraw_compare(self._compare_state["ax"], self._compare_state["canvas"])
        elif key == "velocity" and self._vel_state:
            self._redraw_vel(self._vel_state["ax"], self._vel_state["canvas"])
        elif key == "comm" and self._comm_state:
            ax = self._comm_state["ax"]
            draw_comm_chart(ax, self._jitter,
                            self._comm_state["v_tx"].get(),
                            self._comm_state["v_rx"].get(),
                            self._comm_state["v_rt"].get())
            self._canvases["comm"].draw_idle()
        elif key == "inspector":
            self._load_and_populate_inspector()
        elif key == "frame_analysis":
            self._load_and_populate_frames()

    def _reset_view(self, event=None):
        """重置当前图表视图到全量数据范围（Home / R 键）。"""
        if not self._layout or not self._series: return
        tabs = self._nb.tabs()
        if not tabs: return
        try:
            idx = self._nb.index(self._nb.select())
        except tk.TclError:
            return
        if 0 <= idx < len(self._tab_order):
            key = self._tab_order[idx]
            fig = self._figs.get(key)
            if fig:
                for ax in fig.axes:
                    ax.autoscale()
                self._canvases[key].draw_idle()

    def _kb_zoom(self, factor):
        """键盘缩放当前图表（+ / - 键）。"""
        if not self._layout or not self._series: return
        tabs = self._nb.tabs()
        if not tabs: return
        try:
            idx = self._nb.index(self._nb.select())
        except tk.TclError:
            return
        if 0 <= idx < len(self._tab_order):
            key = self._tab_order[idx]
            fig = self._figs.get(key)
            if fig:
                for ax in fig.axes:
                    x0, x1 = ax.get_xlim(); y0, y1 = ax.get_ylim()
                    xm = (x0 + x1) / 2; ym = (y0 + y1) / 2
                    ax.set_xlim(xm - (xm - x0) * factor, xm + (x1 - xm) * factor)
                    ax.set_ylim(ym - (ym - y0) * factor, ym + (y1 - ym) * factor)
                self._canvases[key].draw_idle()

    # ══════════════════════════════════════════════════════════
    # EtherCAT 数据帧分析（类 Wireshark 帧列表+详情+十六进制）
    # ══════════════════════════════════════════════════════════
    def _add_frame_analysis_tab(self):
        """添加 EtherCAT 数据帧分析标签页（三栏：帧列表 / 帧详情 / 十六进制）。"""
        frm = ttk.Frame(self._nb)
        self._nb.add(frm, text="  EtherCAT数据帧  ")
        fa = {}
        self._frame_analysis_state = fa

        # ── 可调整大小的三栏布局 (PanedWindow) ────────────────
        vpane = ttk.PanedWindow(frm, orient=tk.VERTICAL)
        vpane.pack(fill=tk.BOTH, expand=True, padx=6, pady=(4,4))

        # ── 上部：帧列表（可上下拖拽分割线调整高度）─────────
        top_lf = ttk.LabelFrame(
            vpane, padding=(4,2),
            text="  EtherCAT 数据帧列表  "
                 "[Input = 主站发送 (Master→Slave)  ·  Output = 主站接收 (Slave→Master)]")
        vpane.add(top_lf, weight=1)

        # 跳转控件
        jump_frm = ttk.Frame(top_lf)
        jump_frm.pack(side=tk.TOP, fill=tk.X, pady=(0,4))
        ttk.Label(jump_frm, text="跳转到时间:").pack(side=tk.LEFT, padx=(0,4))
        jump_entry = ttk.Entry(jump_frm, width=12)
        jump_entry.pack(side=tk.LEFT, padx=(0,4))
        ttk.Label(jump_frm, text="秒").pack(side=tk.LEFT, padx=(0,8))
        jump_btn = ttk.Button(jump_frm, text="跳转", width=8)
        jump_btn.pack(side=tk.LEFT)
        fa["jump_entry"] = jump_entry
        fa["jump_btn"] = jump_btn

        cols = ("no","time","src","dst","len","dir","info")
        tree = ttk.Treeview(top_lf, columns=cols, show="headings",
                            height=13, selectmode="browse")
        tree.heading("no",   text="#",         anchor=tk.CENTER)
        tree.heading("time", text="时间 (s)",  anchor=tk.CENTER)
        tree.heading("src",  text="源 MAC",    anchor=tk.CENTER)
        tree.heading("dst",  text="目标 MAC",  anchor=tk.CENTER)
        tree.heading("len",  text="长度(B)",   anchor=tk.CENTER)
        tree.heading("dir",  text="方向",      anchor=tk.CENTER)
        tree.heading("info", text="信息",      anchor=tk.W)
        tree.column("no",   width=55,  anchor=tk.CENTER, stretch=False)
        tree.column("time", width=95,  anchor=tk.CENTER, stretch=False)
        tree.column("src",  width=130, anchor=tk.CENTER, stretch=False)
        tree.column("dst",  width=110, anchor=tk.CENTER, stretch=False)
        tree.column("len",  width=60,  anchor=tk.CENTER, stretch=False)
        tree.column("dir",  width=65,  anchor=tk.CENTER, stretch=False)
        tree.column("info", width=600, stretch=True)
        tree.tag_configure("input",  background="#eaf4fb", foreground="#1a5276")
        tree.tag_configure("output", background="#fef9e7", foreground="#6e2f0b")
        tree.tag_configure("highlight", background="#f9e400", foreground="#000000")
        tree.tag_configure("other",  background="#f5f5f5", foreground="#555")
        vsb = ttk.Scrollbar(top_lf, orient=tk.VERTICAL,   command=tree.yview)
        hsb = ttk.Scrollbar(top_lf, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        fa["tree"] = tree
        fa["frames"] = []

        # ── 下部：帧详情（左）+ 十六进制（右）——可水平拖拽调整宽度
        hpane = ttk.PanedWindow(vpane, orient=tk.HORIZONTAL)
        vpane.add(hpane, weight=1)

        # 左：帧详情 — 可展开/折叠树（类 Wireshark）
        det_lf = ttk.LabelFrame(hpane, text="  帧结构详情  （点击节点以高亮对应字节）", padding=(4,2))
        hpane.add(det_lf, weight=1)
        det_tree = ttk.Treeview(det_lf, show="tree", height=14, selectmode="browse")
        det_tree.column("#0", width=430, stretch=True)
        det_tree.tag_configure("sec",   foreground="#6c3483")
        det_tree.tag_configure("key",   foreground="#2471a3")
        det_tree.tag_configure("val",   foreground="#1b2631")
        det_tree.tag_configure("arrow", foreground="#cb4335")
        det_tree.tag_configure("dim",   foreground="#5d6d7e")
        det_vsb = ttk.Scrollbar(det_lf, orient=tk.VERTICAL,   command=det_tree.yview)
        det_tree.configure(yscrollcommand=det_vsb.set)
        det_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        det_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        fa["det_tree"] = det_tree
        fa["node_ranges"] = {}

        # 右：十六进制
        hex_lf = ttk.LabelFrame(hpane, text="  十六进制载荷", padding=(4,2))
        hpane.add(hex_lf, weight=1)
        hex_txt = tk.Text(hex_lf, font=("Courier New",9), state=tk.DISABLED,
                          bg="#1e1e1e", fg="#d4d4d4", height=14, wrap=tk.NONE,
                          takefocus=False,
                          selectbackground="#1e1e1e",
                          inactiveselectbackground="#1e1e1e")
        hex_vsb = ttk.Scrollbar(hex_lf, orient=tk.VERTICAL,   command=hex_txt.yview)
        hex_hsb = ttk.Scrollbar(hex_lf, orient=tk.HORIZONTAL, command=hex_txt.xview)
        hex_txt.configure(yscrollcommand=hex_vsb.set, xscrollcommand=hex_hsb.set)
        hex_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        hex_txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hex_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hex_txt.tag_configure("hdr",    foreground="#9cdcfe", font=("Courier New",9,"bold"))
        hex_txt.tag_configure("sep",    foreground="#3a3a3a")
        hex_txt.tag_configure("off",    foreground="#858585")
        hex_txt.tag_configure("g0",     foreground="#ce9178")
        hex_txt.tag_configure("g1",     foreground="#dcdcaa")
        hex_txt.tag_configure("asc",    foreground="#b5cea8")
        hex_txt.tag_configure("sel_hi", background="#264f78", foreground="#ffffff")
        hex_txt.tag_raise("sel_hi")
        fa["hex_txt"] = hex_txt

        # ── 渲染函数 ─────────────────────────────────────────
        def _node_id(counter=[0]):
            counter[0] += 1
            return f"dn{counter[0]}"

        def _render_details(fd):
            dt = det_tree
            for item in dt.get_children(): dt.delete(item)
            nr = {}; fa["node_ranges"] = nr
            # Reset iid counter
            _node_id.__defaults__ = ([0],)
            ecs = fd.get("ec_start", 14)
            bits = fd["frame_len"] * 8

            # Frame summary
            fid = _node_id()
            dt.insert("", tk.END, iid=fid, open=True, tags=("sec",),
                      text=f"Frame {fd['frame_no']}: {fd['frame_len']} bytes on wire ({bits} bits)")
            nr[fid] = (0, fd["frame_len"] - 1)

            # Ethernet II
            bc = fd["dst"] == "ff:ff:ff:ff:ff:ff"
            dst_s = f"Broadcast ({fd['dst']})" if bc else fd["dst"]
            eid = _node_id()
            dt.insert(fid, tk.END, iid=eid, open=True, tags=("sec",),
                      text=f"Ethernet II,  Src: {fd['src']},  Dst: {dst_s}")
            nr[eid] = (0, ecs - 1)
            n = _node_id(); dt.insert(eid, tk.END, iid=n, tags=("dim",), text=f"  Destination: {fd['dst']}"); nr[n] = (0, 5)
            n = _node_id(); dt.insert(eid, tk.END, iid=n, tags=("dim",), text=f"  Source: {fd['src']}"); nr[n] = (6, 11)
            n = _node_id(); dt.insert(eid, tk.END, iid=n, tags=("dim",), text="  Type: EtherCAT (0x88A4)"); nr[n] = (12, 13)

            # EtherCAT Header
            ec_type_s = {1:"PDO",2:"Network Variables",3:"Mailbox"}.get(fd["ec_type"], f"0x{fd['ec_type']:X}")
            hid = _node_id()
            dt.insert(fid, tk.END, iid=hid, open=True, tags=("sec",),
                      text=f"EtherCAT Header  [Length={fd['ec_len']}  Type={ec_type_s}]")
            nr[hid] = (ecs, ecs + 1)
            n = _node_id(); dt.insert(hid, tk.END, iid=n, tags=("dim",), text=f"  Length: {fd['ec_len']}"); nr[n] = (ecs, ecs + 1)
            n = _node_id(); dt.insert(hid, tk.END, iid=n, tags=("dim",), text=f"  Type: {ec_type_s} (0x{fd['ec_type']:02x})"); nr[n] = (ecs, ecs + 1)

            # Datagrams
            dg_base = ecs + 2
            for i, dg in enumerate(fd["datagrams"]):
                cn   = _CMD_NAMES.get(dg["cmd"], f"CMD{dg['cmd']:02x}")
                wkc  = dg["wkc"]
                dlen = dg["dlen"]
                dg_end = dg_base + 10 + dlen + 1  # inclusive

                if dg["cmd"] == CMD_LRW:
                    dir_s = "REQ (Master→Slave)" if wkc == 0 else f"RSP (Slave→Master, WKC={wkc})"
                    dg_hdr = f"Datagram[{i+1}]: {cn}  addr=0x{dg['addr']:08X}  len={dlen}  {dir_s}"
                else:
                    dg_hdr = f"Datagram[{i+1}]: {cn}  addr=0x{dg['addr']:08X}  len={dlen}  wkc={wkc}"
                dgid = _node_id()
                dt.insert(fid, tk.END, iid=dgid, open=True, tags=("key",), text=dg_hdr)
                nr[dgid] = (dg_base, dg_end)

                # Fixed header fields
                n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("dim",), text=f"  Command:         0x{dg['cmd']:02x} ({cn})"); nr[n] = (dg_base, dg_base)
                n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("dim",), text=f"  Index:           0x{dg['idx']:02x}"); nr[n] = (dg_base + 1, dg_base + 1)
                n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("dim",), text=f"  Logical Address: 0x{dg['addr']:08X}"); nr[n] = (dg_base + 2, dg_base + 5)
                n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("dim",), text=f"  Length/Flags:    {dlen}"); nr[n] = (dg_base + 6, dg_base + 7)
                n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("dim",), text=f"  IRQ:             0x{dg['irq']:04x}"); nr[n] = (dg_base + 8, dg_base + 9)

                # Data payload
                data_abs = dg_base + 10
                data_end = data_abs + dlen - 1

                if dg["cmd"] == CMD_LRW:
                    if wkc == 0:
                        n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("arrow",), text="  ► 方向: Master → Slave  (Input / 指令帧)"); nr[n] = None
                        if self._layout:
                            rxid = _node_id()
                            dt.insert(dgid, tk.END, iid=rxid, open=True, tags=("key",),
                                      text=f"  RxPdo  [偏移 {data_abs}~{data_end}]")
                            nr[rxid] = (data_abs, data_end)
                            for ax in self._layout["axes"]:
                                o = ax["target_off"]
                                if o + 4 <= len(dg["data"]):
                                    v = struct.unpack_from("<i", dg["data"], o)[0]
                                    n = _node_id()
                                    dt.insert(rxid, tk.END, iid=n, tags=("val",),
                                              text=f"    {ax['name']}-target = {v:,}  [+{o}..+{o+3}]")
                                    nr[n] = (data_abs + o, data_abs + o + 3)
                        else:
                            n = _node_id()
                            dt.insert(dgid, tk.END, iid=n, tags=("dim",),
                                      text=f"  Data: [{dlen} bytes]  [偏移 {data_abs}~{data_end}]")
                            nr[n] = (data_abs, data_end)
                    else:
                        n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("arrow",), text=f"  ► 方向: Slave → Master  (Output / 响应帧, WKC={wkc})"); nr[n] = None
                        if self._layout:
                            txid = _node_id()
                            dt.insert(dgid, tk.END, iid=txid, open=True, tags=("key",),
                                      text=f"  TxPdo  [偏移 {data_abs}~{data_end}]")
                            nr[txid] = (data_abs, data_end)
                            for ax in self._layout["axes"]:
                                o = ax["actual_off"]
                                if o + 4 <= len(dg["data"]):
                                    v = struct.unpack_from("<i", dg["data"], o)[0]
                                    n = _node_id()
                                    dt.insert(txid, tk.END, iid=n, tags=("val",),
                                              text=f"    {ax['name']}-actual = {v:,}  [+{o}..+{o+3}]")
                                    nr[n] = (data_abs + o, data_abs + o + 3)
                            for ch in self._layout.get("vel_torq", []):
                                o = ch["offset"]
                                if o + 4 <= len(dg["data"]):
                                    v = struct.unpack_from("<i", dg["data"], o)[0]
                                    n = _node_id()
                                    dt.insert(txid, tk.END, iid=n, tags=("val",),
                                              text=f"    {ch['name']} = {v:,}  [+{o}..+{o+3}]")
                                    nr[n] = (data_abs + o, data_abs + o + 3)
                        else:
                            n = _node_id()
                            dt.insert(dgid, tk.END, iid=n, tags=("dim",),
                                      text=f"  Data: [{dlen} bytes]  [偏移 {data_abs}~{data_end}]")
                            nr[n] = (data_abs, data_end)
                else:
                    n = _node_id()
                    dt.insert(dgid, tk.END, iid=n, tags=("dim",),
                              text=f"  Data: [{dlen} bytes]  [偏移 {data_abs}~{data_end}]")
                    nr[n] = (data_abs, data_end)

                # WKC
                wkc_abs = data_abs + dlen
                n = _node_id(); dt.insert(dgid, tk.END, iid=n, tags=("dim",), text=f"  Working Counter: {wkc}  [偏移 {wkc_abs}~{wkc_abs+1}]"); nr[n] = (wkc_abs, wkc_abs + 1)

                dg_base += 10 + dlen + 2

        def _render_hex(raw):
            ht = hex_txt
            ht.config(state=tk.NORMAL); ht.delete("1.0", tk.END)
            hdr = ("  偏移  │  "
                   "+0  +1  +2  +3   +4  +5  +6  +7   "
                   "+8  +9  +A  +B   +C  +D  +E  +F  │  0123456789ABCDEF\n")
            ht.insert(tk.END, hdr, "hdr")
            ht.insert(tk.END, "─"*(len(hdr)-1)+"\n", "sep")
            for row_s in range(0, len(raw), 16):
                chunk = raw[row_s:row_s+16]
                ht.insert(tk.END, f"  {row_s:04X}  │  ", "off")
                for i, b in enumerate(chunk):
                    off = row_s + i
                    gtag = "g0" if (i//4)%2==0 else "g1"
                    btag = f"b_{off}"
                    ht.insert(tk.END, f"{b:02x}", (gtag, btag))
                    ht.insert(tk.END, " ", gtag)
                    if i in (3,7,11) and i < len(chunk)-1:
                        ht.insert(tk.END, " ", "sep")
                if len(chunk) < 16:
                    miss = 16 - len(chunk)
                    ht.insert(tk.END, "   "*miss + "  "*(miss//4), "sep")
                ht.insert(tk.END, "│  ", "sep")
                for i, b in enumerate(chunk):
                    off = row_s + i
                    ht.insert(tk.END, chr(b) if 32<=b<127 else ".", (f"b_{off}", "asc"))
                ht.insert(tk.END, "\n")
            ht.config(state=tk.DISABLED)
            fa["cur_raw"] = raw

        def _highlight_range(start, end):
            if start is None or end is None or start < 0 or end < start:
                return
            ht = hex_txt
            raw = fa.get("cur_raw", b"")
            ht.config(state=tk.NORMAL)
            ht.tag_remove("sel_hi", "1.0", tk.END)
            for off in range(start, min(end + 1, len(raw))):
                btag = f"b_{off}"
                ranges = ht.tag_ranges(btag)
                for j in range(0, len(ranges), 2):
                    ht.tag_add("sel_hi", ranges[j], ranges[j+1])
            ht.config(state=tk.DISABLED)
            # Scroll to first highlighted byte
            if start < len(raw):
                btag = f"b_{start}"
                r = ht.tag_ranges(btag)
                if r: ht.see(r[0])

        fa["render_details"]  = _render_details
        fa["render_hex"]      = _render_hex
        fa["highlight_range"] = _highlight_range

        def _on_det_select(event):
            sel = det_tree.selection()
            if not sel: return
            rng = fa.get("node_ranges", {}).get(sel[0])
            if rng:
                _highlight_range(rng[0], rng[1])
            else:
                # Node with no range: just clear highlight
                hex_txt.config(state=tk.NORMAL)
                hex_txt.tag_remove("sel_hi", "1.0", tk.END)
                hex_txt.config(state=tk.DISABLED)

        det_tree.bind("<<TreeviewSelect>>", _on_det_select)

        def _on_select(event):
            sel = tree.selection()
            if not sel: return
            try:  idx = int(sel[0])
            except ValueError: return
            frames = fa.get("frames", [])
            if not (0 <= idx < len(frames)): return
            fd = frames[idx]
            _render_hex(fd["raw"])
            _render_details(fd)

        tree.bind("<<TreeviewSelect>>", _on_select)

        def _on_jump():
            try:
                target_time = float(jump_entry.get())
            except ValueError:
                messagebox.showerror("错误", "请输入有效的时间（秒）")
                return
            frames = fa.get("frames", [])
            if not frames: return
            # 二分查找最接近的帧
            left, right = 0, len(frames) - 1
            closest_idx = 0
            while left <= right:
                mid = (left + right) // 2
                if frames[mid]["ts"] < target_time:
                    left = mid + 1
                    closest_idx = mid
                else:
                    right = mid - 1
                    if abs(frames[mid]["ts"] - target_time) < abs(frames[closest_idx]["ts"] - target_time):
                        closest_idx = mid
            tree.selection_set(str(closest_idx))
            tree.see(str(closest_idx))
            tree.event_generate("<<TreeviewSelect>>")

        jump_btn.config(command=_on_jump)
        jump_entry.bind("<Return>", lambda e: _on_jump())

    def _load_and_populate_frames(self):
        """后台加载全部 EtherCAT 帧并填充数据帧分析列表（懒加载时调用）。"""
        if not hasattr(self, "_path") or not self._path: return
        fa = self._frame_analysis_state
        tree = fa.get("tree")
        if tree is None: return
        for item in tree.get_children(): tree.delete(item)
        fa["frames"] = []

        # 非模态进度窗口
        prog_win = tk.Toplevel(self)
        prog_win.title("加载数据帧")
        prog_win.geometry("400x80")
        prog_win.transient(self)
        # 不使用grab_set()，允许用户继续操作
        prog_label = ttk.Label(prog_win, text="正在后台加载EtherCAT数据帧...")
        prog_label.pack(pady=10)
        prog_bar = ttk.Progressbar(prog_win, mode='indeterminate')
        prog_bar.pack(fill=tk.X, padx=20, pady=10)
        prog_bar.start(10)

        def _bg():
            frames, t0, count = [], None, 0
            try:
                layout = self._layout
                for ts, frame in iter_packets(self._path):
                    fd = parse_ecat_frame(ts, frame, count+1, layout)
                    if fd is None: continue
                    if t0 is None: t0 = ts
                    fd["ts"] = ts - t0
                    frames.append(fd); count += 1
                    if count % 5000 == 0:
                        self.after(0, lambda c=count: prog_label.config(text=f"已加载 {c} 帧..."))
            except Exception:
                pass
            self.after(0, lambda: _fill(frames, prog_win))

        def _fill(frames, pw):
            st = self._frame_analysis_state
            tree2 = st.get("tree")
            if tree2 is None:
                pw.destroy()
                return
            st["frames"] = frames
            for item in tree2.get_children(): tree2.delete(item)
            batch_size = 5000
            for batch_start in range(0, len(frames), batch_size):
                batch_end = min(batch_start + batch_size, len(frames))
                for i in range(batch_start, batch_end):
                    fd = frames[i]
                    d = fd["direction"]
                    tag = "input" if d == "Input" else ("output" if d == "Output" else "other")
                    dst_s = "Broadcast" if fd["dst"]=="ff:ff:ff:ff:ff:ff" else fd["dst"]
                    tree2.insert("", tk.END, iid=str(i),
                                 values=(fd["frame_no"], f"{fd['ts']:.6f}",
                                         fd["src"], dst_s,
                                         fd["frame_len"], d, fd["info"]),
                                 tags=(tag,))
                if batch_end < len(frames):
                    tree2.update_idletasks()
            pw.destroy()
            if frames:
                tree2.selection_set("0"); tree2.see("0")
                tree2.event_generate("<<TreeviewSelect>>")

        threading.Thread(target=_bg, daemon=True).start()

    def jump_to_frame_by_time(self, target_ts):
        """切换到数据帧分析页，并高亮距 target_ts 最近的帧。"""
        # 先切换到数据帧分析标签页
        for tid in self._nb.tabs():
            if "EtherCAT数据帧" in self._nb.tab(tid, "text"):
                self._nb.select(tid); break
        fa = self._frame_analysis_state
        frames = fa.get("frames", [])
        tree   = fa.get("tree")
        if tree is None: return
        # 若尚未加载，先触发加载（异步），本次跳转忽略
        if not frames:
            self._load_and_populate_frames(); return
        # 找最近帧
        best = min(range(len(frames)),
                   key=lambda i: abs(frames[i]["ts"] - target_ts))
        iid = str(best)
        # 清除旧高亮
        for item in tree.get_children():
            tags = list(tree.item(item, "tags"))
            if "highlight" in tags:
                tags.remove("highlight")
                tree.item(item, tags=tuple(tags))
        # 高亮并跳转
        tags = list(tree.item(iid, "tags")) + ["highlight"]
        tree.item(iid, tags=tuple(tags))
        tree.selection_set(iid); tree.see(iid)
        tree.event_generate("<<TreeviewSelect>>")

    # ══════════════════════════════════════════════════════════
    # PDO 帧检查器（类 Wireshark 十六进制视图 + 字段定义 + XML生成）
    # ══════════════════════════════════════════════════════════
    def _add_pdo_inspector_tab(self):
        """添加 PDO 帧检查器标签页。"""
        frm = ttk.Frame(self._nb)
        self._nb.add(frm, text="  PDO帧分析  ")
        self._figs["inspector"]     = None
        self._canvases["inspector"] = None

        # ── 内部状态 ─────────────────────────────────────────
        _raw_frames = []   # [(ts_rel, wkc, payload_bytes), ...]
        _fields     = []   # [{"axis","dtype","pdo","offset","bytelen"}, ...]
        _state = {
            "frames":      _raw_frames,
            "fields":      _fields,
            "sel_payload": b"",
            "sel_wkc":     0,
            "sel_offset":  None,
            "sel_len":     4,
            "drag_start":  None,
            "tree":        None,
            "f_tree":      None,
            "hex_txt":     None,
        }
        self._insp_state = _state

        # ── 上部：帧列表 ──────────────────────────────────────
        top_lf = ttk.LabelFrame(frm,
            text="  EtherCAT 帧列表（前500帧）  [点击行查看十六进制载荷]",
            padding=(4, 2))
        top_lf.pack(fill=tk.X, padx=6, pady=(4, 2))

        cols = ("no", "time", "dir", "wkc", "len", "preview")
        tree = ttk.Treeview(top_lf, columns=cols, show="headings",
                            height=7, selectmode="browse")
        tree.heading("no",      text="#",                      anchor=tk.CENTER)
        tree.heading("time",    text="时间 (s)",                anchor=tk.CENTER)
        tree.heading("dir",     text="方向",                   anchor=tk.CENTER)
        tree.heading("wkc",     text="WKC",                    anchor=tk.CENTER)
        tree.heading("len",     text="载荷(B)",                 anchor=tk.CENTER)
        tree.heading("preview", text="PDO载荷预览（前16字节）", anchor=tk.W)
        tree.column("no",      width=45,  anchor=tk.CENTER, stretch=False)
        tree.column("time",    width=95,  anchor=tk.CENTER, stretch=False)
        tree.column("dir",     width=100, anchor=tk.CENTER, stretch=False)
        tree.column("wkc",     width=55,  anchor=tk.CENTER, stretch=False)
        tree.column("len",     width=65,  anchor=tk.CENTER, stretch=False)
        tree.column("preview", width=420, stretch=True)
        vsb_t = ttk.Scrollbar(top_lf, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=vsb_t.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb_t.pack(side=tk.RIGHT, fill=tk.Y)
        _state["tree"] = tree

        # ── 中部：十六进制视图 ────────────────────────────────
        mid_lf = ttk.LabelFrame(frm,
            text="  PDO 载荷（十六进制）  [左键点击 / 拖拽 选任意字节 · Ctrl+左键单选1字节]",
            padding=(4, 2))
        mid_lf.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 2))

        hex_info_var = tk.StringVar(value="← 请在上方帧列表中点击选择一帧")
        ttk.Label(mid_lf, textvariable=hex_info_var,
                  foreground="#555", font=("Consolas", 9)).pack(anchor=tk.W)

        hex_frm = tk.Frame(mid_lf)
        hex_frm.pack(fill=tk.BOTH, expand=True)
        hex_txt = tk.Text(hex_frm, font=("Courier New", 10),
                          state=tk.DISABLED, bg="#1e1e1e", fg="#d4d4d4",
                          cursor="arrow", wrap=tk.NONE, height=9,
                          takefocus=False,
                          selectbackground="#1e1e1e",
                          inactiveselectbackground="#1e1e1e")
        hex_vsb = ttk.Scrollbar(hex_frm, orient=tk.VERTICAL,   command=hex_txt.yview)
        hex_hsb = ttk.Scrollbar(mid_lf,  orient=tk.HORIZONTAL, command=hex_txt.xview)
        hex_txt.configure(yscrollcommand=hex_vsb.set, xscrollcommand=hex_hsb.set)
        hex_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        hex_txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hex_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        _state["hex_txt"] = hex_txt

        # 颜色主题（VS Code 暗色）
        hex_txt.tag_configure("header",   foreground="#9cdcfe",
                              font=("Courier New", 10, "bold"))
        hex_txt.tag_configure("sep_ln",   foreground="#3a3a3a")
        hex_txt.tag_configure("offset",   foreground="#858585")
        hex_txt.tag_configure("grp0",     foreground="#ce9178")  # 橙
        hex_txt.tag_configure("grp1",     foreground="#dcdcaa")  # 黄
        hex_txt.tag_configure("ascii_ch", foreground="#b5cea8")
        hex_txt.tag_configure("sel_hi",   background="#264f78", foreground="#ffffff")

        sel_info_var = tk.StringVar(value="")
        ttk.Label(mid_lf, textvariable=sel_info_var,
                  foreground="#2980b9", font=("Consolas", 9)).pack(anchor=tk.W)
        _state["hex_info_var"] = hex_info_var
        _state["sel_info_var"] = sel_info_var

        # ── 下部：字段定义 ────────────────────────────────────
        bot_lf = ttk.LabelFrame(frm, text="  PDO 字段定义（轴映射）", padding=(4, 2))
        bot_lf.pack(fill=tk.X, padx=6, pady=(0, 4))

        f_cols = ("axis", "dtype", "pdo", "offset", "bytelen", "value")
        f_tree = ttk.Treeview(bot_lf, columns=f_cols, show="headings",
                              height=5, selectmode="browse")
        f_tree.heading("axis",    text="轴名")
        f_tree.heading("dtype",   text="数据类型")
        f_tree.heading("pdo",     text="PDO方向")
        f_tree.heading("offset",  text="字节偏移")
        f_tree.heading("bytelen", text="字节数")
        f_tree.heading("value",   text="当前帧值（参考）")
        for c, w in [("axis",65),("dtype",95),("pdo",85),
                     ("offset",80),("bytelen",65),("value",120)]:
            f_tree.column(c, width=w, anchor=tk.CENTER, stretch=False)
        f_vsb = ttk.Scrollbar(bot_lf, orient=tk.VERTICAL, command=f_tree.yview)
        f_tree.configure(yscrollcommand=f_vsb.set)
        f_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        f_vsb.pack(side=tk.LEFT, fill=tk.Y)
        _state["f_tree"] = f_tree

        # 右侧控件列
        ctrl = ttk.Frame(bot_lf)
        ctrl.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 4))

        AXIS_OPTS  = ["X","Y","Z","B","C","轴1","轴2","轴3","轴4","轴5","轴6"]
        DTYPE_OPTS = ["目标位置","实际位置","速度","转矩","辅助1","辅助2","辅助3"]
        BLEN_OPTS  = ["4  (int32)", "2  (int16)", "1  (int8)"]

        axis_var  = tk.StringVar(value="X")
        dtype_var = tk.StringVar(value="目标位置")
        blen_var  = tk.StringVar(value="4  (int32)")

        r = 0
        ttk.Label(ctrl, text="轴名：").grid(row=r, column=0, sticky="e", pady=2)
        ttk.Combobox(ctrl, textvariable=axis_var, values=AXIS_OPTS,
                     width=7, state="normal").grid(row=r, column=1, padx=3, pady=2); r+=1
        ttk.Label(ctrl, text="数据类型：").grid(row=r, column=0, sticky="e", pady=2)
        ttk.Combobox(ctrl, textvariable=dtype_var, values=DTYPE_OPTS,
                     width=12, state="readonly").grid(row=r, column=1, padx=3, pady=2); r+=1
        ttk.Label(ctrl, text="字节长度：").grid(row=r, column=0, sticky="e", pady=2)
        ttk.Combobox(ctrl, textvariable=blen_var, values=BLEN_OPTS,
                     width=12, state="readonly").grid(row=r, column=1, padx=3, pady=2); r+=1

        pdo_hint_var = tk.StringVar(value="PDO方向自动识别")
        ttk.Label(ctrl, textvariable=pdo_hint_var,
                  foreground="#27ae60", font=("", 8)
                  ).grid(row=r, column=0, columnspan=2, pady=(0,4)); r+=1

        ttk.Button(ctrl, text="★ 添加字段",
                   command=lambda: _do_add()
                   ).grid(row=r, column=0, columnspan=2, pady=2, padx=2, sticky="ew"); r+=1
        ttk.Button(ctrl, text="✕ 删除选中",
                   command=lambda: _do_del()
                   ).grid(row=r, column=0, columnspan=2, pady=2, padx=2, sticky="ew"); r+=1
        ttk.Button(ctrl, text="清空全部",
                   command=lambda: _do_clear()
                   ).grid(row=r, column=0, columnspan=2, pady=2, padx=2, sticky="ew"); r+=1
        ttk.Separator(ctrl, orient=tk.HORIZONTAL
                      ).grid(row=r, column=0, columnspan=2, sticky="ew", pady=4); r+=1
        ttk.Button(ctrl, text="💾 生成 XML 并加载",
                   command=lambda: _do_gen_xml()
                   ).grid(row=r, column=0, columnspan=2, pady=4, padx=2, sticky="ew"); r+=1

        # ── 内部回调函数 ──────────────────────────────────────

        def _render_hex(payload):
            """将 payload bytes 渲染到 hex_txt（深色主题）。"""
            ht = hex_txt
            ht.config(state=tk.NORMAL)
            ht.delete("1.0", tk.END)
            hdr = ("  偏移  │  "
                   "+0  +1  +2  +3   +4  +5  +6  +7   "
                   "+8  +9  +A  +B   +C  +D  +E  +F  │  0123456789ABCDEF\n")
            ht.insert(tk.END, hdr, "header")
            ht.insert(tk.END, "─" * (len(hdr)-1) + "\n", "sep_ln")
            n = len(payload)
            for row_s in range(0, n, 16):
                chunk = payload[row_s: row_s+16]
                ht.insert(tk.END, f"  {row_s:04X}  │  ", "offset")
                for i, b in enumerate(chunk):
                    grp_tag = "grp0" if (i // 4) % 2 == 0 else "grp1"
                    byte_off = row_s + i
                    btag = f"b_{byte_off}"
                    ht.insert(tk.END, f"{b:02x}", (grp_tag, btag))
                    ht.insert(tk.END, " ",        (grp_tag, btag))
                    if i in (3, 7, 11) and i < len(chunk) - 1:
                        ht.insert(tk.END, "  ", "sep_ln")
                if len(chunk) < 16:
                    miss = 16 - len(chunk)
                    ht.insert(tk.END, "   " * miss + "  " * (miss // 4), "sep_ln")
                ht.insert(tk.END, "│  ", "sep_ln")
                for b in chunk:
                    ht.insert(tk.END, chr(b) if 32 <= b < 127 else ".", "ascii_ch")
                ht.insert(tk.END, "\n")
            ht.config(state=tk.DISABLED)
            # 恢复选中高亮
            if _state["sel_offset"] is not None:
                _highlight(_state["sel_offset"], _state["sel_len"])

        def _highlight(start, length):
            hex_txt.tag_remove("sel_hi", "1.0", tk.END)
            for i in range(start, start + length):
                ranges = hex_txt.tag_ranges(f"b_{i}")
                if ranges:
                    hex_txt.tag_add("sel_hi", ranges[0], ranges[1])

        def _byte_at(event):
            """返回鼠标处的字节偏移，不在字节上则返回 None。"""
            idx_str = hex_txt.index(f"@{event.x},{event.y}")
            tags    = hex_txt.tag_names(idx_str)
            btag    = next((t for t in tags if t.startswith("b_")), None)
            return int(btag[2:]) if btag else None

        def _update_sel(start, length):
            """刷新高亮和状态栏，保存选区到 _state。"""
            _state["sel_offset"] = start
            _state["sel_len"]    = length
            _highlight(start, length)
            payload = _state["sel_payload"]
            if payload and start + length <= len(payload):
                raw  = payload[start: start + length]
                rhex = " ".join(f"{b:02x}" for b in raw)
                if length == 4:
                    vi = struct.unpack_from("<i", raw)[0]
                    vu = struct.unpack_from("<I", raw)[0]
                    vstr = f"int32={vi:,}  hex=0x{vu:08X}"
                elif length == 2:
                    vi = struct.unpack_from("<h", raw)[0]
                    vu = struct.unpack_from("<H", raw)[0]
                    vstr = f"int16={vi}  hex=0x{vu:04X}"
                elif length == 1:
                    vstr = f"uint8={raw[0]}  hex=0x{raw[0]:02X}"
                else:
                    vstr = "hex=" + raw.hex().upper()
                sel_info_var.set(
                    f"已选  偏移: {start}~{start+length-1}  ({length}字节)"
                    f"  │  [{rhex}]  │  {vstr}"
                    f"  │  → 设置轴名/类型后点「添加字段」")
            else:
                sel_info_var.set(f"已选  偏移: {start}  长度: {length}")

        def _on_hex_press(event):
            raw_off = _byte_at(event)
            if raw_off is None: return
            _state["drag_start"] = raw_off
            if event.state & 0x4:          # Ctrl → 单字节
                _update_sel(raw_off, 1)
            else:                          # 普通点击 → 从该字节起按下拉框长度
                _update_sel(raw_off, int(blen_var.get().split()[0]))

        def _on_hex_drag(event):
            if _state["drag_start"] is None: return
            raw_off = _byte_at(event)
            if raw_off is None: return
            a, b    = _state["drag_start"], raw_off
            if b >= a:
                _update_sel(a, b - a + 1)
            else:
                _update_sel(b, a - b + 1)

        def _on_hex_release(event):
            _state["drag_start"] = None

        hex_txt.bind("<ButtonPress-1>",   _on_hex_press)
        hex_txt.bind("<B1-Motion>",       _on_hex_drag)
        hex_txt.bind("<ButtonRelease-1>", _on_hex_release)

        def _on_frame_select(event):
            sel = tree.selection()
            if not sel: return
            vals = tree.item(sel[0], "values")
            idx  = int(vals[0]) - 1
            if not (0 <= idx < len(_raw_frames)): return
            ts, wkc, payload = _raw_frames[idx]
            _state["sel_payload"] = payload
            _state["sel_wkc"]     = wkc
            _state["sel_offset"]  = None
            pdo_dir = ("RxPDO（目标位置，WKC=0）" if wkc == 0
                       else f"TxPDO（从站响应，WKC={wkc}）")
            hex_info_var.set(
                f"第 {idx+1} 帧  │  方向：{pdo_dir}"
                f"  │  载荷：{len(payload)} 字节  │  时间：{ts:.6f}s")
            pdo_hint_var.set(f"PDO方向自动识别：{'RxPDO' if wkc==0 else 'TxPDO'}")
            _render_hex(payload)
            sel_info_var.set("← 点击十六进制字节区域选中位置（默认对齐到4字节/int32）")

        tree.bind("<<TreeviewSelect>>", _on_frame_select)

        def _refresh_f_tree():
            payload = _state["sel_payload"]
            for item in f_tree.get_children(): f_tree.delete(item)
            for i, f in enumerate(_fields):
                val_str = ""
                off, bl = f["offset"], f["bytelen"]
                if payload and off + bl <= len(payload):
                    raw = payload[off: off + bl]
                    if   bl == 4: val_str = str(struct.unpack_from("<i", raw)[0])
                    elif bl == 2: val_str = str(struct.unpack_from("<h", raw)[0])
                    else:         val_str = str(raw[0])
                f_tree.insert("", tk.END, iid=str(i),
                              values=(f["axis"], f["dtype"], f["pdo"],
                                      f["offset"], f["bytelen"], val_str))

        def _do_add():
            if _state["sel_offset"] is None:
                messagebox.showinfo("提示", "请先在十六进制区域点击/拖拽选中字节位置"); return
            sel_len  = _state["sel_len"]
            axis     = axis_var.get().strip() or "X"
            dtype    = dtype_var.get()
            # 目标位置固定为 RxPDO；实际位置/速度/转矩固定为 TxPDO；其余按所选帧方向
            _DTYPE_PDO = {"目标位置": "RxPDO",
                          "实际位置": "TxPDO", "速度": "TxPDO", "转矩": "TxPDO"}
            pdo_type = _DTYPE_PDO.get(dtype, "RxPDO" if _state["sel_wkc"] == 0 else "TxPDO")
            pdo_hint_var.set(f"PDO方向自动识别：{pdo_type}")
            _fields.append({"axis": axis, "dtype": dtype, "pdo": pdo_type,
                             "offset": _state["sel_offset"], "bytelen": sel_len})
            _refresh_f_tree()

        def _do_del():
            sel = f_tree.selection()
            if not sel: return
            idx = int(sel[0])
            if 0 <= idx < len(_fields):
                _fields.pop(idx)
            _refresh_f_tree()

        def _do_clear():
            _fields.clear()
            _refresh_f_tree()

        def _do_gen_xml():
            if not _fields:
                messagebox.showinfo("提示", "请先添加至少一个 PDO 字段定义"); return
            import xml.dom.minidom as _minidom
            # ─── 与参考 XML 格式完全一致 ────────────────────────
            root_el = ET.Element("EtherCATInfo")
            descs   = ET.SubElement(root_el, "Descriptions")
            modules = ET.SubElement(descs,   "Modules")
            module  = ET.SubElement(modules, "Module")
            ET.SubElement(module, "Type").text = "ENET-Analyzer"
            ET.SubElement(module, "Name").text = "ENET-Analyzer"
            rx_pdo = ET.SubElement(module, "RxPdo")
            ET.SubElement(rx_pdo, "Name").text = "Inputs"
            tx_pdo = ET.SubElement(module, "TxPdo")
            ET.SubElement(tx_pdo, "Name").text = "Outputs"
            # 数据类型 → Entry Name 后缀（小写，与参考 XML 一致）
            _T = {"目标位置": "target",   "实际位置": "actual",
                  "速度":     "velocity", "转矩":     "torque",
                  "辅助1":   "aux1",     "辅助2":    "aux2", "辅助3": "aux3"}
            for f in _fields:
                parent = rx_pdo if f["pdo"] == "RxPDO" else tx_pdo
                entry  = ET.SubElement(parent, "Entry")
                ET.SubElement(entry, "Enable").text    = "1"
                ET.SubElement(entry, "Name").text      = f"{f['axis']}-{_T.get(f['dtype'], f['dtype'])}"
                ET.SubElement(entry, "CmdType").text   = "LRW"
                ET.SubElement(entry, "AddrType").text  = "0"
                ET.SubElement(entry, "BitOffset").text = str(f["offset"] * 8)
                ET.SubElement(entry, "BitLen").text    = str(f["bytelen"] * 8)
                ET.SubElement(entry, "DataType").text  = "DINT"
            xml_raw    = ET.tostring(root_el, encoding="unicode")
            xml_pretty = _minidom.parseString(xml_raw).toprettyxml(indent="  ")
            lines = [l for l in xml_pretty.splitlines() if not l.startswith("<?xml")]
            xml_out = '<?xml version="1.0" encoding="utf-8"?>\n' + "\n".join(lines)
            out_path = filedialog.asksaveasfilename(
                title="保存 PDO XML 配置文件",
                defaultextension=".xml",
                filetypes=[("XML 配置文件", "*.xml"), ("所有文件", "*.*")],
                initialfile="pdo_config.xml")
            if not out_path: return
            with open(out_path, "w", encoding="utf-8") as fp:
                fp.write(xml_out)
            if messagebox.askyesno(
                    "XML 生成成功",
                    f"XML 配置已保存：\n{out_path}\n\n"
                    f"共 {len(_fields)} 个字段。\n\n"
                    f"是否立即加载此配置并重新分析当前数据文件？"):
                try:
                    self._layout     = layout_from_xml(out_path)
                    self._xml_loaded = True
                    self._lbl_cfg.config(
                        text=f"[XML: {os.path.basename(out_path)}]",
                        foreground="#27ae60")
                    if hasattr(self, "_path") and self._path:
                        self._lbl_stat.config(text="XML 已加载，正在重新解析数据文件…")
                        self._pbar.config(mode="indeterminate")
                        self._pbar.start(12)
                        threading.Thread(target=self._worker,
                                         args=(self._path,), daemon=True).start()
                except Exception as exc:
                    messagebox.showerror("XML 加载失败", str(exc))

    def _load_and_populate_inspector(self):
        """后台加载原始帧并填充 PDO 帧检查器列表（懒加载时调用）。"""
        if not self._insp_state or not hasattr(self, "_path"): return
        state = self._insp_state
        tree  = state.get("tree")
        if tree is None: return
        for item in tree.get_children(): tree.delete(item)
        state.get("frames", []).clear()

        def _bg_load():
            frames = []
            try:
                t0 = None
                for ts, frame in iter_packets(self._path):
                    r = _extract_lrw(frame)
                    if r is None: continue
                    wkc, payload = r
                    if t0 is None: t0 = ts
                    frames.append((ts - t0, wkc, bytes(payload)))
                    if len(frames) >= 500: break
            except Exception:
                pass
            self.after(0, lambda: _fill(frames))

        def _fill(frames):
            st   = self._insp_state
            tree = st.get("tree")
            if tree is None: return
            fr_list = st.get("frames", [])
            fr_list.clear()
            fr_list.extend(frames)
            for item in tree.get_children(): tree.delete(item)
            for i, (ts, wkc, pl) in enumerate(frames):
                direction = "RxPDO (WKC=0)" if wkc == 0 else f"TxPDO (WKC={wkc})"
                preview   = " ".join(f"{b:02x}" for b in pl[:16])
                tree.insert("", tk.END, iid=str(i),
                            values=(i+1, f"{ts:.6f}", direction, wkc, len(pl), preview))
            # 自动选第一帧并触发渲染
            children = tree.get_children()
            if children:
                tree.selection_set(children[0])
                tree.event_generate("<<TreeviewSelect>>")

        threading.Thread(target=_bg_load, daemon=True).start()

    def _export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV","*.csv"),("所有文件","*.*")])
        if not path: return
        try:
            s=self._series; axes=self._layout["axes"]; vel=self._layout["vel_torq"]
            with open(path,"w",encoding="utf-8-sig") as f:
                rx_keys=[a["name"]+"-target" for a in axes]
                f.write(",".join(["时间(s)"]+rx_keys)+"\n")
                for i,t in enumerate(s["ts_rx"]):
                    f.write(",".join([f"{t:.6f}"]+[str(s[k][i]) if i<len(s[k]) else "" for k in rx_keys])+"\n")
                f.write("\n")
                tx_keys=[a["name"]+"-actual" for a in axes]+[ch["name"] for ch in vel]
                f.write(",".join(["时间(s)"]+tx_keys)+"\n")
                for i,t in enumerate(s["ts_tx"]):
                    f.write(",".join([f"{t:.6f}"]+[str(s[k][i]) if i<len(s[k]) else "" for k in tx_keys])+"\n")
            messagebox.showinfo("成功",f"已导出到：\n{path}")
        except Exception as e:
            messagebox.showerror("导出失败",str(e))

if __name__ == "__main__":
    App().mainloop()
