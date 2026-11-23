#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcl_ce_unlock.py — PCL2 CE (Plain Craft Launcher Community Edition) 区域下载限制解锁补丁
借鉴 ailixiyaX/PCLDownloadUnlock (MIT) 的解析与补丁逻辑, 用纯 Python 实现。

原理:
  对 .NET 单文件包内的 PCL.RestrictedFeaturePolicy 两个方法做等长 IL 补丁:
    Check(string, bool)   -> ldc.i4.1; ret  (0x17 0x2A)  恒放行
    get_IsRestricted()    -> ldc.i4.0; ret  (0x16 0x2A)  恒"未受限"
  同时把方法体 codeSize 改为 2, 避免尾部残留指令触发 InvalidProgramException。
  不改元数据、不改文件大小、不注入代码。

用法:
  python pcl_ce_unlock.py check  [file]   检测状态
  python pcl_ce_unlock.py patch  [file] [--out OUT] [--backup BAK]
  python pcl_ce_unlock.py revert [file] [--backup BAK]
"""

import argparse
import hashlib
import os
import shutil
import struct
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

DEFAULT_TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "MC", "PCL2_CE_Release_x64.exe")

# ---------------------------------------------------------------- 常量

# .NET 单文件包 32 字节 bundle 签名 (apphost 预留头之后)
BUNDLE_MARKER = bytes([
    0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38,
    0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
    0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18,
    0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE,
])

TARGET_NAMESPACE = "PCL"
TARGET_TYPE = "RestrictedFeaturePolicy"
CHECK_METHOD = "Check"                 # 补成恒 true
RESTRICTED_PROPERTY = "get_IsRestricted"  # 补成恒 false

CHECK_IL = bytes([0x17, 0x2A])      # ldc.i4.1; ret  -> 恒"允许"
RESTRICTED_IL = bytes([0x16, 0x2A])  # ldc.i4.0; ret  -> 恒"未受限"

SITE_EXPECTED = {
    CHECK_METHOD: (CHECK_IL, "允许通过/不再弹提示"),
    RESTRICTED_PROPERTY: (RESTRICTED_IL, "恒为\"未受限\""),
}


class PatchError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- 基础读取

def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def i64(b, o):
    return struct.unpack_from("<q", b, o)[0]


def read_lenstr(b, pos):
    """读 7-bit 编码长度前缀的 UTF-8 字符串, 返回 (字符串, 新位置)。"""
    length = 0
    shift = 0
    while True:
        if pos >= len(b) or shift > 35:
            raise ValueError("bad length-prefixed string")
        x = b[pos]
        pos += 1
        length |= (x & 0x7F) << shift
        if not (x & 0x80):
            break
        shift += 7
    if length < 0 or pos + length > len(b):
        raise ValueError("bad string length")
    return b[pos:pos + length].decode("utf-8", errors="replace"), pos + length


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest().upper()


# ---------------------------------------------------------------- 单文件包 (bundle) 解析

def parse_bundle(data):
    """定位并解析 .NET 单文件包清单, 返回 dict; 失败抛 PatchError('not-bundle')。"""
    mpos = data.find(BUNDLE_MARKER)
    if mpos < 0:
        raise PatchError("not-bundle", "未找到 .NET 单文件包签名, 不是单文件包")

    candidates = []
    if mpos >= 8:
        candidates.append(i64(data, mpos - 8))
    if mpos >= 16:
        candidates.append(i64(data, mpos - 16))

    for c in candidates:
        bundle = _try_parse_bundle_at(data, c)
        if bundle:
            return bundle

    # 回退: 每隔 8 字节扫描 (罕见布局)
    for off in range(0, max(0, len(data) - 48), 8):
        if u32(data, off) not in (2, 6):
            continue
        bundle = _try_parse_bundle_at(data, off)
        if bundle:
            return bundle

    raise PatchError("not-bundle", "未能定位有效的单文件包清单")


def _try_parse_bundle_at(data, off):
    if off <= 0 or off + 48 > len(data):
        return None
    major = u32(data, off)
    minor = u32(data, off + 4)
    if major not in (2, 6) or minor != 0:
        return None
    count = u32(data, off + 8)
    if count <= 0 or count > 20000:
        return None

    pos = off + 12
    try:
        bundle_id, pos = read_lenstr(data, pos)
        deps_off = deps_size = rc_off = rc_size = 0
        if major >= 2:
            if pos + 40 > len(data):
                return None
            deps_off = i64(data, pos)
            deps_size = i64(data, pos + 8)
            rc_off = i64(data, pos + 16)
            rc_size = i64(data, pos + 24)
            pos += 40

        entries = []
        fixed = 25 if major >= 6 else 17  # major>=6 才有 compressedSize 字段
        for _ in range(count):
            if pos + fixed > len(data):
                return None
            e_off = i64(data, pos)
            e_size = i64(data, pos + 8)
            if major >= 6:
                e_csize = i64(data, pos + 16)
                e_type = data[pos + 24]
            else:
                e_csize = 0
                e_type = data[pos + 16]
            pos += fixed
            path, pos = read_lenstr(data, pos)
            if e_off < 0 or e_size < 0 or e_csize < 0:
                return None
            if e_off + e_size > off:  # 条目必须落在清单头之前
                return None
            entries.append({"offset": e_off, "size": e_size,
                            "csize": e_csize, "type": e_type, "path": path})

        if deps_off + deps_size > off or rc_off + rc_size > off:
            return None
    except (ValueError, struct.error):
        return None

    # 清单应恰好结束于文件尾 (或罕见地结束于头偏移处)
    if pos != len(data) and pos != off:
        return None

    return {"header_off": off, "major": major, "minor": minor,
            "count": count, "id": bundle_id, "entries": entries}


# ---------------------------------------------------------------- PE / CLI 元数据解析

def rva_to_offset(sections, rva):
    for vaddr, vsize, rsize, rptr in sections:
        span = max(vsize, rsize)
        if vaddr <= rva < vaddr + span:
            delta = rva - vaddr
            if delta >= rsize:
                return -1
            return rptr + delta
    return -1


def parse_pe_metadata(data):
    """解析内嵌 DLL, 返回 (sections, strings_heap_off, tables_off, heap_sizes, rows)。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = u32(data, 0x3C)
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        num_sections = u16(data, coff + 2)
        size_opt = u16(data, coff + 16)
        opt = coff + 20
        magic = u16(data, opt)
        if magic == 0x20B:      # PE32+
            dd = opt + 112
        elif magic == 0x10B:    # PE32
            dd = opt + 96
        else:
            return None

        cli_rva = u32(data, dd + 14 * 8)        # CLR 运行时头 (第 15 个数据目录)
        if cli_rva == 0:
            return None
        sections = []
        sec_off = opt + size_opt
        if sec_off + num_sections * 40 > len(data):
            return None
        for i in range(num_sections):
            s = sec_off + i * 40
            sections.append((u32(data, s + 12), u32(data, s + 8),
                             u32(data, s + 16), u32(data, s + 20)))

        cli_off = rva_to_offset(sections, cli_rva)
        if cli_off < 0 or cli_off + 24 > len(data):
            return None
        md_rva = u32(data, cli_off + 8)
        md_off = rva_to_offset(sections, md_rva)
        if md_off < 0 or md_off + 20 > len(data):
            return None
        if u32(data, md_off) != 0x424A5342:     # "BSJB"
            return None

        ver_len = u32(data, md_off + 12)
        p = md_off + 16 + ver_len
        if p + 4 > len(data):
            return None
        n_streams = u16(data, p + 2)
        p += 4
        streams = {}
        for _ in range(n_streams):
            if p + 8 > len(data):
                return None
            s_off = u32(data, p)
            s_size = u32(data, p + 4)
            q = p + 8
            name_end = data.find(b"\x00", q, q + 64)
            if name_end < 0:
                return None
            name = data[q:name_end].decode("ascii", errors="replace")
            q_next = q + ((name_end - q + 1 + 3) & ~3)
            streams[name] = (md_off + s_off, s_size)
            p = q_next

        tbl = streams.get("#~") or streams.get("#-")
        if not tbl:
            return None
        strings = streams.get("#Strings")
        if not strings:
            return None

        t_off = tbl[0]
        if t_off + 24 > len(data):
            return None
        heap_sizes = data[t_off + 6]
        valid = u64(data, t_off + 8)
        p = t_off + 24
        rows = {}
        for i in range(64):
            if valid & (1 << i):
                if p + 4 > len(data):
                    return None
                rows[i] = u32(data, p)
                p += 4
        return sections, strings[0], p, heap_sizes, rows
    except (ValueError, struct.error):
        return None


def find_policy_methods(data):
    """在内嵌 DLL 字节中定位 RestrictedFeaturePolicy 的两个方法, 返回站点列表。"""
    parsed = parse_pe_metadata(data)
    if not parsed:
        return []
    sections, str_off, tables_off, heap_sizes, rows = parsed

    s_sz = 4 if heap_sizes & 0x01 else 2
    g_sz = 4 if heap_sizes & 0x02 else 2
    b_sz = 4 if heap_sizes & 0x04 else 2

    def tidx(table):
        return 4 if rows.get(table, 0) > 0xFFFF else 2

    def cidx(tables, bits):
        max_rows = max((rows.get(t, 0) for t in tables), default=0)
        return 4 if max_rows >= (1 << (16 - bits)) else 2

    # ECMA-335: 0..6 号表行宽 (定位 TypeDef/MethodDef 只需要这些)
    TYPE_DEF_OR_REF = [0x02, 0x01, 0x1B]
    RESOLUTION_SCOPE = [0x00, 0x1A, 0x23, 0x01]
    row_sizes = {
        0x00: 2 + s_sz + 3 * g_sz,                                # Module
        0x01: cidx(RESOLUTION_SCOPE, 2) + s_sz + s_sz,            # TypeRef
        0x02: 4 + s_sz + s_sz + cidx(TYPE_DEF_OR_REF, 2)          # TypeDef
              + tidx(0x04) + tidx(0x06),
        0x03: tidx(0x04),                                          # FieldPtr
        0x04: 2 + s_sz + b_sz,                                     # Field
        0x05: tidx(0x06),                                          # MethodPtr
        0x06: 4 + 2 + 2 + s_sz + b_sz + tidx(0x08),               # MethodDef
    }

    # 按表序累加, 得到 0..6 号表的数据起始偏移
    offsets = {}
    cur = tables_off
    for i in sorted(rows):
        if i > 0x06:
            break
        offsets[i] = cur
        if i not in row_sizes:
            return []
        cur += row_sizes[i] * rows[i]

    if 0x02 not in offsets or 0x06 not in offsets:
        return []

    def read_str(idx):
        o = str_off + idx
        end = data.find(b"\x00", o, o + 1024)
        if end < 0:
            return ""
        return data[o:end].decode("utf-8", errors="replace")

    typedef_off = offsets[0x02]
    typedef_size = row_sizes[0x02]
    typedef_count = rows.get(0x02, 0)
    methoddef_off = offsets[0x06]
    methoddef_size = row_sizes[0x06]
    methoddef_count = rows.get(0x06, 0)

    # 找 PCL.RestrictedFeaturePolicy
    target_row = None
    for r in range(typedef_count):
        base = typedef_off + r * typedef_size
        name_idx = u32(data, base + 4) if s_sz == 4 else u16(data, base + 4)
        ns_idx = u32(data, base + 4 + s_sz) if s_sz == 4 else u16(data, base + 4 + s_sz)
        if read_str(name_idx) != TARGET_TYPE or read_str(ns_idx) != TARGET_NAMESPACE:
            continue
        method_list_off = base + 4 + s_sz + s_sz + cidx(TYPE_DEF_OR_REF, 2) + tidx(0x04)
        method_list = u32(data, method_list_off) if tidx(0x06) == 4 else u16(data, method_list_off)
        if r + 1 < typedef_count:
            nxt = typedef_off + (r + 1) * typedef_size
            nxt_list_off = nxt + 4 + s_sz + s_sz + cidx(TYPE_DEF_OR_REF, 2) + tidx(0x04)
            method_end = u32(data, nxt_list_off) if tidx(0x06) == 4 else u16(data, nxt_list_off)
        else:
            method_end = methoddef_count + 1
        target_row = (method_list, method_end)
        break

    if not target_row:
        return []
    m_start, m_end = target_row
    if m_start < 1 or m_end < m_start:
        return []
    m_start -= 1  # 转为 0 基
    m_end -= 1

    sites = []
    for r in range(m_start, min(m_end, methoddef_count)):
        base = methoddef_off + r * methoddef_size
        rva = u32(data, base)
        name_off_idx = base + 8
        name_idx = u32(data, name_off_idx) if s_sz == 4 else u16(data, name_off_idx)
        name = read_str(name_idx)
        if name not in SITE_EXPECTED:
            continue
        if rva == 0:
            continue
        body_off = rva_to_offset(sections, rva)
        if body_off < 0 or body_off >= len(data):
            continue

        b0 = data[body_off]
        if (b0 & 0x03) == 0x02:      # tiny 头
            code_size = b0 >> 2
            il_off = body_off + 1
            is_fat = False
        elif (b0 & 0x03) == 0x03:    # fat 头
            if body_off + 12 > len(data):
                continue
            code_size = u32(data, body_off + 4)
            il_off = body_off + 12
            is_fat = True
        else:
            continue
        if code_size < 2 or il_off + code_size > len(data):
            continue

        expected, effect = SITE_EXPECTED[name]
        sites.append({
            "name": name,
            "effect": effect,
            "rva": rva,
            "body_off": body_off,
            "il_off": il_off,
            "code_size": code_size,
            "is_fat": is_fat,
            "expected": expected,
        })
    return sites


def is_site_patched(data, abs_il, abs_body, site):
    if abs_il + 1 >= len(data) or abs_body >= len(data):
        return False
    if data[abs_il] != site["expected"][0] or data[abs_il + 1] != site["expected"][1]:
        return False
    if site["is_fat"]:
        if abs_body + 8 > len(data):
            return False
        code_size = u32(data, abs_body + 4)
    else:
        code_size = data[abs_body] >> 2
    return code_size == 2


# ---------------------------------------------------------------- 分析 / 补丁 / 还原

def analyze(data):
    bundle = parse_bundle(data)
    sites = []
    skipped = []
    for e in bundle["entries"]:
        if e["type"] != 1:  # 1 = 程序集
            continue
        if e["csize"] != 0:
            skipped.append(e["path"])
            continue
        dll = data[e["offset"]:e["offset"] + e["size"]]
        found = find_policy_methods(dll)
        for s in found:
            s["entry"] = e
            s["abs_il"] = e["offset"] + s["il_off"]
            s["abs_body"] = e["offset"] + s["body_off"]
            s["patched"] = is_site_patched(data, s["abs_il"], s["abs_body"], s)
        sites.extend(found)
    return bundle, sites, skipped


def apply_patch(data):
    """返回 (新字节, 补丁了哪些, 已补过哪些)。"""
    mutable = bytearray(data)
    bundle, sites, _ = analyze(data)
    patched, already = [], []
    for s in sites:
        if s["patched"]:
            already.append(s["name"])
            continue
        mutable[s["abs_il"]] = s["expected"][0]
        mutable[s["abs_il"] + 1] = s["expected"][1]
        if s["is_fat"]:
            struct.pack_into("<I", mutable, s["abs_body"] + 4, 2)
        else:
            mutable[s["abs_body"]] = (2 << 2) | 0x02
        patched.append(s["name"])
    if not patched and not already:
        raise PatchError("incompatible",
                         "在程序集中未找到 %s.%s 的可补丁点" % (TARGET_NAMESPACE, TARGET_TYPE))
    return bytes(mutable), patched, already


def verify(data):
    bundle, sites, _ = analyze(data)
    if not sites:
        raise PatchError("verify", "校验失败: 补丁后未找到补丁点")
    for s in sites:
        if not s["patched"]:
            raise PatchError("verify", "校验失败: %s 未成功打补丁" % s["name"])
    return bundle, sites


def write_file_safely(path, data):
    tmp = path + ".pclunlock.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def load(path):
    with open(path, "rb") as f:
        return f.read()


def is_locked(path):
    try:
        with open(path, "r+b"):
            return False
    except PermissionError:
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- 命令行

def cmd_check(path):
    data = load(path)
    print("文件: %s" % path)
    print("大小: %d 字节  SHA256: %s" % (len(data), sha256_hex(data)))
    try:
        bundle, sites, skipped = analyze(data)
    except PatchError as e:
        print("状态: 不适用 (%s)" % e)
        return 3
    print("单文件包: v%d.%d, %d 个文件, 清单头 0x%X, id=%s"
          % (bundle["major"], bundle["minor"], bundle["count"], bundle["header_off"], bundle["id"]))
    for p in skipped:
        print("跳过(压缩条目): %s" % p)
    if not sites:
        print("状态: 不适用 (未找到 %s.%s 补丁点; 可能是不带该限制的版本)"
              % (TARGET_NAMESPACE, TARGET_TYPE))
        return 4
    all_patched = True
    for s in sites:
        state = "已打补丁" if s["patched"] else "未打补丁"
        if not s["patched"]:
            all_patched = False
        print("  %-18s RVA=0x%-6X IL=%2d 字节  文件偏移=0x%X  [%s]  -> %s"
              % (s["name"], s["rva"], s["code_size"], s["abs_il"], state, s["effect"]))
    print("状态: %s" % ("已打补丁 ✓" if all_patched else "未打补丁"))
    return 0 if all_patched else 1


def cmd_patch(path, out=None, backup=None):
    if is_locked(path):
        raise PatchError("busy", "目标文件被占用: PCL 可能正在运行, 请完全退出后重试")
    data = load(path)
    print("原文件 SHA256: %s" % sha256_hex(data))
    new_data, patched, already = apply_patch(data)
    target_desc = out or path

    if patched:
        if out:
            write_file_safely(out, new_data)
        else:
            bak = backup or (path + ".pclfix.bak")
            if not os.path.exists(bak):
                shutil.copy2(path, bak)
                print("已备份原文件: %s" % bak)
            else:
                print("备份已存在, 不覆盖: %s" % bak)
            write_file_safely(path, new_data)
    else:
        print("所有补丁点均已打过补丁, 文件未修改。")

    # 写后校验 (失败时自动还原, 避免留下坏文件)
    try:
        verify(load(target_desc))
    except PatchError:
        if patched and out:
            if os.path.exists(out):
                os.remove(out)
            print("校验失败, 已删除输出文件。")
        elif patched:
            write_file_safely(path, data)
            print("校验失败, 已自动还原原文件内容。")
        raise
    print("已补丁: %s" % ", ".join(patched) if patched else "无新补丁")
    for a in already:
        print("本已补丁: %s" % a)
    print("校验通过 ✓  当前文件 SHA256: %s" % sha256_hex(load(target_desc)))
    return 0


def cmd_revert(path, backup=None):
    bak = backup or (path + ".pclfix.bak")
    if not os.path.exists(bak):
        print("未找到备份文件: %s" % bak)
        return 1
    if is_locked(path):
        raise PatchError("busy", "目标文件被占用: 请先完全退出 PCL")
    write_file_safely(path, load(bak))
    print("已从备份还原: %s" % bak)
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description="PCL2 CE 区域下载限制解锁补丁")
    ap.add_argument("action", nargs="?", default="check", choices=["check", "patch", "revert"])
    ap.add_argument("file", nargs="?", default=DEFAULT_TARGET)
    ap.add_argument("--out", help="把补丁结果写到新文件而不修改原文件")
    ap.add_argument("--backup", help="自定义备份文件路径 (patch/revert)")
    args = ap.parse_args(argv)

    try:
        if args.action == "check":
            return cmd_check(args.file)
        if args.action == "patch":
            return cmd_patch(args.file, out=args.out, backup=args.backup)
        if args.action == "revert":
            return cmd_revert(args.file, backup=args.backup)
    except PatchError as e:
        print("错误[%s]: %s" % (e.code, e))
        return 5
    except FileNotFoundError:
        print("错误: 文件不存在: %s" % args.file)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
