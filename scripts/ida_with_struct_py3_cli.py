# -*- coding: utf-8 -*-
import json
import idaapi
import ida_funcs
import idc
import os
import time
import sys

processFields = [
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
]

imageBase = idaapi.get_imagebase()

def get_addr(addr):
    return imageBase + addr

def set_name(addr, name):
    ret = idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)
    if ret == 0:
        new_name = name + '_' + str(addr)
        ret = idc.set_name(addr, new_name, SN_NOWARN | SN_NOCHECK)

def make_function(start, end):
    next_func = idc.get_next_func(start)
    if next_func < end:
        end = next_func
    if idc.get_func_attr(start, FUNCATTR_START) == start:
        ida_funcs.del_func(start)
    ida_funcs.add_func(start, end)

def print_progress(current, total, last_time, interval=5.0):
    """通用进度打印函数"""
    curr_time = time.time()
    if curr_time - last_time >= interval or current == total:
        percentage = (current / total) * 100 if total > 0 else 100
        print(f"[*] Progress ({current}/{total}): {percentage:.2f}%")
        return curr_time
    return last_time

# --- 参数解析 ---
if len(idc.ARGV) >= 3:
    path = idc.ARGV[1]  
    hpath = idc.ARGV[2] 
    print(f"[*] CLI Mode: Using {path = } and {hpath = }")
else:
    path = idaapi.ask_file(False, '*.json', 'script.json from Il2cppdumper')
    hpath = idaapi.ask_file(False, '*.h', 'il2cpp.h from Il2cppdumper')

if not path or not os.path.exists(path):
    print("[-] Error: `script.json` File not found!")
    idc.qexit(1)

if not hpath or not os.path.exists(hpath):
    print("[-] Error: `il2cpp.h` File not found!")
    idc.qexit(1)

print("[*] Load data")
parse_decls(open(hpath, 'r').read(), 0)
data = json.loads(open(path, 'rb').read().decode('utf-8'))

print("[*] Start running script")

# --- 1. 处理 Addresses ---
if "Addresses" in data and "Addresses" in processFields:
    addresses = data["Addresses"]
    total = len(addresses) - 1
    l_time = time.time()
    print(f"[*] Making functions ({total})...")
    for index in range(total):
        start = get_addr(addresses[index])
        end = get_addr(addresses[index + 1])
        make_function(start, end)
        l_time = print_progress(index + 1, total, l_time)

# --- 2. 处理 ScriptMethod ---
if "ScriptMethod" in data and "ScriptMethod" in processFields:
    methods = data["ScriptMethod"]
    total = len(methods)
    l_time = time.time()
    print(f"[*] Applying ScriptMethods ({total})...")
    for index, method in enumerate(methods):
        addr = get_addr(method["Address"])
        name = method["Name"]
        set_name(addr, name)
        signature = method["Signature"]
        
        # 尝试应用类型，失败则打印
        if not apply_type(addr, parse_decl(signature, 0), 1):
            print(f"[!] apply_type failed: {hex(addr)} | {signature}")
            
        l_time = print_progress(index + 1, total, l_time)

# --- 3. 处理 ScriptString ---
if "ScriptString" in data and "ScriptString" in processFields:
    strings = data["ScriptString"]
    total = len(strings)
    l_time = time.time()
    print(f"[*] Naming ScriptStrings ({total})...")
    for index, s_item in enumerate(strings):
        addr = get_addr(s_item["Address"])
        value = s_item["Value"]
        name = f"StringLiteral_{index + 1}"
        idc.set_name(addr, name, SN_NOWARN)
        idc.set_cmt(addr, value, 1)
        l_time = print_progress(index + 1, total, l_time)

# --- 4. 处理 ScriptMetadata ---
if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
    metadata = data["ScriptMetadata"]
    total = len(metadata)
    l_time = time.time()
    print(f"[*] Applying ScriptMetadata ({total})...")
    for index, m_item in enumerate(metadata):
        addr = get_addr(m_item["Address"])
        name = m_item["Name"]
        set_name(addr, name)
        idc.set_cmt(addr, name, 1)
        
        if m_item.get("Signature"):
            signature = m_item["Signature"]
            if not apply_type(addr, parse_decl(signature, 0), 1):
                print(f"[!] apply_type (Metadata) failed: {hex(addr)} | {signature}")
        
        l_time = print_progress(index + 1, total, l_time)

# --- 5. 处理 ScriptMetadataMethod ---
if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
    meta_methods = data["ScriptMetadataMethod"]
    total = len(meta_methods)
    l_time = time.time()
    print(f"[*] Setting ScriptMetadataMethods ({total})...")
    for index, mm_item in enumerate(meta_methods):
        addr = get_addr(mm_item["Address"])
        name = mm_item["Name"]
        m_addr = get_addr(mm_item["MethodAddress"])
        set_name(addr, name)
        idc.set_cmt(addr, name, 1)
        idc.set_cmt(addr, f'{m_addr:X}', 0)
        l_time = print_progress(index + 1, total, l_time)

print('[*] Script finished, waiting for autoanalysis to complete...')
sys.stdout.flush()

idaapi.auto_wait()
idc.save_database("")
print("[*] All done! Database saved.")
idc.qexit(0)