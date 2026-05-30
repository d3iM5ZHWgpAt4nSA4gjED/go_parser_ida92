#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import importlib
import idc, idaapi

try:
    import ida_bytes
except Exception:
    ida_bytes = None
try:
    import ida_name
except Exception:
    ida_name = None
try:
    import ida_funcs
except Exception:
    ida_funcs = None
try:
    import ida_search
except Exception:
    ida_search = None
try:
    import ida_nalt
except Exception:
    ida_nalt = None
try:
    import ida_ida
except Exception:
    ida_ida = None
try:
    import ida_auto
except Exception:
    ida_auto = None

BADADDR = getattr(idaapi, 'BADADDR', getattr(idc, 'BADADDR', 0xFFFFFFFFFFFFFFFF))
SN_FORCE = getattr(idaapi, 'SN_FORCE', 0)
SEARCH_DOWN = getattr(idaapi, 'SEARCH_DOWN', getattr(ida_search, 'SEARCH_DOWN', 1))
FCB_RET = getattr(idaapi, 'fcb_ret', getattr(idaapi, 'fc_ret', 2))
DELIT_SIMPLE = getattr(idc, 'DELIT_SIMPLE', 0)
DELIT_EXPAND = getattr(idc, 'DELIT_EXPAND', 0)
FF_WORD = getattr(idc, 'FF_WORD', 0)
FF_DWORD = getattr(idc, 'FF_DWORD', 0)
FF_QWORD = getattr(idc, 'FF_QWORD', 0)
DR_O = getattr(idaapi, 'dr_O', 0)


def require(modname):
    return importlib.import_module(modname)


def get_inf_structure():
    if hasattr(idaapi, 'get_inf_structure'):
        return idaapi.get_inf_structure()
    if ida_ida and hasattr(ida_ida, 'inf_get_procname'):
        class _InfWrap:
            max_ea = ida_ida.inf_get_max_ea()
            procname = ida_ida.inf_get_procname()
            def is_64bit(self):
                return ida_ida.inf_is_64bit()
            def is_be(self):
                return ida_ida.inf_is_be()
            @property
            def mf(self):
                return ida_ida.inf_is_be()
        return _InfWrap()
    raise RuntimeError('Unable to obtain IDA info structure')


def auto_wait():
    if ida_auto and hasattr(ida_auto, 'auto_wait'):
        return ida_auto.auto_wait()
    if hasattr(idaapi, 'auto_wait'):
        return idaapi.auto_wait()
    return None


def create_strlit(start, end):
    if hasattr(idc, 'create_strlit'):
        return idc.create_strlit(start, end)
    if ida_bytes and hasattr(ida_bytes, 'create_strlit'):
        return ida_bytes.create_strlit(start, end, ida_nalt.STRTYPE_C if ida_nalt else 0)
    return False


def del_items(ea, size, flags=DELIT_SIMPLE):
    return idc.del_items(ea, flags, size)


def set_name(ea, name, flags=SN_FORCE):
    if ida_name and hasattr(ida_name, 'set_name'):
        return ida_name.set_name(ea, name, flags)
    return idc.set_name(ea, name, flags)


def get_ea_name(ea):
    if ida_name and hasattr(ida_name, 'get_ea_name'):
        return ida_name.get_ea_name(ea)
    return idc.get_name(ea)


def get_func_name(ea):
    if ida_funcs and hasattr(ida_funcs, 'get_func_name'):
        return ida_funcs.get_func_name(ea)
    return idc.get_func_name(ea)


def add_dref(frm, to, drtype=DR_O):
    if idaapi and hasattr(idaapi, 'add_dref'):
        return idaapi.add_dref(frm, to, drtype)
    return False


def find_code(ea, direction=SEARCH_DOWN):
    if ida_search and hasattr(ida_search, 'find_code'):
        return ida_search.find_code(ea, direction)
    return idc.find_code(ea, direction)


def op_plain_offset(ea, n, base):
    if hasattr(idc, 'op_plain_offset'):
        return idc.op_plain_offset(ea, n, base)
    if ida_offset and hasattr(ida_offset, 'op_plain_offset'):
        return ida_offset.op_plain_offset(ea, n, base)
    return False
