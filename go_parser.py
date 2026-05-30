#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
go_parser.py:
IDA Plugin for Golang Executable file parsing.
'''

__author__ = "JiaYu"
__license__ = "MIT"
__version__ = "1.0"
__email__ = ["jiayu0x@gmail.com"]

import idautils, idc, idaapi

import sys

sys.setrecursionlimit(10000)

import common
import strings
import ida_compat as ic
import pclntbl
import moduledata
import types_builder
import itab


def main():
    # find and parsefirfst moduledata
    firstmoddata_addr, magic_number = moduledata.find_first_moduledata_addr()
    common._debug("Parsing firstmoduledata object...")
    firstmoddata = moduledata.ModuleData(firstmoddata_addr, magic_number)
    firstmoddata.parse()
    # parse pclntab(functions/srcfiles and function pointers)
    common._debug("Parsing pcln table...")
    if magic_number == common.MAGIC_112:
        pclntab = pclntbl.Pclntbl(firstmoddata.pclntbl_addr, magic_number)
    else:
        pclntab = pclntbl.Pclntbl(firstmoddata.pcheader_addr, magic_number)
    pclntab.parse()

    common.get_goversion()

    common._info(f"pclntbl addr: {firstmoddata.pclntbl_addr:#x}\n")
    # parse strings
    parse_str_cnt = strings.parse_strings()
    common._info(f"Parsed [{parse_str_cnt}] strings\n")

    # parse data types
    type_parser = types_builder.TypesParser(firstmoddata)
    type_parser.build_all_types()

    # parse itabs
    itab.parse_itab(firstmoddata, type_parser)

if __name__ == '__main__':
    main()
