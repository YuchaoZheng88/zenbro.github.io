---
title: IDA Python
author: Yuchao
date: 2023-04-26 11:33:00 +0800
categories: [sec]
tags: [forensic]
math: true
mermaid: true
---

# PE format
- https://github.com/corkami/pics/blob/master/binary/PE.png
- https://github.com/corkami/pics/blob/master/binary/PE101.png
- https://github.com/corkami/pics/blob/master/binary/PE102.png


# unit42
- https://unit42.paloaltonetworks.com/tag/idapython/




---

# The Beginner's Guide to IDAPython 
- by Alexander Hanel

three modules
- idc, idautils, idaapi.

#### basics
- ``` ea=ide.get_screen_ea(); print "0x%x %s" % (ea, ea) ```
- ``` idc.get_inf_attr(INF_MIN_EA) ``` 
- ``` idc.get_segm_name(ea) ```
- ``` idc.generate_disasm_line(ea, 0) ``` flag 0: returns the displayed disassembly that IDA discovered during its analysis; flag 1: To disassembly a particularoffset and ignore IDA's analysis. 
- ``` idc.print_insn_mnem(ea) ``` result eg: lea, eg2: mov ...
- ``` hex(idaapi.BADADDR) # output: 0xffffffffL ``` 32 bit bad address
- ``` hex(idc.BADADDR) # output: 0xffffffffffffffff ``` 64 bit bad address

#### segments
- ``` for seg in idautils.Segments(): print idc.get_segm_name(seg), idc.get_segm_start(seg), idc.get_segm_end(seg) ``` seg is a segment's start address.
- ``` idc.get_next_seg(ea) ```
- - ``` idc.selector_by_name() ``` returns the segment selector, which is an int, starts from 1 for each seg.
- ``` idc.get_segm_by_sel(idc.selector_by_name(str_SectionName)) ``` return the start address of segment.

#### functions
- ``` for func in idautils.Functions(): print hex(func), idc.get_func_name(func) ```
- ``` idautils.Functions(start_addr, end_addr) ``` search functions in range
- ``` idc.get_func_name(ea) ```


---

# The IDA Pro Book The Unofficial Guide 
- by Chris Eagle




---

# Introduction to IDAPython
- by Ero Carrera
