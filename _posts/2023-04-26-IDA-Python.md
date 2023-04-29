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


---

# The Beginner's Guide to IDAPython 
- by Alexander Hanel

#### three modules
- idc, idautils, idaapi.

#### basics
- ``` ea=ide.get_screen_ea(); print "0x%x %s" % (ea, ea) ```
- ``` idc.get_inf_attr(INF_MIN_EA) ``` 
- ``` idc.get_segm_name(ea) ```
- ``` idc.generate_disasm_line(ea, 0) ``` flag 0: returns the displayed disassembly that IDA discovered during its analysis; flag 1: To disassembly a particularoffset and ignore IDA's analysis. 
- ``` idc.print_insn_mnem(ea) ``` another way of above. result eg: lea, eg2: mov ...
- ``` idaapi.decode_insn(ea) ```
- ``` hex(idaapi.BADADDR) # output: 0xffffffffL ``` 32 bit bad address
- ``` hex(idc.BADADDR) # output: 0xffffffffffffffff ``` 64 bit bad address
- ``` idc.get_operand_type(line, 0) ``` https://www.hex-rays.com/products/ida/support/idadoc/276.shtml

#### segments
- ``` for seg in idautils.Segments(): print idc.get_segm_name(seg), idc.get_segm_start(seg), idc.get_segm_end(seg) ``` seg is a segment's start address.
- ``` idc.get_next_seg(ea) ```
- - ``` idc.selector_by_name() ``` returns the segment selector, which is an int, starts from 1 for each seg.
- ``` idc.get_segm_by_sel(idc.selector_by_name(str_SectionName)) ``` return the start address of segment.

#### functions
- ``` for func in idautils.Functions(): print hex(func), idc.get_func_name(func) ```
- ``` idautils.Functions(start_addr, end_addr) ``` search functions in range
- ``` idc.get_func_name(ea) ```
- ``` func = idaapi.get_func(ea); print "Start: 0x%x, End: 0x%x" % (func.startEA, func.endEA) ``` class idaapi.func_t
- ``` dir(func) ``` check how to use class returned above as idaapi.func_t
- ``` idc.get_next_func(ea); idc.get_prev_func(ea) ``` ea:  an address within the boundaries of the analyzed function
- ``` idc.get_func_attr(ea, attr) ```
- ``` idautils.FuncItems(ea) ``` loop through address in function, in case jmp outside the function.
- ``` idc.get_func_attr(ea, FUNCATTR_FLAGS) ``` retrieve function flags.
- 9 flags: FUNC_NORET, FUNC_FAR, FUNC_LIB, FUNC_STATIC, FUNC_FRAME, FUNC_USERFAR, FUNC_HIDDEN, FUNC_THUNK, FUNC_BOTTOMBP.
- a function can consist of multiple flags

#### Instructions
- get list of instruction address in a function: ``` dism_addr = list(idautils.FuncItems(here())) ``` note: instructions have different length.
- ``` for line in dism_addr: print hex(line), idc.generate_disasm_line(line, 0) ``` continue above
- ``` idc.next_head(ea) ``` next instruction, not next address. Similar ``` prev_instr = idc.prev_head(ea) ```
- ``` dir(idaapi.cmd) ``` check the attributes of idaapi.cmd

#### Operands



#### Xrefs
#### Searching
#### Selecting Data
#### Comments & Renaming
#### Accessing Raw Data
#### Patching
#### Input and Output
#### Intel Pin Logger
#### Batch File Generation
#### Executing Scripts



---

# The IDA Pro Book The Unofficial Guide 
- by Chris Eagle



---

# unit42
- https://unit42.paloaltonetworks.com/tag/idapython/



---

# Introduction to IDAPython
- by Ero Carrera
