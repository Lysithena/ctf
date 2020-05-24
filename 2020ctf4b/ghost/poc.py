from pwn import *

#io = remote("bs.quals.beginners.seccon.jp",9001)
#payload = cyclic(40)+p32(0x00400861)
#payload = rop.chain()
#io.send(payload.decode('ascii'))
flag = "ctf4b{"
ans = "3417 61039 39615 14756 10315 49836 44840 20086 18149 31454 35718 44949 4715 22725 62312 18726 47196 54518 2667 44346 55284 5240 32181 61722 6447 38218 6033 32270 51128 6112 22332 60338 14994 44529 25059 61829 52094"
answers = ans.split()
for i in range(31):
    m=0
    c=''
    for j in range(0x21,0x7e):
        io = process(['gs','./chall.ps'])
        io.sendline(flag+chr(j))
        io.recvuntil("details.\n")
        r=io.readline()
        nums = r.split()
        io.close()
        if nums[len(nums)-1].decode()==answers[i+6]:
            flag+=chr(j)
            break
    print(flag)
io.interactive()
