#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    puts("You win!");
}

void init () {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
int main(int argc, char **argv) {
    init();
    char buf[0x1000];
    long long address;
    long long value;
    
    // Leak win function address
    printf("win func is located at: %p\n", &win);
    printf("puts is located at: %p\n", puts);
    printf("Reading into stack buff located at: %p\n", buf);

    // Open a file
    FILE *file_pointer = fopen("/dev/null", "w");
    // print file pointer
    printf("File pointer: %p\n", file_pointer);
    

    // Give user arbitrary write
    while (1) {
        printf("Enter an address to write to: ");
        scanf("%llx", &address);
        printf("Enter a value to write: ");
        scanf("%llx", &value);
        *(long long *)address = value;
        printf("Wrote %llx to %llx\n", value, address);
        printf("Do you want to write again? (y/n): ");
        char c;
        read(0, &c, 1);
        if (c != 'y') {
            break;
        }
    }
    
    printf("Enter to stack buffer: ");
    read(0, buf, 0x1000);    

    // Call fwrite on the file
    puts("Calling fwrite");
    fwrite(buf, 1, 10, file_pointer);
    
    exit(0);
}
