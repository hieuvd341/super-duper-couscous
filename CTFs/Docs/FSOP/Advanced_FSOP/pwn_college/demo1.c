#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    puts("You win!");
}

int main(int argc, char **argv) {
    // Leak win function address
    printf("win func is located at: %p\n", &win);
    printf("puts is located at: %p\n", puts);

    // Open a file
    FILE *file_pointer = fopen("/dev/null", "w");

    char buf[0x1000];
    printf("Reading into stack buff located at: %p\n", buf);
    read(0, buf, 0x1000);

    puts("Reading over file pointer\n");

    // Overwrite the file struct from stdin
    read(0, file_pointer, 0x1000);

    // Call fwrite on the file
    puts("Calling fwrite");
    fwrite(buf, 1, 10, file_pointer);

    exit(0);
}
