#include <stdio.h>
#include <wchar.h>
#include <wctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>

#define BUF_SIZE (0x200000)

int charInSet(char c, const char* set) 
{
    size_t len = strlen(set);

    for (size_t i = 0; i < len; i++) {
        if (c == set[i]) {
            return 1;
        }
    }

    return 0;
}

int containsHebrew(const char* str, const char* set) 
{
    while (*str) {
        unsigned short tmp_char = *(wchar_t *)str;
        unsigned short flipped = (tmp_char << 8) | (tmp_char >> 8);

        if (charInSet(*str, set)) {
            str++;
        }
        else if ( flipped >= 0xd6b0 && flipped <= 0xd7b2  ) {
            str += 2;
        }
        else {
            return false;
        }
    }

    return true;
}

int main() {
    char* shellcode = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const char* ALLOWED_CHARS = "1234567890!@#$%^&*()_+-=[]{},./\\\"':; " ;
    
    printf("קוד צדף בבקשה: ");
    fgets(shellcode, BUF_SIZE, stdin);
    
    // trailing rn
    size_t len = strlen(shellcode);
    if (len > 0 && shellcode[len - 1] == '\n') {
        shellcode[len - 1] = '\0';
    }
    len = strlen(shellcode);
    if (len > 0 && shellcode[len - 1] == '\r') {
        shellcode[len - 1] = '\0';
    }
    
    if (containsHebrew(shellcode, ALLOWED_CHARS)) {
        printf("קוד הצדף בעברית בלבד, כל הכבוד!...\n");
        void (*executeShellcode)() = (void (*)())shellcode;
        __asm__ __volatile__(
            "xor %%ecx, %%ecx"
            :
        );
        executeShellcode();
    } else {
        printf("עברית דבר עברית\n");
    }
    
    return 0;
}
