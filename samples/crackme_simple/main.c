#include <stdio.h>
#include <string.h>

static void build_expected(char *out, size_t out_size) {
    const unsigned char seed[] = { 0x4D, 0x44, 0x52, 0x30, 0x36, 0x35, 0x3B, 0x3D };
    size_t i;

    if (out_size < sizeof(seed) + 1) {
        if (out_size != 0) {
            out[0] = '\0';
        }
        return;
    }

    for (i = 0; i < sizeof(seed); ++i) {
        out[i] = (char)(seed[i] - (unsigned char)i);
    }
    out[sizeof(seed)] = '\0';
}

static int validate_password(const char *input) {
    char expected[9];
    size_t i;

    build_expected(expected, sizeof(expected));
    if (strlen(input) != strlen(expected)) {
        return 0;
    }

    for (i = 0; expected[i] != '\0'; ++i) {
        if ((unsigned char)input[i] != (unsigned char)expected[i]) {
            return 0;
        }
    }

    return 1;
}

int main(void) {
    char buffer[128];

    puts("crackme_simple");
    puts("Enter password:");

    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        puts("no input");
        return 1;
    }

    buffer[strcspn(buffer, "\r\n")] = '\0';

    if (validate_password(buffer)) {
        puts("correct");
        puts("flag: MCP{simple_crackme_passed}");
        return 0;
    }

    puts("wrong");
    return 2;
}
