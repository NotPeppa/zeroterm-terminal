#include "common/iconv.h"
#include "common/clipboard.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char text[] = "\xE4\xB8\xAD\xF0\x9F\x98\x80\n";
    const char encoded[] = "\x2D\x4E\x3D\xD8\x00\xDE\x0D\x00\x0A\x00\x00\x00";
    char utf16[32] = {0}, decoded[32] = {0};
    const char* input = text;
    char* output = utf16;
    assert(guac_iconv(GUAC_READ_UTF8, &input, sizeof(text),
        GUAC_WRITE_UTF16_CRLF, &output, sizeof(utf16)));
    assert(output - utf16 == 12 && !memcmp(utf16, encoded, 12));
    input = utf16; output = decoded;
    assert(guac_iconv(GUAC_READ_UTF16_NORMALIZED, &input, 12,
        GUAC_WRITE_UTF8, &output, sizeof(decoded)));
    assert(!strcmp(decoded, text));
    const char invalid[] = "\x00\xD8\x41\x00\x00\xDC";
    input = invalid;
    assert(GUAC_READ_UTF16(&input, 6) == 0xFFFD && input == invalid + 2);
    assert(GUAC_READ_UTF16(&input, 4) == 65);
    assert(GUAC_READ_UTF16(&input, 2) == 0xFFFD);
    input = invalid;
    assert(GUAC_READ_UTF16(&input, 2) == 0xFFFD && input == invalid + 2);
    memset(utf16, 'X', sizeof(utf16)); output = utf16;
    GUAC_WRITE_UTF16(&output, 3, 0x1F600);
    assert(output == utf16 && utf16[0] == 'X');
    GUAC_WRITE_UTF16(&output, 4, 0x10FFFF);
    input = utf16;
    assert(GUAC_READ_UTF16(&input, 4) == 0x10FFFF);
    const int limit = 262144;
    assert(GUAC_COMMON_CLIPBOARD_MAX_LENGTH > limit);
    char* large = malloc(limit + 1);
    char* expanded = malloc(limit * 4 + 2);
    assert(large && expanded);
    memset(large, '\n', limit); large[limit] = '\0';
    input = large; output = expanded;
    assert(guac_iconv(GUAC_READ_UTF8, &input, limit + 1,
        GUAC_WRITE_UTF16_CRLF, &output, limit * 4 + 2));
    assert(output - expanded == limit * 4 + 2);
    free(expanded); free(large);
    return 0;
}
