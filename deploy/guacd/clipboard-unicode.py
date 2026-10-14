#!/usr/bin/env python3
"""Correct Guacamole 1.6.0's UCS-2 conversion for RDP Unicode clipboard."""
import re,sys
from pathlib import Path

path=Path(sys.argv[1])/'src/common/iconv.c'
source=path.read_text()
reader='''int GUAC_READ_UTF16(const char** input, int remaining) {
    if (remaining < 2)
        return 0;
    const unsigned char* bytes = (const unsigned char*) *input;
    int value = bytes[0] | (bytes[1] << 8);
    *input += 2;
    if (value >= 0xD800 && value <= 0xDBFF) {
        if (remaining >= 4) {
            int low = bytes[2] | (bytes[3] << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                *input += 2;
                return 0x10000 + ((value - 0xD800) << 10) + low - 0xDC00;
            }
        }
        return 0xFFFD;
    }
    return value >= 0xDC00 && value <= 0xDFFF ? 0xFFFD : value;
}'''
writer='''void GUAC_WRITE_UTF16(char** output, int remaining, int value) {
    if (value < 0 || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF))
        value = 0xFFFD;
    int length = value > 0xFFFF ? 4 : 2;
    if (remaining < length)
        return;
    unsigned char* bytes = (unsigned char*) *output;
    if (value > 0xFFFF) {
        int high = 0xD800 | ((value - 0x10000) >> 10);
        int low = 0xDC00 | ((value - 0x10000) & 0x3FF);
        bytes[0] = high & 0xFF;
        bytes[1] = high >> 8;
        bytes[2] = low & 0xFF;
        bytes[3] = low >> 8;
    }
    else {
        bytes[0] = value & 0xFF;
        bytes[1] = value >> 8;
    }
    *output += length;
}'''
for signature,replacement in [('int GUAC_READ_UTF16',reader),('void GUAC_WRITE_UTF16',writer)]:
    source,count=re.subn(re.escape(signature)+r'\([^)]*\) \{.*?\n\}',lambda _:replacement,source,flags=re.S)
    assert count==1,'unexpected official iconv source'
path.write_text(source)

# Reserve the terminating NUL and worst-case UTF-16/CRLF expansion at the public 256 KiB limit.
header=Path(sys.argv[1])/'src/common/common/clipboard.h'
text=header.read_text();old='#define GUAC_COMMON_CLIPBOARD_MAX_LENGTH 262144'
assert text.count(old)==1
header.write_text(text.replace(old,'#define GUAC_COMMON_CLIPBOARD_MAX_LENGTH (262144 + 1)'))
channel=Path(sys.argv[1])/'src/protocols/rdp/channels/cliprdr.c'
text=channel.read_text()
for old,new in [
    ('char* output = guac_mem_alloc(GUAC_COMMON_CLIPBOARD_MAX_LENGTH);',
     'char* output = guac_mem_alloc(GUAC_COMMON_CLIPBOARD_MAX_LENGTH * 4 + 2);'),
    ('remote_writer, &output, GUAC_COMMON_CLIPBOARD_MAX_LENGTH);',
     'remote_writer, &output, GUAC_COMMON_CLIPBOARD_MAX_LENGTH * 4 + 2);')]:
    assert text.count(old)==1,'unexpected official RDP clipboard source'
    text=text.replace(old,new)
channel.write_text(text)
