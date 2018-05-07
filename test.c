#include "libcheat.h"

#include <stdio.h>

static uint32_t conv_cb(uint32_t addr) {
    return addr;
}

static int read_cb(uint32_t addr, void *data, int len) {
}

static int write_cb(uint32_t addr, const void *data, int len) {
}

void dump_codes(cheat_t *ch) {
    cheat_code_t *codes;
    int i, count;
    printf("%s %d\n", cheat_get_titleid(ch), cheat_get_type(ch));
    count = cheat_get_codes(ch, &codes);
    for (i = 0; i < count; ++i) {
        cheat_code_t *c = &codes[i];
        printf("  %c%c %2d %2d %08X %08X\n", c->status ? 'o' : 'x', c->extra ? '+' : ' ', c->op, c->type, c->addr, c->value);
    }
}

int main() {
    cheat_t *ch = cheat_new(CH_CWCHEAT);
    cheat_set_callbacks(ch, conv_cb, read_cb, write_cb);
    cheat_add(ch, "_S PCSH10003");
    cheat_add(ch, "_G Dynasty Warriors NEXT");
    cheat_add(ch, "_C1");
    cheat_add(ch, "_L 0x01234567 0x00000012");
    cheat_add(ch, "_L 0x12345678 0x00001234");
    cheat_add(ch, "_L 0x23456789 0x12345678");

    cheat_add(ch, "_L 0x30100012 0x01234567");
    cheat_add(ch, "_L 0x30200012 0x01234567");
    cheat_add(ch, "_L 0x30301234 0x01234567");
    cheat_add(ch, "_L 0x30403412 0x01234567");

    cheat_add(ch, "_L 0x30500000 0x01234567");
    cheat_add(ch, "_L 0x12345678 0x00000000");
    cheat_add(ch, "_L 0x30600000 0x01234567");
    cheat_add(ch, "_L 0x12345678 0x00000000");

    cheat_add(ch, "_L 0x41234567 0x00040020");
    cheat_add(ch, "_L 0x12345678 0x00000008");
    cheat_add(ch, "_L 0x81234567 0x00040020");
    cheat_add(ch, "_L 0x02345678 0x00000008");
    cheat_add(ch, "_L 0x81234567 0x00040020");
    cheat_add(ch, "_L 0x12345678 0x00000008");

    cheat_add(ch, "_L 0x61234567 0x12345678");
    cheat_add(ch, "_L 0x00000001 0x23104867");
    cheat_add(ch, "_L 0x61234567 0x12345678");
    cheat_add(ch, "_L 0x00010001 0x23104867");
    cheat_add(ch, "_L 0x61234567 0x12345678");
    cheat_add(ch, "_L 0x00020001 0x23104867");
    cheat_add(ch, "_L 0x61234567 0x12345678");
    cheat_add(ch, "_L 0x00030001 0x23104867");
    cheat_add(ch, "_L 0x61234567 0x12345678");
    cheat_add(ch, "_L 0x00040001 0x23104867");
    cheat_add(ch, "_L 0x61234567 0x12345678");
    cheat_add(ch, "_L 0x00050001 0x23104867");
    cheat_add(ch, "_L 0x71234567 0x00001234");
    cheat_add(ch, "_L 0x71234567 0x00011234");
    cheat_add(ch, "_L 0x71234567 0x00021234");
    cheat_add(ch, "_L 0x71234567 0x00031234");
    cheat_add(ch, "_L 0x71234567 0x00041234");
    cheat_add(ch, "_L 0x71234567 0x00051234");

    cheat_add(ch, "_L 0xB0000000 0x000001F4");
    cheat_add(ch, "_L 0xC1234567 0x87654321");

    dump_codes(ch);

    cheat_finish(ch);

    return 0;
}
