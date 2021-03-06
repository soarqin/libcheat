#include "libcheat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int a;
    int b;
    int c;
} test_level3;

typedef struct {
    int n[10];
    test_level3 *l3[5];
} test_level2;

typedef struct {
    int n[5];
    test_level2 *l2[5];
} test_level1;

typedef struct {
    int n[8];
    test_level1 *l1[5];
} test_level0;

static test_level0 *test_val, *test_val2, *test_val3[5];

static inline void* get_addr(uint32_t addr) {
    static uint32_t n[256] = {};
    if (addr == 0x1000000)
        n[8] = (uint32_t)(uintptr_t)&n[10];
    else if (addr == 0x1000001) {
        if (n[0] == 0) {
            n[8] = 0x87654321U;
            n[0] = 1;
        } else n[8] = 0;
    } else if (addr == 0x00008870) {
        return &test_val3[0];
    } else if (addr == 0x00008874) {
        return &test_val3[1];
    } else if (addr == 0x00008878) {
        return &test_val3[2];
    } else if (addr == 0x0000887C) {
        return &test_val3[3];
    } else if (addr == 0x00008880) {
        return &test_val3[4];
    } else if (addr == 0x00008884) {
        return &test_val2;
    } else if (addr == 0x00008888) {
        return &test_val;
    } else
        n[8] = (rand() & 0xFFFU) | ((rand() & 0xFFFU) << 12) | ((rand() & 0xFFU) << 24);
    return &n[8];
}

int read_cb(void *arg, uint32_t addr, void *data, int len, int need_conv) {
    void *paddr = need_conv ? get_addr(addr) : (void*)(uintptr_t)addr;
    memcpy(data, paddr, len);
    printf("Read %08X from %08X\n", *(uint32_t*)data, paddr);
}

int write_cb(void *arg, uint32_t addr, const void *data, int len, int need_conv) {
    void *paddr = need_conv ? get_addr(addr) : (void*)(uintptr_t)addr;
    printf("Write %08X to %08X\n", *(uint32_t*)data, paddr);
    memcpy(need_conv ? get_addr(addr) : (void*)(uintptr_t)addr, data, len);
}

int trans_cb(void *arg, uint32_t addr, uint32_t value, int len, int op, int need_conv) {
    void *paddr = need_conv ? get_addr(addr) : (void*)(uintptr_t)addr;
    uint32_t val;
    memcpy(&val, paddr, len);
    switch(op) {
        case 0:
            val += value; break;
        case 1:
            val -= value; break;
        case 2:
            val |= value; break;
        case 3:
            val &= value; break;
        case 4:
            val ^= value; break;
    }
    printf("Write transformed %08X to %08X\n", val, paddr);
    memcpy(paddr, &val, len);
}

int copy_cb(void *arg, uint32_t toaddr, uint32_t fromaddr, int len, int need_conv) {
    void *paddr1 = need_conv ? get_addr(toaddr) : (void*)(uintptr_t)toaddr;
    void *paddr2 = need_conv ? get_addr(fromaddr) : (void*)(uintptr_t)fromaddr;
    printf("Copying %d bytes from %08X to %08X\n", fromaddr, toaddr, len);
    memcpy(paddr1, paddr2, len);
}

static int input_cb(void *arg, uint32_t buttons) {
    printf("Checking button: %08X\n", buttons);
    return 1;
}

static void delay_cb(void *arg, uint32_t millisec) {
    printf("Delay: %d\n", millisec);
}

void dump_codes(cheat_t *ch) {
    const cheat_code_t *codes;
    const cheat_section_t *sections;
    int i, count;
    printf("%s %d\n", cheat_get_titleid(ch), cheat_get_type(ch));
    count = cheat_get_sections(ch, &sections);
    for (i = 0; i < count; ++i) {
        const cheat_section_t *s = &sections[i];
        printf(" %c%c %2d %4d %s\n", s->status & 4 ? '!' : ' ', s->status & 1 ? 'o' : 'x', s->index, s->code_index, s->name);
    }
    count = cheat_get_codes(ch, &codes);
    for (i = 0; i < count; ++i) {
        const cheat_code_t *c = &codes[i];
        printf("  %c %2d %2d %08X %08X\n", c->extra ? '+' : ' ', c->op, c->type, c->addr, c->value);
    }
}

int main() {
    test_val = (test_level0*)calloc(1, sizeof(test_level0));
    test_val->l1[0] = (test_level1*)calloc(1, sizeof(test_level1));
    test_val->l1[0]->l2[0] = (test_level2*)calloc(1, sizeof(test_level2));
    test_val->l1[0]->l2[0]->l3[0] = (test_level3*)calloc(1, sizeof(test_level3));
    test_val2 = (test_level0*)calloc(1, sizeof(test_level0));
    test_val2->l1[1] = (test_level1*)calloc(1, sizeof(test_level1));
    test_val2->l1[1]->l2[1] = (test_level2*)calloc(1, sizeof(test_level2));
    test_val2->l1[1]->l2[1]->l3[1] = (test_level3*)calloc(1, sizeof(test_level3));
    for (int h = 0; h < 5; ++h) {
        test_val3[h] = (test_level0*)calloc(1, sizeof(test_level0));
        for (int i = 0; i < 5; ++i) {
            test_val3[h]->l1[i] = (test_level1*)calloc(1, sizeof(test_level1));
            for (int j = 0; j < 5; ++j) {
                test_val3[h]->l1[i]->l2[j] = (test_level2*)calloc(1, sizeof(test_level2));
                for (int k = 0; k < 5; ++k) {
                    test_val3[h]->l1[i]->l2[j]->l3[k] = (test_level3*)calloc(1, sizeof(test_level3));
                }
            }
        }
    }

    cheat_t *ch = cheat_new(CH_CWCHEAT, NULL);
    cheat_set_read_cb(ch, read_cb);
    cheat_set_write_cb(ch, write_cb);
    cheat_set_trans_cb(ch, trans_cb);
    cheat_set_copy_cb(ch, copy_cb);
    cheat_set_button_cb(ch, input_cb);
    cheat_set_delay_cb(ch, delay_cb);

    cheat_add(ch, "_S PCSH10003");
    cheat_add(ch, "_G Dynasty Warriors NEXT");
    cheat_add(ch, "_C1 Section1");

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

    cheat_add(ch, "_C3 Section2");
    cheat_add(ch, "_L 0x61000000 0x12345678");
    cheat_add(ch, "_L 0x00000001 0x00000004");
    cheat_add(ch, "_L 0x61000000 0x12345678");
    cheat_add(ch, "_L 0x00010001 0x00000004");
    cheat_add(ch, "_L 0x61000000 0x12345678");
    cheat_add(ch, "_L 0x00020001 0x00000004");
    cheat_add(ch, "_L 0x61000000 0x12345678");
    cheat_add(ch, "_L 0x00030001 0x00000004");
    cheat_add(ch, "_L 0x61000000 0x12345678");
    cheat_add(ch, "_L 0x00040001 0x00000004");
    cheat_add(ch, "_L 0x61000000 0x12345678");
    cheat_add(ch, "_L 0x00050001 0x00000004");
    cheat_add(ch, "_L 0x71234567 0x00001234");
    cheat_add(ch, "_L 0x71234567 0x00011234");
    cheat_add(ch, "_L 0x71234567 0x00021234");
    cheat_add(ch, "_L 0x71234567 0x00031234");
    cheat_add(ch, "_L 0x71234567 0x00041234");
    cheat_add(ch, "_L 0x71234567 0x00051234");

    cheat_add(ch, "_L 0xB0000000 0x000001F4");
    cheat_add(ch, "_L 0xC1000001 0x87654321");

    cheat_add(ch, "_L 0xD0000000 0x100000FF");
    cheat_add(ch, "_L 0x01234567 0x00000010");
    cheat_add(ch, "_L 0xD0000000 0x300000FF");
    cheat_add(ch, "_L 0x01234567 0x00000011");

    cheat_add(ch, "_L 0xD1234567 0x00001234");
    cheat_add(ch, "_L 0x01234567 0x00000012");
    cheat_add(ch, "_L 0xD1234567 0x00101234");
    cheat_add(ch, "_L 0x12345678 0x00001234");
    cheat_add(ch, "_L 0xD1234567 0x00201234");
    cheat_add(ch, "_L 0x23456789 0x12345678");
    cheat_add(ch, "_L 0xD1234567 0x00301234");
    cheat_add(ch, "_L 0x01234567 0x00000020");
    cheat_add(ch, "_L 0xD1234567 0x20001234");
    cheat_add(ch, "_L 0x01234567 0x00000021");
    cheat_add(ch, "_L 0xD1234567 0x20101234");
    cheat_add(ch, "_L 0x01234567 0x00000022");
    cheat_add(ch, "_L 0xD1234567 0x20201234");
    cheat_add(ch, "_L 0x01234567 0x00000023");
    cheat_add(ch, "_L 0xD1234567 0x20301234");
    cheat_add(ch, "_L 0x01234567 0x00000024");

    cheat_add(ch, "_L 0xD1234567 0x47654321");
    cheat_add(ch, "_L 0x00000001 0x00000000");
    cheat_add(ch, "_L 0x01234567 0x00000025");
    cheat_add(ch, "_L 0xD1234567 0x47654321");
    cheat_add(ch, "_L 0x00000001 0x00000001");
    cheat_add(ch, "_L 0x01234567 0x00000026");
    cheat_add(ch, "_L 0xD1234567 0x47654321");
    cheat_add(ch, "_L 0x00000001 0x00000002");
    cheat_add(ch, "_L 0x01234567 0x00000027");
    cheat_add(ch, "_L 0xD1234567 0x57654321");
    cheat_add(ch, "_L 0x00000001 0x00000000");
    cheat_add(ch, "_L 0x01234567 0x00000028");
    cheat_add(ch, "_L 0xD1234567 0x57654321");
    cheat_add(ch, "_L 0x00000001 0x00000001");
    cheat_add(ch, "_L 0x01234567 0x00000029");
    cheat_add(ch, "_L 0xD1234567 0x57654321");
    cheat_add(ch, "_L 0x00000001 0x00000002");
    cheat_add(ch, "_L 0x01234567 0x0000002A");
    cheat_add(ch, "_L 0xD1234567 0x67654321");
    cheat_add(ch, "_L 0x00000001 0x00000000");
    cheat_add(ch, "_L 0x01234567 0x0000002B");
    cheat_add(ch, "_L 0xD1234567 0x67654321");
    cheat_add(ch, "_L 0x00000001 0x00000001");
    cheat_add(ch, "_L 0x01234567 0x0000002C");
    cheat_add(ch, "_L 0xD1234567 0x67654321");
    cheat_add(ch, "_L 0x00000001 0x00000002");
    cheat_add(ch, "_L 0x01234567 0x0000002D");
    cheat_add(ch, "_L 0xD1234567 0x77654321");
    cheat_add(ch, "_L 0x00000001 0x00000000");
    cheat_add(ch, "_L 0x01234567 0x0000002E");
    cheat_add(ch, "_L 0xD1234567 0x77654321");
    cheat_add(ch, "_L 0x00000001 0x00000001");
    cheat_add(ch, "_L 0x01234567 0x0000002F");
    cheat_add(ch, "_L 0xD1234567 0x77654321");
    cheat_add(ch, "_L 0x00000001 0x00000002");
    cheat_add(ch, "_L 0x01234567 0x00000030");

    cheat_add(ch, "_L 0xE0018765 0x01234567");
    cheat_add(ch, "_L 0x01234567 0x00000031");
    cheat_add(ch, "_L 0xE0018765 0x11234567");
    cheat_add(ch, "_L 0x01234567 0x00000032");
    cheat_add(ch, "_L 0xE0018765 0x21234567");
    cheat_add(ch, "_L 0x01234567 0x00000033");
    cheat_add(ch, "_L 0xE0018765 0x31234567");
    cheat_add(ch, "_L 0x01234567 0x00000034");
    cheat_add(ch, "_L 0xE1018765 0x01234567");
    cheat_add(ch, "_L 0x01234567 0x00000035");
    cheat_add(ch, "_L 0xE1018765 0x11234567");
    cheat_add(ch, "_L 0x01234567 0x00000036");
    cheat_add(ch, "_L 0xE1018765 0x21234567");
    cheat_add(ch, "_L 0x01234567 0x00000037");
    cheat_add(ch, "_L 0xE1018765 0x31234567");
    cheat_add(ch, "_L 0x01234567 0x00000038");

    cheat_add(ch, "_L 0x90008888 0x20000004");
    cheat_add(ch, "_L 0x00000020 0x00000000");
    cheat_add(ch, "_L 0x00000014 0x00000000");
    cheat_add(ch, "_L 0x00000028 0x00000000");
    cheat_add(ch, "_L 0x00000008 0x0000F00D");

    cheat_add(ch, "_L 0x90008884 0x21000005");
    cheat_add(ch, "_L 0x00008888 0x00000000");
    cheat_add(ch, "_L 0x00000024 0x00000020");
    cheat_add(ch, "_L 0x00000018 0x00000014");
    cheat_add(ch, "_L 0x0000002C 0x00000028");
    cheat_add(ch, "_L 0x00000004 0x00000008");

    cheat_add(ch, "_L 0x90008870 0x22000505");
    cheat_add(ch, "_L 0x00000020 0x00000000");
    cheat_add(ch, "_L 0x00000014 0x00000000");
    cheat_add(ch, "_L 0x00000028 0x00000000");
    cheat_add(ch, "_L 0x00000004 0x0000F00D");
    cheat_add(ch, "_L 0x03000004 0x00000028");

    dump_codes(ch);

    printf("First pass\n");
    cheat_apply(ch);
    printf("%X %X\n", test_val->l1[0]->l2[0]->l3[0]->c, test_val2->l1[1]->l2[1]->l3[1]->b);
    for (int i = 0; i < 5; ++i) {
        printf("%X\n", test_val3[0]->l1[0]->l2[0]->l3[i]->b);
    }
    printf("Second pass\n");
    cheat_apply(ch);
    cheat_section_toggle(ch, 1, 0);
    cheat_section_toggle(ch, 1, 1);
    printf("Third pass\n");
    cheat_apply(ch);

    cheat_finish(ch);

    for (int h = 0; h < 5; ++h) {
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < 5; ++j) {
                for (int k = 0; k < 5; ++k) {
                    free(test_val3[h]->l1[i]->l2[j]->l3[k]);
                }
                free(test_val3[h]->l1[i]->l2[j]);
            }
            free(test_val3[h]->l1[i]);
        }
        free(test_val3[h]);
    }
    free(test_val2->l1[1]->l2[1]->l3[1]);
    free(test_val2->l1[1]->l2[1]);
    free(test_val2->l1[1]);
    free(test_val2);
    free(test_val->l1[0]->l2[0]->l3[0]);
    free(test_val->l1[0]->l2[0]);
    free(test_val->l1[0]);
    free(test_val);

    return 0;
}
