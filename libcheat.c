#include "libcheat.h"

#include <stdlib.h>
#include <string.h>

#define CAPACITY_INIT      (32)
#define CAPACITY_INCREMENT (32)

// for internal use
enum {
    CR_MERGED = 100,
};

typedef struct cheat_t {
    // Callback functions
    cheat_addr_conv_t conv_cb;
    cheat_read_cb_t   read_cb;
    cheat_write_cb_t  write_cb;
    cheat_delay_cb_t  delay_cb;
    // allocator functions
    cheat_alloc_t     alloc_func;
    cheat_realloc_t   realloc_func;
    cheat_free_t      free_func;
    // code type
    uint8_t           type;
    // status 1-enable by default
    uint8_t           status;
    // game title id
    char              titleid[16];
    // valid code lines
    int               lines;
    // array capacity
    int               capacity;
    // cheat codes
    cheat_code_t      codes[];
} cheat_t;

static uint32_t default_conv_cb(uint32_t addr) {
    return addr;
}

static int default_read_cb(uint32_t addr, void *data, int len) {
    memcpy(data, (const void *)(uintptr_t)addr, len);
    return len;
}

static int default_write_cb(uint32_t addr, const void *data, int len) {
    memcpy((void *)(uintptr_t)addr, data, len);
    return len;
}


cheat_t *cheat_new(uint8_t type) {
    return cheat_new2(type, malloc, realloc, free);
}

cheat_t *cheat_new2(uint8_t type, cheat_alloc_t a, cheat_realloc_t r, cheat_free_t f) {
    cheat_t *ch = (cheat_t*)a(sizeof(cheat_t) + CAPACITY_INIT * sizeof(cheat_code_t));
    if (ch == NULL) return NULL;

    ch->conv_cb = NULL;
    ch->read_cb = NULL;
    ch->write_cb = NULL;
    ch->delay_cb = NULL;

    ch->alloc_func = a;
    ch->realloc_func = r;
    ch->free_func = f;

    ch->type = type;

    ch->titleid[0] = 0;
    ch->lines = 0;

    ch->capacity = CAPACITY_INIT;
    return ch;
}

void cheat_set_callbacks(cheat_t *ch, cheat_addr_conv_t conv_cb, cheat_read_cb_t read_cb, cheat_write_cb_t write_cb, cheat_delay_cb_t delay_cb) {
    ch->conv_cb = conv_cb;
    ch->read_cb = read_cb;
    ch->write_cb = write_cb;
    ch->delay_cb = delay_cb;
}

void cheat_finish(cheat_t *ch) {
    ch->free_func(ch);
}

uint8_t cheat_get_type(cheat_t *ch) {
    return ch->type;
}

const char *cheat_get_titleid(cheat_t *ch) {
    return ch->titleid;
}

void cheat_reset(cheat_t *ch) {
    ch->type = CH_UNKNOWN;
    ch->titleid[0] = 0;
    ch->lines = 0;
    if (ch->capacity > CAPACITY_INIT) {
        ch = (cheat_t*)ch->realloc_func(ch, sizeof(cheat_t) + CAPACITY_INIT * sizeof(cheat_code_t));
        ch->capacity = CAPACITY_INIT;
    }
}

static inline uint32_t get_code_value(const char *s) {
    if (s[0] == 0) return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    return (uint32_t)strtoul(s, NULL, 16);
}

static inline void parse_values(const char *s, uint32_t *val1, uint32_t *val2) {
    while (*s == ' ' || *s == '\t') ++s;            // skip spaces
    *val1 = get_code_value(s);
    while (*s != ' ' && *s != '\t' && *s != 0) ++s; // skip value
    while (*s == ' ' || *s == '\t') ++s;            // skip spaces
    *val2 = get_code_value(s);
}

static inline int add_cwcheat_code(cheat_t *ch, cheat_code_t *code, uint32_t val1, uint32_t val2) {
    if (ch->lines > 0) {
        cheat_code_t *last = &ch->codes[ch->lines - 1];
        if (last->extra > 0) {
            code->status = last->status;
            switch (last->op) {
                case CO_INCR:
                case CO_DECR:
                    last->extra = 0;
                    last->value = val1;
                    return CR_MERGED;
                case CO_MULWRITE:
                    code->op    = CO_MULWRITE;
                    code->type  = CT_I32;
                    code->extra = 0;
                    code->addr  = val1;
                    code->value = val2;
                    return CR_OK;
                case CO_MULWRITE2:
                    code->op    = CO_MULWRITE2;
                    code->extra = 0;
                    code->value = val2;
                    switch(val1 >> 28) {
                        case 0:
                            last->type = CT_I8;
                            code->type = CT_I8;
                            code->addr = val1 & 0xFFU;
                            break;
                        case 1:
                            last->type = CT_I16;
                            code->type = CT_I16;
                            code->addr = val1 & 0xFFFFU;
                            break;
                        default:
                            return CR_INVALID;
                    }
                    return CR_OK;
                case CO_PTRWRITE:
                    code->op    = CO_PTRWRITE;
                    code->addr  = 0;
                    code->extra = 0;
                    if ((val1 & 0xFFFFU) != 1) return CR_INVALID;
                    switch (val1 >> 16) {
                        case 0:
                            last->type  = CT_I8;
                            last->value &= 0xFFU;
                            code->type  = CT_I8;
                            code->value = val2;
                            break;
                        case 1:
                            last->type  = CT_I16;
                            last->value &= 0xFFFFU;
                            code->type  = CT_I16;
                            code->value = val2;
                            break;
                        case 2:
                            last->type  = CT_I32;
                            code->type  = CT_I32;
                            code->value = val2;
                            break;
                        case 3:
                            last->type  = CT_I8;
                            last->value &= 0xFFU;
                            code->type  = CT_I8;
                            code->value = ~(val2 - 1);
                            break;
                        case 4:
                            last->type  = CT_I16;
                            last->value &= 0xFFFFU;
                            code->type  = CT_I16;
                            code->value = ~(val2 - 1);
                            break;
                        case 5:
                            last->type  = CT_I32;
                            code->type  = CT_I32;
                            code->value = ~(val2 - 1);
                            break;
                        default:
                            return CR_INVALID;
                    }
                    return CR_OK;
            }
        }
    }
    switch(val1 >> 28) {
        case 0:
            code->op    = CO_WRITE;
            code->type  = CT_I8;
            code->extra = 0;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2 & 0xFFU;
            break;
        case 1:
            code->op    = CO_WRITE;
            code->type  = CT_I16;
            code->extra = 0;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2 & 0xFFFFU;
            break;
        case 2:
            code->op    = CO_WRITE;
            code->type  = CT_I32;
            code->extra = 0;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2;
            break;
        case 3:
            code->addr = val2 & 0x0FFFFFFFU;
            switch((val1 >> 20) & 0xFF) {
                case 1:
                    code->op    = CO_INCR;
                    code->type  = CT_I8;
                    code->extra = 0;
                    code->value = val1 & 0xFFU;
                    break;
                case 2:
                    code->op    = CO_DECR;
                    code->type  = CT_I8;
                    code->extra = 0;
                    code->value = val1 & 0xFFU;
                    break;
                case 3:
                    code->op    = CO_INCR;
                    code->type  = CT_I16;
                    code->extra = 0;
                    code->value = val1 & 0xFFFFU;
                    break;
                case 4:
                    code->op    = CO_DECR;
                    code->type  = CT_I16;
                    code->extra = 0;
                    code->value = val1 & 0xFFFFU;
                    break;
                case 5:
                    code->op    = CO_INCR;
                    code->type  = CT_I32;
                    code->extra = 1;
                    break;
                case 6:
                    code->op    = CO_DECR;
                    code->type  = CT_I32;
                    code->extra = 1;
                    break;
                default: return CR_INVALID;
            }
            break;
        case 4:
            code->op    = CO_MULWRITE;
            code->type  = CT_I32;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2;
            code->extra = 1;
            break;
        case 8:
            code->op    = CO_MULWRITE2;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2;
            code->extra = 1;
            break;
        case 6:
            code->op    = CO_PTRWRITE;
            code->type  = CT_I32;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2;
            code->extra = 1;
            break;
        case 7:
            code->addr  = val1 & 0x0FFFFFFFU;
            code->extra = 0;
            switch (val2 >> 16) {
                case 0:
                    code->op    = CO_BITOR;
                    code->type  = CT_I8;
                    code->value = val2 & 0xFFU;
                    break;
                case 1:
                    code->op    = CO_BITOR;
                    code->type  = CT_I16;
                    code->value = val2 & 0xFFFFU;
                    break;
                case 2:
                    code->op    = CO_BITAND;
                    code->type  = CT_I8;
                    code->value = val2 & 0xFFU;
                    break;
                case 3:
                    code->op    = CO_BITAND;
                    code->type  = CT_I16;
                    code->value = val2 & 0xFFFFU;
                    break;
                case 4:
                    code->op    = CO_BITXOR;
                    code->type  = CT_I8;
                    code->value = val2 & 0xFFU;
                    break;
                case 5:
                    code->op    = CO_BITXOR;
                    code->type  = CT_I16;
                    code->value = val2 & 0xFFFFU;
                    break;
            }
            break;
        case 0xB:
            code->op    = CO_DELAY;
            code->type  = CT_I32;
            code->extra = 0;
            code->addr  = 0;
            code->value = val2;
            break;
        case 0xC:
            code->op    = CO_STOPPER;
            code->type  = CT_I32;
            code->extra = 0;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2;
            break;
        default: return CR_INVALID;
    }
    return CR_OK;
}

int cheat_add(cheat_t *ch, const char *line) {
    cheat_code_t code;

    switch(ch->type) {
        case CH_CWCHEAT: {
            // parse the cheat code
            if (line[0] == 0) return CR_OK;
            if (line[0] != '_') return CR_INVALID;

            switch (line[1]) {
                case 'S':
                    line += 3;
                    while (*line == ' ' || *line == '\t') ++line;
                    strncpy(ch->titleid, line, 15);
                    ch->titleid[15] = 0;
                    return CR_OK;
                case 'G':
                    return CR_OK;
                case 'C':
                    ch->status = (line[2] > '0' && line[2] <= '9') ? 1 : 0;
                    return CR_OK;
                case 'L': {
                    uint32_t val1, val2;
                    parse_values(line + 3, &val1, &val2);
                    int r = add_cwcheat_code(ch, &code, val1, val2);
                    if (r == CR_MERGED) return CR_OK;
                    if (r != CR_OK) return r;
                    code.status = ch->status;
                    break;
                }
            }
            break;
        }
    }

    // check for capacity
    {
        int cap = ch->capacity;
        if (ch->lines >= cap) {
            cap += CAPACITY_INCREMENT;
            ch = (cheat_t*)ch->realloc_func(ch, sizeof(cheat_t) + cap * sizeof(cheat_code_t));
            ch->capacity = cap;
        }
    }
    // add code
    ch->codes[ch->lines++] = code;
    return code.extra ? CR_MORELINE : CR_OK;
}

void cheat_apply(cheat_t *ch) {

}

int cheat_get_codes(cheat_t *ch, cheat_code_t **codes) {
    *codes = ch->codes;
    return ch->lines;
}
