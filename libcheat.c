#include "libcheat.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CAPACITY_INIT      (32)
#define CAPACITY_INCREMENT (32)

// for internal use
enum {
    CR_MERGED = 100,
};

typedef struct cheat_t {
    // Callback functions
    cheat_get_addr_t  addr_cb;
    cheat_is_pressed  input_cb;
    cheat_delay_cb_t  delay_cb;
    // allocator functions
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
    cheat_code_t      *codes;
} cheat_t;

cheat_t *cheat_new(uint8_t type) {
    return cheat_new2(type, realloc, free);
}

cheat_t *cheat_new2(uint8_t type, cheat_realloc_t r, cheat_free_t f) {
    cheat_t *ch = (cheat_t*)r(NULL, sizeof(cheat_t));
    if (ch == NULL) return NULL;
    ch->codes = (cheat_code_t*)r(NULL, CAPACITY_INIT * sizeof(cheat_code_t));

    ch->addr_cb  = NULL;
    ch->input_cb = NULL;
    ch->delay_cb = NULL;

    ch->realloc_func = r;
    ch->free_func = f;

    ch->type = type;

    ch->titleid[0] = 0;
    ch->lines = 0;

    ch->capacity = CAPACITY_INIT;
    return ch;
}

void cheat_set_callbacks(cheat_t *ch, cheat_get_addr_t addr_cb, cheat_is_pressed input_cb, cheat_delay_cb_t delay_cb) {
    ch->addr_cb  = addr_cb;
    ch->input_cb = input_cb;
    ch->delay_cb = delay_cb;
}

void cheat_finish(cheat_t *ch) {
    ch->lines = 0;
    ch->free_func(ch->codes);
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
        ch->codes = (cheat_code_t*)ch->realloc_func(ch->codes, CAPACITY_INIT * sizeof(cheat_code_t));
        ch->capacity = CAPACITY_INIT;
    }
}

int cheat_get_codes(cheat_t *ch, cheat_code_t **codes) {
    *codes = ch->codes;
    return ch->lines;
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
            code->op     = CO_DATA;
            code->status = last->status;
            code->extra = 0;
            switch (last->op) {
                case CO_INCR:
                case CO_DECR:
                    last->value = val1;
                    code->addr  = 0;
                    code->value = 0;
                    return CR_MERGED;
                case CO_MULWRITE:
                    code->type  = CT_I32;
                    code->addr  = val1;
                    code->value = val2;
                    return CR_OK;
                case CO_MULWRITE2:
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
                case CO_COPY:
                    code->type  = CT_NONE;
                    code->addr  = val1;
                    code->value = 0;
                    return CR_OK;
                case CO_PTRWRITE:
                    code->addr  = 0;
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
                        default: return CR_INVALID;
                    }
                    return CR_OK;
                case CO_IFEQUAL:
                case CO_IFNEQUAL:
                case CO_IFLESS:
                case CO_IFGREATER:
                    switch (val2 & 0x0F) {
                        case 0:
                            last->type = code->type = CT_I8;
                            break;
                        case 1:
                            last->type = code->type = CT_I16;
                            break;
                        case 2:
                            last->type = code->type = CT_I32;
                            break;
                        default: return CR_INVALID;
                    }
                    code->addr  = 0;
                    code->value = val1 & 0xFFU;
                    return CR_OK;
                default: return CR_INVALID;
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
            code->type  = CT_NONE;
            code->addr  = val1 & 0x0FFFFFFFU;
            code->value = val2;
            code->extra = 1;
            break;
        case 5:
            code->op    = CO_COPY;
            code->type  = CT_NONE;
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
            code->type  = CT_NONE;
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
        case 0x0D:
            switch (val2 >> 28) {
                case 1:
                case 3:
                    code->op    = (val2 >> 28) == 1 ? CO_PRESSED : CO_NOTPRESSED;
                    code->type  = CT_NONE;
                    code->extra = 0;
                    code->addr  = (val1 & 0xFFU) + 1;
                    code->value = val2 & 0x0FFFFFFFU;
                    break;
                case 0:
                case 2:
                    switch ((val2 >> 20) & 0x0F) {
                        case 0:
                            code->op = CO_IFEQUAL;
                            break;
                        case 1:
                            code->op = CO_IFNEQUAL;
                            break;
                        case 2:
                            code->op = CO_IFLESS;
                            break;
                        case 3:
                            code->op = CO_IFGREATER;
                            break;
                        default:
                            return CR_INVALID;
                    }
                    code->extra = 0;
                    code->addr = val1 & 0x0FFFFFFFU;
                    if ((val2 >> 28) == 0) {
                        code->type  = CT_I16;
                        code->value = 0x10000 | (val2 & 0xFFFFU);
                    } else {
                        code->type = CT_I8;
                        code->value = 0x10000 | (val2 & 0xFFU);
                    }
                    break;
                case 4:
                case 5:
                case 6:
                case 7:
                    switch (val2 >> 28) {
                        case 4:
                            code->op = CO_IFEQUAL;
                            break;
                        case 5:
                            code->op = CO_IFNEQUAL;
                            break;
                        case 6:
                            code->op = CO_IFLESS;
                            break;
                        case 7:
                            code->op = CO_IFGREATER;
                            break;
                    }
                    code->type  = CT_I32;
                    code->extra = 1;
                    code->addr  = val1 & 0x0FFFFFFFU;
                    code->value = val2 & 0x0FFFFFFFU;
                    break;
                default: return CR_INVALID;
            }
            break;
        case 0x0E:
            switch (val2 >> 28) {
                case 0:
                    code->op = CO_IFEQUAL;
                    break;
                case 1:
                    code->op = CO_IFNEQUAL;
                    break;
                case 2:
                    code->op = CO_IFLESS;
                    break;
                case 3:
                    code->op = CO_IFGREATER;
                    break;
                default: return CR_INVALID;
            }
            switch((val1 >> 24) & 0x0F) {
                case 0:
                    code->type  = CT_I16;
                    code->value = val1 & 0x00FFFFFFU;
                    break;
                case 1:
                    code->type  = CT_I8;
                    code->value = val1 & 0x00FF00FFU;
                    break;
                default: return CR_INVALID;
            }
            code->extra = 0;
            code->addr  = val2 & 0x0FFFFFFFU;
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
                    code.status = ch->status;
                    if (r == CR_MERGED) break;
                    if (r != CR_OK) return r;
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
            ch->codes = (cheat_code_t*)ch->realloc_func(ch->codes, cap * sizeof(cheat_code_t));
            ch->capacity = cap;
        }
    }
    // add code
    ch->codes[ch->lines++] = code;
    return code.extra ? CR_MORELINE : CR_OK;
}

static inline void _set_value(void *addr, uint8_t type, uint32_t value) {
    switch(type) {
        case CT_I8:
            memcpy(addr, &value, 1);
            break;
        case CT_I16:
            memcpy(addr, &value, 2);
            break;
        case CT_I32:
            memcpy(addr, &value, 4);
            break;
    }
}

void cheat_apply(cheat_t *ch) {
    int i;
    int e = ch->lines;
    for(i = 0; i < e; ++i) {
        cheat_code_t *c = &ch->codes[i];
        i += c->extra;

#define REAL_ADDR(addr, oaddr) void *(addr) = ch->addr_cb ? ch->addr_cb((oaddr), 1) : (void*)(oaddr); if ((addr) == NULL) continue
#define REAL_ADDR_RETURN(addr, oaddr) void *(addr) = ch->addr_cb ? ch->addr_cb((oaddr), 1) : (void*)(oaddr); if ((addr) == NULL) return
#define UNREAL_ADDR(addr, raddr) void *(addr) = ch->addr_cb ? ch->addr_cb((raddr), 0) : (void*)(raddr); if ((addr) == NULL) continue
        switch(c->op) {
            case CO_WRITE: {
                REAL_ADDR(addr, c->addr);
                _set_value(addr, c->type, c->value);
                break;
            }
            case CO_INCR: {
                REAL_ADDR(addr, c->addr);
                switch(c->type) {
                case CT_I8:
                    _set_value(addr, CT_I8, *(uint8_t*)addr + c->value);
                    break;
                case CT_I16:
                    _set_value(addr, CT_I16, *(uint16_t*)addr + c->value);
                    break;
                case CT_I32:
                    _set_value(addr, CT_I32, *(uint32_t*)addr + c->value);
                    break;
                }
                break;
            }
            case CO_DECR: {
                REAL_ADDR(addr, c->addr);
                switch(c->type) {
                case CT_I8:
                    _set_value(addr, CT_I8, *(uint8_t*)addr - c->value);
                    break;
                case CT_I16:
                    _set_value(addr, CT_I16, *(uint16_t*)addr - c->value);
                    break;
                case CT_I32:
                    _set_value(addr, CT_I32, *(uint32_t*)addr - c->value);
                    break;
                }
                break;
            }
            case CO_MULWRITE: {
                if (i >= e) continue;
                cheat_code_t *c2 = &ch->codes[i];
                REAL_ADDR(addr, c->addr);
                uint32_t *addr_s = (uint32_t*)addr;
                uint32_t count = c->value >> 16;
                uint32_t off = c->value & 0xFFFFU;
                uint32_t value = c2->addr;
                uint32_t incr = c2->value;
                uint32_t i;
                for (i = 0; i < count; ++i) {
                    _set_value(addr_s, CT_I32, value);
                    addr_s += off;
                    value += incr;
                }
                break;
            }
            case CO_MULWRITE2: {
                if (i >= e) continue;
                cheat_code_t *c2 = &ch->codes[i];
                REAL_ADDR(addr, c->addr);
                uint32_t count = c->value >> 16;
                uint32_t off = c->value & 0xFFFFU;
                uint32_t value = c2->addr;
                uint32_t incr = c2->value;
                uint32_t i;
                switch (c->type) {
                    case CT_I8: {
                        uint8_t *addr_s = (uint8_t*)addr;
                        for (i = 0; i < count; ++i) {
                            _set_value(addr_s, CT_I8, value);
                            addr_s += off;
                            value += incr;
                        }
                        break;
                    }
                    case CT_I16: {
                        uint16_t *addr_s = (uint16_t*)addr;
                        for (i = 0; i < count; ++i) {
                            _set_value(addr_s, CT_I16, value);
                            addr_s += off;
                            value += incr;
                        }
                        break;
                    }
                }
                break;
            }
            case CO_COPY: {
                if (i >= e) continue;
                cheat_code_t *c2 = &ch->codes[i];
                REAL_ADDR(addr, c->addr);
                REAL_ADDR(addr2, c2->addr);
                memcpy(addr, addr2, c->value);
                break;
            }
            case CO_PTRWRITE: {
                if (i >= e) continue;
                cheat_code_t *c2 = &ch->codes[i];
                REAL_ADDR(addr, c->addr);
                UNREAL_ADDR(addr2, *(uint32_t*)addr);
                _set_value((uint8_t*)addr2 + c2->value, c->type, c->value);
                break;
            }
            case CO_BITOR: {
                REAL_ADDR(addr, c->addr);
                switch (c->type) {
                    case CT_I8:
                        _set_value(addr, CT_I8, *(uint8_t*)addr | c->value);
                        break;
                    case CT_I16:
                        _set_value(addr, CT_I16, *(uint16_t*)addr | c->value);
                        break;
                    case CT_I32:
                        _set_value(addr, CT_I32, *(uint32_t*)addr | c->value);
                        break;
                }
                break;
            }
            case CO_BITAND: {
                REAL_ADDR(addr, c->addr);
                switch (c->type) {
                    case CT_I8:
                        _set_value(addr, CT_I8, *(uint8_t*)addr & c->value);
                        break;
                    case CT_I16:
                        _set_value(addr, CT_I16, *(uint16_t*)addr & c->value);
                        break;
                    case CT_I32:
                        _set_value(addr, CT_I32, *(uint32_t*)addr & c->value);
                        break;
                }
                break;
            }
            case CO_BITXOR: {
                REAL_ADDR(addr, c->addr);
                switch (c->type) {
                    case CT_I8:
                        _set_value(addr, CT_I8, *(uint8_t*)addr ^ c->value);
                        break;
                    case CT_I16:
                        _set_value(addr, CT_I16, *(uint16_t*)addr ^ c->value);
                        break;
                    case CT_I32:
                        _set_value(addr, CT_I32, *(uint32_t*)addr ^ c->value);
                        break;
                }
                break;
            }
            case CO_DELAY: {
                if (ch->delay_cb) ch->delay_cb(c->value);
                break;
            }
            case CO_STOPPER: {
                REAL_ADDR_RETURN(addr, c->addr);
                if (*(uint32_t*)addr != c->value) i = e;
                break;
            }
            case CO_PRESSED: {
                if (!ch->input_cb || !ch->input_cb(c->value))
                    i += c->addr;
                break;
            }
            case CO_NOTPRESSED: {
                if (!ch->input_cb || ch->input_cb(c->value))
                    i += c->addr;
                break;
            }
            case CO_IFEQUAL:
            case CO_IFNEQUAL:
            case CO_IFLESS:
            case CO_IFGREATER: {
                uint32_t skip;
                uint32_t value;
                uint32_t cvalue;
                REAL_ADDR_RETURN(addr, c->addr);
                if (c->extra) {
                    if (i >= e) continue;
                    cheat_code_t *c2 = &ch->codes[i];
                    skip = c2->value;
                    value = c->value;
                } else {
                    skip = c->value >> 16;
                    value = c->value & 0xFFFFU;
                }
                switch(c->type) {
                    case CT_I8:
                        cvalue = *(uint8_t*)addr;
                        break;
                    case CT_I16:
                        cvalue = *(uint16_t*)addr;
                        break;
                    case CT_I32:
                        cvalue = *(uint32_t*)addr;
                        break;
                }
                switch(c->op) {
                    case CO_IFEQUAL:
                        if (cvalue != value) i += skip;
                        break;
                    case CO_IFNEQUAL:
                        if (cvalue == value) i += skip;
                        break;
                    case CO_IFLESS:
                        if (cvalue >= value) i += skip;
                        break;
                    case CO_IFGREATER:
                        if (cvalue <= value) i += skip;
                        break;
                }
                break;
            }
            default: continue;
        }
#undef REAL_ADDR_RETURN
#undef REAL_ADDR
#undef UNREAL_ADDR
    }
}
