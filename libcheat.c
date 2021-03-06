#include "libcheat.h"

#include <stdlib.h>
#include <string.h>

#define CODES_CAP_INIT      (32)
#define CODES_CAP_INCREMENT (32)
#define CODES_MAX           (4000)
#define SECTIONS_CAP_INIT      (8)
#define SECTIONS_CAP_INCREMENT (8)
#define SECTIONS_MAX           (240)

// for internal use
enum {
    CR_MERGED = 100,
};

typedef struct cheat_t {
    // pass-over argument for callbacks
    void *arg;

    // Callback functions
    cheat_read_cb_t     read_cb;
    cheat_write_cb_t    write_cb;
    cheat_copy_cb_t     copy_cb;
    cheat_trans_cb_t    trans_cb;
    cheat_button_cb_t   input_cb;
    cheat_delay_cb_t    delay_cb;
    cheat_ext_cb_t      ext_cb;
    cheat_ext_call_cb_t ext_call_cb;

    // allocator functions
    cheat_realloc_t realloc_func;
    cheat_free_t    free_func;

    // code type
    uint8_t type;
    // game title id
    char    titleid[16];

    // count of valid codes
    uint16_t     codes_count;
    // codes array capacity
    uint16_t     codes_cap;
    // cheat codes
    cheat_code_t *codes;

    // count of code sections
    uint8_t         sections_count;
    // sections array capacity
    uint8_t         sections_cap;
    // sections array
    cheat_section_t *sections;
} cheat_t;

int default_read_cb(void *arg, uint32_t addr, void *data, int len, int need_conv) {
    return -1;
}

int default_write_cb(void *arg, uint32_t addr, const void *data, int len, int need_conv) {
    return -1;
}

int default_trans_cb(void *arg, uint32_t addr, uint32_t value, int len, int op, int need_conv) {
    return -1;
}

int default_copy_cb(void *arg, uint32_t toaddr, uint32_t fromaddr, int len, int need_conv) {
    return -1;
}

int default_button_cb(void *arg, uint32_t buttons) {
    return 0;
}

void default_delay_cb(void *arg, uint32_t millisec) {
}

int default_ext_cb(void *arg, cheat_code_t *code, const char *op, uint32_t val1, uint32_t val2) {
    return CR_INVALID;
}

int default_ext_call_cb(void *arg, int line, const cheat_code_t *code) {
    return CR_INVALID;
}

cheat_t *cheat_new(uint8_t type, void *arg) {
    return cheat_new2(type, realloc, free, arg);
}

cheat_t *cheat_new2(uint8_t type, cheat_realloc_t r, cheat_free_t f, void *arg) {
    cheat_t *ch = (cheat_t*)r(NULL, sizeof(cheat_t));
    if (ch == NULL) return NULL;
    ch->arg = arg;
    ch->codes = (cheat_code_t*)r(NULL, CODES_CAP_INIT * sizeof(cheat_code_t));
    ch->sections = (cheat_section_t*)r(NULL, SECTIONS_CAP_INIT * sizeof(cheat_section_t));

    ch->read_cb  = default_read_cb;
    ch->write_cb = default_write_cb;
    ch->trans_cb = default_trans_cb;
    ch->copy_cb  = default_copy_cb;
    ch->input_cb = default_button_cb;
    ch->delay_cb = default_delay_cb;
    ch->ext_cb   = default_ext_cb;

    ch->realloc_func = r;
    ch->free_func    = f;

    ch->type = type;

    ch->titleid[0] = 0;

    ch->codes_count = 0;
    ch->codes_cap   = CODES_CAP_INIT;

    ch->sections_count = 0;
    ch->sections_cap   = SECTIONS_CAP_INIT;
    return ch;
}

void cheat_set_read_cb(cheat_t *ch, cheat_read_cb_t cb) {
    if (cb == NULL)
        ch->read_cb = default_read_cb;
    else
        ch->read_cb = cb;
}

void cheat_set_write_cb(cheat_t *ch, cheat_write_cb_t cb) {
    if (cb == NULL)
        ch->write_cb = default_write_cb;
    else
        ch->write_cb = cb;
}

void cheat_set_trans_cb(cheat_t *ch, cheat_trans_cb_t cb) {
    if (cb == NULL)
        ch->trans_cb = default_trans_cb;
    else
        ch->trans_cb = cb;
}

void cheat_set_copy_cb(cheat_t *ch, cheat_copy_cb_t cb) {
    if (cb == NULL)
        ch->copy_cb = default_copy_cb;
    else
        ch->copy_cb = cb;
}

void cheat_set_button_cb(cheat_t *ch, cheat_button_cb_t cb) {
    if (cb == NULL)
        ch->input_cb = default_button_cb;
    else
        ch->input_cb = cb;
}

void cheat_set_delay_cb(cheat_t *ch, cheat_delay_cb_t cb) {
    if (cb == NULL)
        ch->delay_cb = default_delay_cb;
    else
        ch->delay_cb = cb;
}

void cheat_set_ext_cb(cheat_t *ch, cheat_ext_cb_t cb) {
    if (cb == NULL)
        ch->ext_cb = default_ext_cb;
    else
        ch->ext_cb = cb;
}

void cheat_set_ext_call_cb(cheat_t *ch, cheat_ext_call_cb_t cb) {
    if (cb == NULL)
        ch->ext_call_cb = default_ext_call_cb;
    else
        ch->ext_call_cb = cb;
}

void cheat_finish(cheat_t *ch) {
    ch->codes_count = 0;
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
    ch->codes_count = 0;
    if (ch->codes_cap > CODES_CAP_INIT) {
        ch->codes = (cheat_code_t*)ch->realloc_func(ch->codes, CODES_CAP_INIT * sizeof(cheat_code_t));
        ch->codes_cap = CODES_CAP_INIT;
    }

    ch->sections_count = 0;
    if (ch->sections_cap > SECTIONS_CAP_INIT) {
        ch->sections = (cheat_section_t*)ch->realloc_func(ch->sections, SECTIONS_CAP_INIT * sizeof(cheat_section_t));
        ch->sections_cap = SECTIONS_CAP_INIT;
    }
}

int cheat_get_codes(cheat_t *ch, const cheat_code_t **codes) {
    *codes = ch->codes;
    return ch->codes_count;
}

int cheat_get_code_count(cheat_t *ch) {
    return ch->codes_count;
}

cheat_code_t *cheat_get_code(cheat_t *ch, int index) {
    return index < ch->codes_count ? &ch->codes[index] : NULL;
}

int cheat_get_sections(cheat_t *ch, const cheat_section_t **sections) {
    *sections = ch->sections;
    return ch->sections_count;
}

int cheat_get_section_count(cheat_t *ch) {
    return ch->sections_count;
}

cheat_section_t *cheat_get_section(cheat_t *ch, int index) {
    return index < ch->sections_count ? &ch->sections[index] : NULL;
}

int cheat_section_toggle(cheat_t *ch, uint16_t index, int enabled) {
    cheat_section_t *sec;
    if (index >= ch->sections_count) return CR_INVALID;
    sec = &ch->sections[index];
    if ((sec->status & 1) == enabled) return CR_OK;
    sec->status = (sec->status & ~5) | enabled;
    return CR_OK;
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
    if (ch->codes_count > 0) {
        cheat_code_t *last = &ch->codes[ch->codes_count - 1];
        if (last->extra > 0) {
            code->op    = last->op | 0x80;
            code->extra = 0;
            switch (last->op & 0x7F) {
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
                case CO_PTRCHAINWRITE:
                case CO_PTRCHAINCOPY:
                case CO_MULPTRCHAINWRITE:
                    code->addr  = val1;
                    code->type  = last->type;
                    code->value = val2;
                    code->extra = last->extra - 1;
                    return CR_OK;
                case CO_IFEQUAL:
                case CO_IFNEQUAL:
                case CO_IFLESS:
                case CO_IFGREATER:
                    last->value = val2;
                    code->type = last->type;
                    code->value = val1;
                    code->addr = 0;
                    return CR_OK;
                case CO_ADDRIFEQUAL:
                case CO_ADDRIFNEQUAL:
                case CO_ADDRIFLESS:
                case CO_ADDRIFGREATER:
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
        case 9: {
            uint32_t sub = (val2 >> 24) & 0x0F;
            switch(sub) {
                case 1:
                    code->op = CO_PTRCHAINCOPY;
                    code->value = 0;
                    break;
                case 2:
                    code->op = CO_MULPTRCHAINWRITE;
                    code->value = (val2 >> 8) & 0xFFFFU;
                    break;
                default:
                    code->op = CO_PTRCHAINWRITE;
                    code->value = 0;
                    break;
            }
            code->addr  = val1 & 0x0FFFFFFFU;
            code->extra = (uint8_t)(val2 & 0xFFU);
            switch (val2 >> 28) {
                case 0:
                    code->type = CT_I8;
                    break;
                case 1:
                    code->type = CT_I16;
                    break;
                default:
                    code->type = CT_I32;
                    break;
            }
            break;
        }
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
                            code->op = CO_ADDRIFEQUAL;
                            break;
                        case 5:
                            code->op = CO_ADDRIFNEQUAL;
                            break;
                        case 6:
                            code->op = CO_ADDRIFLESS;
                            break;
                        case 7:
                            code->op = CO_ADDRIFGREATER;
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
                    code->extra = 0;
                    code->addr  = val2 & 0x0FFFFFFFU;
                    break;
                case 1:
                    code->type  = CT_I8;
                    code->value = val1 & 0x00FF00FFU;
                    code->extra = 0;
                    code->addr  = val2 & 0x0FFFFFFFU;
                    break;
                case 2:
                    code->type  = CT_I32;
                    code->value = 0;
                    code->extra = 1;
                    code->addr  = val2 & 0x0FFFFFFFU;
                    break;
                default: return CR_INVALID;
            }
            break;
        default: return CR_INVALID;
    }
    return CR_OK;
}

static inline void do_add_code(cheat_t *ch, cheat_code_t *code) {
    // check capacity
    int cap = ch->codes_cap;
    if (ch->codes_count >= cap) {
        cap += CODES_CAP_INCREMENT;
        ch->codes = (cheat_code_t*)ch->realloc_func(ch->codes, cap * sizeof(cheat_code_t));
        ch->codes_cap = cap;
    }
    // add code
    ch->codes[ch->codes_count++] = *code;
}

int cheat_add(cheat_t *ch, const char *line) {
    cheat_code_t code;

    if (ch->codes_count >= CODES_MAX) return -1;
    if (line[0] == 0 || line[1] == 0 || line[2] == 0) return -1;

    switch(ch->type) {
        case CH_CWCHEAT: {
            char op;
            // parse the cheat code
            if (line[0] == 0) return CR_OK;
            if (line[0] != '_') return CR_INVALID;
            op = line[1];

            switch (op) {
                // Comment
                case '#':
                    return CR_OK;

                // Game TITLEID
                case 'S':
                    line += 2;
                    while (*line == ' ' || *line == '\t') ++line;
                    strncpy(ch->titleid, line, 15);
                    ch->titleid[15] = 0;
                    return CR_OK;

                // Game name/description, ignored here
                case 'G':
                    return CR_OK;

                // Cheat section
                case 'C': {
                    cheat_section_t *sec;
                    uint8_t status = (line[2] >= '0' && line[2] <= '3') ? (line[2] - '0') : (line[2] > '3' ? 1 : 0);
                    line += 3;
                    while (*line == ' ' || *line == '\t') ++line;
                    // check capacity
                    {
                        int cap = ch->sections_cap;
                        if (ch->sections_count >= cap) {
                            cap += SECTIONS_CAP_INCREMENT;
                            ch->sections = (cheat_section_t*)ch->realloc_func(ch->sections, cap * sizeof(cheat_section_t));
                            ch->sections_cap = cap;
                        }
                    }
                    // add section
                    sec = &ch->sections[ch->sections_count++];
                    sec->index = ch->sections_count;
                    sec->status = status;
                    sec->code_index = ch->codes_count;
                    strncpy(sec->name, line, 59);
                    sec->name[59] = 0;
                    return CR_OK;
                }

                // Cheat line
                case 'L': {
                    uint32_t val1, val2;
                    int r;
                    line += 2;
                    parse_values(line, &val1, &val2);
                    r = add_cwcheat_code(ch, &code, val1, val2);
                    if (r != CR_MERGED && r != CR_OK) return r;
                    do_add_code(ch, &code);
                    return code.extra ? CR_MORELINE : CR_OK;
                }
                default: {
                    const char *s;
                    uint32_t val1, val2;
                    int len;
                    char ctlcode[16];
                    s = line + 1;
                    line += 2;
                    while (*line != 0 && *line != ' ' && *line != '\t') ++line;
                    len = line - s;
                    if (len > 15) len = 15;
                    if (len > 0) strncpy(ctlcode, s, len);
                    ctlcode[len] = 0;
                    parse_values(line, &val1, &val2);
                    if (ch->ext_cb(ch->arg, &code, ctlcode, val1, val2) == CR_OK) {
                        do_add_code(ch, &code);
                        return CR_OK;
                    }
                    return CR_INVALID;
                }
            }
            break;
        default:
            return CR_INVALID;
        }
    }
}

int cheat_apply(cheat_t *ch) {
    int ret = CR_OK;
    int i;
    int e = ch->sections_count;
    for(i = 0; i < e; ++i) {
        int j, e2;
        cheat_section_t *sec = &ch->sections[i];
        if (!(sec->status & 1) || (sec->status & 4)) {
            continue;
        }
        e2 = i + 1 < e ? ch->sections[i + 1].code_index : ch->codes_count;
        for (j = sec->code_index; j < e2; ++j) {
            cheat_code_t *c = &ch->codes[j];
            switch(c->op) {
                case CO_WRITE: {
                    ch->write_cb(ch->arg, c->addr, &c->value, c->type, 1);
                    break;
                }
                case CO_INCR: {
                    switch(c->type) {
                    case CT_I8:
                        ch->trans_cb(ch->arg, c->addr, c->value, 1, 0, 1);
                        break;
                    case CT_I16:
                        ch->trans_cb(ch->arg, c->addr, c->value, 2, 0, 1);
                        break;
                    case CT_I32:
                        ch->trans_cb(ch->arg, c->addr, c->value, 4, 0, 1);
                        break;
                    }
                    break;
                }
                case CO_DECR: {
                    switch(c->type) {
                    case CT_I8:
                        ch->trans_cb(ch->arg, c->addr, c->value, 1, 1, 1);
                        break;
                    case CT_I16:
                        ch->trans_cb(ch->arg, c->addr, c->value, 2, 1, 1);
                        break;
                    case CT_I32:
                        ch->trans_cb(ch->arg, c->addr, c->value, 4, 1, 1);
                        break;
                    }
                    break;
                }
                case CO_MULWRITE: {
                    if (j + 1 >= e2) break;
                    cheat_code_t *c2 = &ch->codes[j + 1];
                    uint32_t addr_s = c->addr;
                    uint32_t count = c->value >> 16;
                    uint32_t off = (c->value & 0xFFFFU) * 4;
                    uint32_t value = c2->addr;
                    uint32_t incr = c2->value;
                    uint32_t z;
                    for (z = 0; z < count; ++z) {
                        ch->write_cb(ch->arg, c->addr, &value, 4, 1);
                        addr_s += off;
                        value += incr;
                    }
                    break;
                }
                case CO_MULWRITE2: {
                    if (j + 1 >= e2) break;
                    cheat_code_t *c2 = &ch->codes[j + 1];
                    uint32_t count = c->value >> 16;
                    uint32_t addr = c->addr;
                    uint32_t off = c->value & 0xFFFFU;
                    uint32_t value = c2->addr;
                    uint32_t incr = c2->value;
                    uint32_t z;
                    switch (c->type) {
                        case CT_I8: {
                            for (z = 0; z < count; ++z) {
                                ch->write_cb(ch->arg, addr, &value, 1, 1);
                                addr += off;
                                value += incr;
                            }
                            break;
                        }
                        case CT_I16: {
                            uint16_t *addr_s = (uint16_t*)addr;
                            for (z = 0; z < count; ++z) {
                                ch->write_cb(ch->arg, (uint32_t)addr_s, &value, 2, 1);
                                addr_s += off;
                                value += incr;
                            }
                            break;
                        }
                    }
                    break;
                }
                case CO_COPY: {
                    cheat_code_t *c2;
                    if (j + 1 >= e2) break;
                    c2 = &ch->codes[j + 1];
                    ch->copy_cb(ch->arg, c->addr, c2->addr, c->value, 1);
                    break;
                }
                case CO_PTRWRITE: {
                    if (j + 1 >= e2) break;
                    cheat_code_t *c2 = &ch->codes[j + 1];
                    uint32_t addr2;
                    if (ch->read_cb(ch->arg, c->addr, &addr2, 4, 1) < 0) break;
                    ch->write_cb(ch->arg, addr2 + c2->value, &c->value, c->type, 0);
                    break;
                }
                case CO_PTRCHAINWRITE: {
                    uint16_t z;
                    uint32_t addr;
                    uint32_t addr_next;
                    cheat_code_t *c2;
                    if (c->extra < 1 || j + c->extra >= e2) break;
                    addr = c->addr;
                    for (z = 1; z <= c->extra; ++z) {
                        if (ch->read_cb(ch->arg, addr, &addr_next, 4, z == 1) < 0) {
                            z = 0; break;
                        }
                        c2 = &ch->codes[j + z];
                        addr = addr_next + c2->addr;
                    }
                    if (z == 0) break;
                    ch->write_cb(ch->arg, addr, &c2->value, c->type, 0);
                    break;
                }
                case CO_MULPTRCHAINWRITE: {
                    uint32_t y, z;
                    uint32_t addr, addr_, addr_next, addr_delta;
                    cheat_code_t *c2;
                    uint32_t count;
                    uint32_t index;
                    uint32_t value_, value_delta;
                    if (c->extra < 2 || j + c->extra >= e2) break;
                    c2 = &ch->codes[j + c->extra];
                    index = c2->addr >> 24;
                    if (index >= c->extra) break;
                    count = c->value;
                    addr_delta = c2->addr & 0xFFFFFFU;
                    value_delta = c2->value;
                    addr_ = c->addr;
                    ++index;
                    for (z = 1; z < index; ++z) {
                        if (ch->read_cb(ch->arg, addr_, &addr_next, 4, z == 1) < 0) {
                            z = 0; break;
                        }
                        c2 = &ch->codes[j + z];
                        addr_ = addr_next + c2->addr;
                    }
                    value_ = ch->codes[j + c->extra - 1].value;
                    for (y = 0; y < count; ++y, addr_ += addr_delta, value_ += value_delta) {
                        addr = addr_;
                        for (z = index; z < c->extra; ++z) {
                            if (ch->read_cb(ch->arg, addr, &addr_next, 4, z == 1) < 0) {
                                z = 0; break;
                            }
                            c2 = &ch->codes[j + z];
                            addr = addr_next + c2->addr;
                        }
                        if (z == 0) break;
                        ch->write_cb(ch->arg, addr, &value_, c->type, 0);
                    }
                    break;
                }
                case CO_PTRCHAINCOPY: {
                    uint16_t z;
                    uint32_t value;
                    uint32_t addr, addr2;
                    uint32_t addr_next, addr_next2;
                    cheat_code_t *c2;
                    if (c->extra < 1 || j + c->extra >= e2) break;
                    addr = c->addr;
                    addr2 = ch->codes[j + 1].addr;
                    for (z = 2; z <= c->extra; ++z) {
                        int need_conv = z == 2;
                        if (ch->read_cb(ch->arg, addr, &addr_next, 4, need_conv) < 0) {
                            z = 0; break;
                        }
                        if (ch->read_cb(ch->arg, addr2, &addr_next2, 4, need_conv) < 0) {
                            z = 0; break;
                        }
                        c2 = &ch->codes[j + z];
                        addr = addr_next + c2->addr;
                        addr2 = addr_next2 + c2->value;
                    }
                    if (z == 0) break;
                    if (ch->read_cb(ch->arg, addr2, &value, c->type, 0) < 0) break;
                    ch->write_cb(ch->arg, addr, &value, c->type, 0);
                    break;
                }
                case CO_BITOR: {
                    switch(c->type) {
                    case CT_I8:
                        ch->trans_cb(ch->arg, c->addr, c->value, 1, 2, 1);
                        break;
                    case CT_I16:
                        ch->trans_cb(ch->arg, c->addr, c->value, 2, 2, 1);
                        break;
                    case CT_I32:
                        ch->trans_cb(ch->arg, c->addr, c->value, 4, 2, 1);
                        break;
                    }
                    break;
                }
                case CO_BITAND: {
                    switch(c->type) {
                    case CT_I8:
                        ch->trans_cb(ch->arg, c->addr, c->value, 1, 3, 1);
                        break;
                    case CT_I16:
                        ch->trans_cb(ch->arg, c->addr, c->value, 2, 3, 1);
                        break;
                    case CT_I32:
                        ch->trans_cb(ch->arg, c->addr, c->value, 4, 3, 1);
                        break;
                    }
                    break;
                }
                case CO_BITXOR: {
                    switch(c->type) {
                    case CT_I8:
                        ch->trans_cb(ch->arg, c->addr, c->value, 1, 4, 1);
                        break;
                    case CT_I16:
                        ch->trans_cb(ch->arg, c->addr, c->value, 2, 4, 1);
                        break;
                    case CT_I32:
                        ch->trans_cb(ch->arg, c->addr, c->value, 4, 4, 1);
                        break;
                    }
                    break;
                }
                case CO_DELAY: {
                    ch->delay_cb(ch->arg, c->value);
                    break;
                }
                case CO_STOPPER: {
                    uint32_t val;
                    if (ch->read_cb(ch->arg, c->addr, &val, 4, 1) < 0) break;
                    if (val != c->value) {
                        i = e;
                        j = e2;
                        ret = CR_STOPPER;
                    }
                    continue;
                }
                case CO_PRESSED: {
                    if (!ch->input_cb(ch->arg, c->value))
                        j += c->addr;
                    break;
                }
                case CO_NOTPRESSED: {
                    if (ch->input_cb(ch->arg, c->value))
                        j += c->addr;
                    break;
                }
                case CO_IFEQUAL:
                case CO_IFNEQUAL:
                case CO_IFLESS:
                case CO_IFGREATER: {
                    uint32_t skip;
                    uint32_t value;
                    uint32_t cvalue;
                    if (c->extra) {
                        if (j + 1 >= e2) break;
                        cheat_code_t *c2 = &ch->codes[j + 1];
                        skip = c2->value;
                        value = c->value;
                    } else {
                        skip = c->value >> 16;
                        value = c->value & 0xFFFFU;
                    }
                    cvalue = 0U;
                    switch(c->type) {
                        case CT_I8:
                            if (ch->read_cb(ch->arg, c->addr, &cvalue, 1, 1) < 0) break;
                            break;
                        case CT_I16:
                            if (ch->read_cb(ch->arg, c->addr, &cvalue, 2, 1) < 0) break;
                            break;
                        case CT_I32:
                            if (ch->read_cb(ch->arg, c->addr, &cvalue, 4, 1) < 0) break;
                            break;
                    }
                    switch(c->op) {
                        case CO_IFEQUAL:
                            if (cvalue != value) j += skip;
                            break;
                        case CO_IFNEQUAL:
                            if (cvalue == value) j += skip;
                            break;
                        case CO_IFLESS:
                            if (cvalue >= value) j += skip;
                            break;
                        case CO_IFGREATER:
                            if (cvalue <= value) j += skip;
                            break;
                    }
                    break;
                }
                case CO_ADDRIFEQUAL:
                case CO_ADDRIFNEQUAL:
                case CO_ADDRIFLESS:
                case CO_ADDRIFGREATER: {
                    uint32_t skip;
                    uint32_t addr2;
                    uint32_t value;
                    uint32_t cvalue;
                    if (!c->extra) continue;
                    if (j + 1 >= e2) break;
                    cheat_code_t *c2 = &ch->codes[j + 1];
                    skip = c2->value;
                    addr2 = c->value;
                    value = cvalue = 0U;
                    switch(c->type) {
                        case CT_I8:
                            if (ch->read_cb(ch->arg, c->addr, &cvalue, 1, 1) < 0) break;
                            if (ch->read_cb(ch->arg, addr2, &value, 1, 1) < 0) break;
                            break;
                        case CT_I16:
                            if (ch->read_cb(ch->arg, c->addr, &cvalue, 2, 1) < 0) break;
                            if (ch->read_cb(ch->arg, addr2, &value, 2, 1) < 0) break;
                            break;
                        case CT_I32:
                            if (ch->read_cb(ch->arg, c->addr, &cvalue, 4, 1) < 0) break;
                            if (ch->read_cb(ch->arg, addr2, &value, 4, 1) < 0) break;
                            break;
                    }
                    switch(c->op) {
                        case CO_IFEQUAL:
                            if (cvalue != value) j += skip;
                            break;
                        case CO_IFNEQUAL:
                            if (cvalue == value) j += skip;
                            break;
                        case CO_IFLESS:
                            if (cvalue >= value) j += skip;
                            break;
                        case CO_IFGREATER:
                            if (cvalue <= value) j += skip;
                            break;
                    }
                    break;
                }
                default:
                    if (ch->ext_call_cb(ch->arg, j, c) == CR_STOPPER) {
                        i = e;
                        j = e2;
                        ret = CR_STOPPER;
                        continue;
                    }
                    break;
            }
            j += c->extra;
        }
        if (sec->status & 2) sec->status |= 4;
    }
    return ret;
}
