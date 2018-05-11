#ifndef __LIBCHEAT_H_
#define __LIBCHEAT_H_

#include <stddef.h>
#include <stdint.h>

// Cheat category
enum {
    CH_UNKNOWN = 0,
    CH_CWCHEAT,
    CH_MAX,
};

// Cheat operations
enum {
    CO_WRITE = 0,
    CO_INCR,
    CO_DECR,
    CO_MULWRITE,
    CO_MULWRITE2,
    CO_COPY,
    CO_PTRWRITE,
    CO_BITOR,
    CO_BITAND,
    CO_BITXOR,
    CO_DELAY,
    CO_STOPPER,
    CO_PRESSED,
    CO_NOTPRESSED,
    CO_IFEQUAL,
    CO_IFNEQUAL,
    CO_IFLESS,
    CO_IFGREATER,
    CO_DATA,      // used as data for multi-line cheat
    CO_EXTENSION, // opcode above this is extension codes registered by cheat_ext_cb_t,
                  // they are running through cheat_ext_call_cb_t,
};

enum {
    CT_NONE = 0,
    CT_I8 = 1,
    CT_I16 = 2,
    CT_I24 = 3, /* currently not used */
    CT_I32 = 4,
};

// Cheat section struct
typedef struct cheat_section_t {
    uint8_t  index;      // section index
    uint8_t  enabled;    // enabled
    uint16_t code_index; // index in codes array
    char name[28];       // section name with maximum of 27 chars, exceeded characters will be truncated
} cheat_section_t;

// Cheat code struct
typedef struct cheat_code_t {
    uint8_t  op;      // operation
    uint8_t  type;    // data type
    uint8_t  status;  // 0-disabled 1-enabled
    uint8_t  extra;   // extra lines used by this code
    uint32_t addr;
    uint32_t value;
} cheat_code_t;

// Results
enum {
    CR_OK = 0,
    // for cheat_add
    CR_INVALID      = -1,    // invalid code
    CR_TOOMANYCODES = -2,    // codes count exceeded
    CR_TOOMANYSECS  = -3,    // sections count exceeded
    CR_MORELINE     = -100,  // need more lines as a complete cheat set
    // for cheat_apply
    CR_STOPPER      = -11,   // stopped by code stopper
};

typedef int   (*cheat_read_cb_t)(uint32_t addr, void *data, int len, int need_conv);
typedef int   (*cheat_write_cb_t)(uint32_t addr, const void *data, int len, int need_conv);
// transform data, 0-INCR 1-DECR 2-OR 3-AND 4-XOR
typedef int   (*cheat_trans_cb_t)(uint32_t addr, uint32_t value, int len, int op, int need_conv);
typedef int   (*cheat_copy_cb_t)(uint32_t toaddr, uint32_t fromaddr, int len, int need_conv);
typedef int   (*cheat_button_cb_t)(uint32_t buttons);
typedef void  (*cheat_delay_cb_t)(uint32_t millisec);
// return CR_OK to add code to list
typedef int   (*cheat_ext_cb_t)(cheat_code_t *code, char op, const char *data);
// return CR_STOPPER to stop code running
typedef int   (*cheat_ext_call_cb_t)(int line, cheat_code_t *code);
typedef void  *(*cheat_realloc_t)(void *ptr, size_t size);
typedef void  (*cheat_free_t)(void *ptr);

typedef struct cheat_t cheat_t;

cheat_t *        cheat_new(uint8_t type);
cheat_t *        cheat_new2(uint8_t type, cheat_realloc_t r, cheat_free_t f);
void             cheat_set_read_cb(cheat_t *ch, cheat_read_cb_t cb);
void             cheat_set_write_cb(cheat_t *ch, cheat_write_cb_t cb);
void             cheat_set_trans_cb(cheat_t *ch, cheat_trans_cb_t cb);
void             cheat_set_copy_cb(cheat_t *ch, cheat_copy_cb_t cb);
void             cheat_set_button_cb(cheat_t *ch, cheat_button_cb_t cb);
void             cheat_set_delay_cb(cheat_t *ch, cheat_delay_cb_t cb);
void             cheat_set_ext_cb(cheat_t *ch, cheat_ext_cb_t cb);
void             cheat_set_ext_call_cb(cheat_t *ch, cheat_ext_call_cb_t cb);
void             cheat_finish(cheat_t *ch);
uint8_t          cheat_get_type(cheat_t *ch);
const char *     cheat_get_titleid(cheat_t *ch);
void             cheat_reset(cheat_t *ch);
int              cheat_get_codes(cheat_t *ch, const cheat_code_t **codes);
int              cheat_get_code_count(cheat_t *ch);
cheat_code_t *   cheat_get_code(cheat_t *ch, int index);
int              cheat_get_sections(cheat_t *ch, const cheat_section_t **sections);
int              cheat_get_section_count(cheat_t *ch);
cheat_section_t *cheat_get_section(cheat_t *ch, int index);
int              cheat_section_toggle(cheat_t *ch, uint16_t index, int enabled);
int              cheat_add(cheat_t *ch, const char *line);
int              cheat_apply(cheat_t *ch);

#endif // __LIBCHEAT_H_
