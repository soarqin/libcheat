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
    CO_PTRWRITE,
    CO_BITOR,
    CO_BITAND,
    CO_BITXOR,
    CO_DELAY,
    CO_STOPPER,
    CO_DATA, // used as data for multi-line cheat
};

enum {
    CT_I8 = 0,
    CT_I16 = 1,
    CT_I32 = 2,
};

// Cheat code struct
typedef struct cheat_code_t {
    uint8_t    op;          // operation
    uint8_t    type;        // data type
    uint8_t    status;      // 0-disabled 1-enabled
    uint8_t    extra;       // extra lines used by this code
    uint32_t   addr;
    uint32_t   value;
} cheat_code_t;

// Results
enum {
    CR_OK = 0,
    // for cheat_add
    CR_INVALID = -1,
    CR_MORELINE = -100,
    // for cheat_apply
    CR_STOPPER = -2,
};

typedef uint32_t (*cheat_addr_conv_t)(uint32_t addr);
typedef int (*cheat_read_cb_t)(uint32_t addr, void *data, int len);
typedef int (*cheat_write_cb_t)(uint32_t addr, const void *data, int len);
typedef void (*cheat_delay_cb_t)(uint32_t millisec);
typedef void *(*cheat_alloc_t)(size_t size);
typedef void *(*cheat_realloc_t)(void *ptr, size_t size);
typedef void (*cheat_free_t)(void *ptr);

typedef struct cheat_t cheat_t;

cheat_t *   cheat_new(uint8_t type);
cheat_t *   cheat_new2(uint8_t type, cheat_alloc_t a, cheat_realloc_t r, cheat_free_t f);
void        cheat_set_callbacks(cheat_t *ch, cheat_addr_conv_t conv_cb, cheat_read_cb_t read_cb, cheat_write_cb_t write_cb, cheat_delay_cb_t delay_cb);
void        cheat_finish(cheat_t *ch);
uint8_t     cheat_get_type(cheat_t *ch);
const char *cheat_get_titleid(cheat_t *ch);
void        cheat_reset(cheat_t *ch);
int         cheat_add(cheat_t *ch, const char *line);
void        cheat_apply(cheat_t *ch);
int         cheat_get_codes(cheat_t *ch, cheat_code_t **codes);

#endif // __LIBCHEAT_H_
