
#ifndef _UTIL_H
#define _UTIL_H

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long) &((TYPE*)0)->MEMBER)
#endif

#define container_of(ptr, type, member) \
        ((type *)(((char *)(ptr)) - offsetof(type,member)))

#endif
