#ifndef __KPSTR_H__
#define __KPSTR_H__

#include <string.h>
#include <ctype.h>

#include "kpatch_log.h"

/* --------------------------------------- kp strings -------------------------------------- */

typedef struct {
	char *s;
	int l;
} kpstr_t;

static inline void kpstrset(kpstr_t *x, char *s, int len)
{
	x->s = s;
	x->l = len;
}

static inline void kpstrskip(kpstr_t *x, int len)
{
	if (x->l < len)
		kpfatal("kpstrskip: skipping too much");
	x->s += len;
	x->l -= len;
}

static inline int kpstrncmp(kpstr_t *s1, kpstr_t *s2, int maxlen)
{
	int len = (s1->l < s2->l) ? s1->l : s2->l;
	int res;

	len = (len < maxlen) ? len : maxlen;
	res = memcmp(s1->s, s2->s, len);
	if (res)
		return res;

	if (s1->l > s2->l && s2->l < maxlen)
		return 1;
	else if (s1->l < s2->l && s1->l < maxlen)
		return -1;
	else
		return 0;
}

static inline int kpstrcmp(kpstr_t *s1, kpstr_t *s2)
{
	return kpstrncmp(s1, s2, (s1->l > s2->l) ? s1->l : s2->l);
}

/* compares kpstr and asciiz for exact match */
static inline int kpstrcmpz(kpstr_t *s1, char *s)
{
	kpstr_t s2;
	kpstrset(&s2, s, strlen(s));
	return kpstrcmp(s1, &s2);
}

/* compares that kpstr *starts* with asciiz string s */
static inline int kpstrncmpz(kpstr_t *s1, char *s)
{
	kpstr_t s2;
	kpstrset(&s2, s, strlen(s));
	return kpstrncmp(s1, &s2, s2.l);
}

/* ----------------------------------- helpers ------------------------------------ */

static inline char *skip_blanks(char *s)
{
	while (isblank(*s))
		s++;
	return s;
}

static inline void trim_crlf(char *s)
{
	char *se;

	/* remove trailing \n */
	se = s + strlen(s) - 1;
	while (se >= s) {
		if (*se != '\n' && *se != '\r')
			break;
		se--;
	}
	*(se + 1) = 0;
}

#endif	/* __KPSTR_H__ */
