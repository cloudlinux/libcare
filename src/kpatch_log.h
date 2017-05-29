#ifndef __KP_LOG_H__
#define __KP_LOG_H__

#include <stdio.h>

extern int log_level, log_indent;

void kplog(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void kpfatal(const char *fmt, ...) __attribute__((noreturn,format(printf,1,2)));

#define kpdebug(fmt...)		kplog(LOG_DEBUG, fmt)
#define kpwarn(fmt...)		kplog(LOG_WARN, fmt)
#define kpinfo(fmt...)		kplog(LOG_INFO, fmt)

void _kpfatalerror(const char *filename, int line, const char *fmt, ...)
	__attribute__((noreturn,format(printf,3,4)));
void _kplogerror(const char *filename, int line, const char *fmt, ...)
	__attribute__((format(printf,3,4)));

#define kpfatalerror(fmt...)	_kpfatalerror(__FILE__, __LINE__, fmt)
#define kplogerror(fmt...)	_kplogerror(__FILE__, __LINE__, fmt)

#define kperr(fmt...)		do {		\
	int errsv = errno;			\
	errno = 0;				\
	_kplogerror(__FILE__, __LINE__, fmt);	\
	errno = errsv;				\
} while (0)

#define LOG_ERR		0
#define LOG_WARN	1
#define LOG_INFO	2
#define LOG_DEBUG	3
#define LOG_TRACE	5

#endif
