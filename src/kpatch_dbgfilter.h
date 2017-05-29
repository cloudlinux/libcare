#ifndef __DBGFILTER_H__
#define __DBGFILTER_H__

#include "kpatch_io.h"

#define DFO_SKIP_EH_FRAME		1 << 0
#define DFO_SKIP_GCC_EXCEPT_TABLE	1 << 1
#define DFO_SKIP_CFI			1 << 2
#define DFO_EMIT_NEWLINES		1 << 3

void debug_filter(struct kp_file *fin, struct kp_file *fout, int options);

#endif	/* __DBGFILTER_H__ */
