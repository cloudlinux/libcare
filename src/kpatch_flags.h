#ifndef __KPATCH_FLAGS_H__
#define __KPATCH_FLAGS_H__

#define pp_make_str(x) #x

#define KPINFO_DEFINE_FLAGS(fname, flags) \
	asm(".equ " pp_make_str(fname) ".kpatch.flags, " pp_make_str(flags))

/* Mark function as adapted, see --must-adapt kpatch_gensrc option for details */
#define KPGENSRC_ADAPTED		(1 << 0)

#define KPGENSRC_DEFINE_FLAGS(flags) \
	asm(".kpgensrc_flags " # flags)

#endif
