
//
//#include <stdio.h>
gcc -E -v compile_preprocess.c -o compile_preprocess.i

#ifdef BIHASH_TYPE
#undef BIHASH_TYPE
#endif

#define BIHASH_TYPE _40_8
#define BIHASH_KVP_PER_PAGE 4

#ifndef BIHASH_TYPE
#error BIHASH_TYPE not defined
#endif

#define _bv(a,b) a##b
#define __bv(a,b) _bv(a,b)
#define BV(a) __bv(a,BIHASH_TYPE)
BV(clib_bihash_value) /*output: clib_bihash_value_40_8*/

#define _bvt(a,b) a##b##_t
#define __bvt(a,b) _bvt(a,b)
#define BVT(a) __bvt(a,BIHASH_TYPE)
BVT(clib_bihash_value) /*output: clib_bihash_value_40_8_t*/

#define _bvs(a,b) struct a##b
#define __bvs(a,b) _bvs(a,b)
#define BVS(a) __bvs(a,BIHASH_TYPE)
BVS(clib_bihash_value) /*output: struct clib_bihash_value_40_8*/

#define foreach_bihash_stat                     \
_(alloc_add)                                    \
_(add)                                          \
_(split_add)                                    \
_(replace)                                      \
_(update)                                       \
_(del)                                          \
_(del_free)                                     \
_(linear)                                       \
_(resplit)                                      \
_(working_copy_lost)                            \
_(splits)			/* must be last */

typedef enum
{
#define _(a) BIHASH_STAT_##a,
  foreach_bihash_stat
#undef _
    BIHASH_STAT_N_STATS,
} BVT (clib_bihash_stat_id);
#endif /* BIHASH_STAT_IDS */
