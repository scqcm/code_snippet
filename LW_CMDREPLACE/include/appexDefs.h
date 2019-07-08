/*************************************************************************
* LEGALESE:   Copyright (c) 2007, AppEx Networks.
*
* This source code is confidential, proprietary, and contains trade
* secrets that are the sole property of AppEx Networks.
* Copy and/or distribution of this source code or disassembly or reverse
* engineering of the resultant object code are strictly forbidden without
* the written consent of AppEx Networks LLC.
*
************************************************************************
* FILE NAME :       appexDefs.h
*
* DESCRIPTION :     define basic macros and data structures.
*
* AUTHOR :          hao zhuang
*
* HISTORY :         hao     07/16/2007  created
*************************************************************************/

#ifndef __APPEX_DEFS_H__
#define __APPEX_DEFS_H__


/*******************************************************************************
 * data type definitions
 ******************************************************************************/

#ifndef APX_PACKED
#define APX_PACKED
#endif

#ifndef APX_CACHE_ALIGNED
#define APX_CACHE_ALIGNED
#endif

#ifndef APX_THREAD_VAR
#define APX_THREAD_VAR
#endif

#ifndef APXENV_HAS_INTS
typedef unsigned char       UINT8;
typedef unsigned short      UINT16;
typedef unsigned int        UINT32;
typedef unsigned long long  UINT64;
typedef char                INT8;
typedef short               INT16;
typedef int                 INT32;
typedef long long           INT64;

typedef UINT32	uint32_t;
typedef UINT16	uint16_t;
typedef UINT8	uint8_t;
#endif /* !APXENV_HAS_INTS */

#ifndef __in_ecount
#define __in
#define __out
#define __inout
#define __in_opt
#define __out_opt
#define __inout_opt
#define __in_ecount(size)
#define __out_ecount(size)
#define __inout_ecount(size)
#define __in_ecount_opt(size)
#define __out_ecount_opt(size)
#define __inout_ecount_opt(size)

#endif

#ifndef APXENV_HAS_BOOL
#undef FALSE
#undef TRUE
typedef enum BOOL { FALSE = 0, TRUE = 1 } BOOL;
#endif /* !APXENV_HAS_BOOL */


/*******************************************************************************
 * platform macros
 ******************************************************************************/

#ifdef __cplusplus

#ifndef APX_ARRAY_SIZE
extern "C++" template<typename T, size_t N> char (&_APX_ARRAY_SIZE_HELPER(T (&ArrayArg)[N]))[N];
#define APX_ARRAY_SIZE(_array_) (sizeof(_APX_ARRAY_SIZE_HELPER(_array_)))
#endif /* !APX_ARRAY_SIZE */

#endif /* __cplusplus */

#ifdef __GNUC__

#define APX_GCC_ATTR(_attr_)    __attribute__ (_attr_)

#define APX_IS_ARRAY(_v_) \
    (__builtin_types_compatible_p(typeof(_v_), typeof(&(_v_)[0])) == 0)

#define APX_MUST_BE_ARRAY(_array_) \
    sizeof(char[-!APX_IS_ARRAY(_array_)])

/*
 * this macro counts the number of elements in the array variable. it ensures
 * the variable is of the array type instead of a pointer.
 */
#ifndef APX_ARRAY_SIZE
#define APX_ARRAY_SIZE(_array_) \
( \
    sizeof((_array_)) / sizeof((_array_)[0]) + APX_MUST_BE_ARRAY(_array_) \
)
#endif /* APX_ARRAY_SIZE */

#else /* !__GNUC__ */

#define APX_GCC_ATTR(_attr_)

#ifndef APX_ARRAY_SIZE
#define APX_ARRAY_SIZE(_array_) \
( \
    sizeof((_array_)) / sizeof((_array_)[0]) \
)
#endif /* APX_ARRAY_SIZE */

#endif /* !__GNUC__ */


#ifndef APX_INLINE
#define APX_INLINE
#endif /* !APX_INLINE */

#ifndef APX_FORCE_INLINE
#define APX_FORCE_INLINE static inline
#endif /* !APX_FORCE_INLINE */

#ifndef APX_LIKELY
#define APX_LIKELY(_expr_)      _expr_
#endif /* !APX_LIKELY */

#ifndef APX_UNLIKELY
#define APX_UNLIKELY(_expr_)    _expr_
#endif /* !APX_UNLIKELY */

#ifndef APX_UNREFERENCED
#define APX_UNREFERENCED(_arg_) _arg_ = _arg_
#endif /* !APX_UNREFERENCED */

#ifndef APX_MAYBE_UNREFERENCED
#define APX_MAYBE_UNREFERENCED(_var_) _var_ = _var_
#endif /* !APX_MAYBE_UNREFERENCED */

#ifndef APX_ASSERT
#define APX_ASSERT(_expr_)      assert((_expr_))
#endif /* !APX_ASSERT */

#ifndef APX_C_ASSERT
#define APX_C_ASSERT(_expr_)    typedef char __APX_C_ASSERT__[(_expr_) ? 1 : -1]
#endif /* !APX_C_ASSERT */

#ifndef APX_ALERT
#define APX_ALERT(_expr_)       APX_ASSERT(_expr_)
#endif /* !APX_ALERT */

#ifndef APX_NTOHL
#define APX_NTOHL(_i_)          ntohl(_i_)
#endif /* !APX_NTOHL */

#ifndef APX_NTOHS
#define APX_NTOHS(_i_)          ntohs(_i_)
#endif /* !APX_NTOHS */

#ifndef APX_HTONL
#define APX_HTONL(_i_)          htonl(_i_)
#endif /* !APX_HTONL */

#ifndef APX_HTONS
#define APX_HTONS(_i_)          htons(_i_)
#endif /* !APX_HTONS */

#ifndef APX_NTOHL_CONST
#define APX_NTOHL_CONST(_i_)    APX_NTOHL(_i_)
#endif /* !APX_NTOHL_CONST */

#ifndef APX_NTOHS_CONST
#define APX_NTOHS_CONST(_i_)    APX_NTOHS(_i_)
#endif /* !APX_NTOHS_CONST */

#ifndef APX_HTONL_CONST
#define APX_HTONL_CONST(_i_)    APX_HTONL(_i_)
#endif /* !APX_HTONL_CONST */

#ifndef APX_HTONS_CONST
#define APX_HTONS_CONST(_i_)    APX_HTONS(_i_)
#endif /* !APX_HTONS_CONST */

#ifndef APX_OFFSET_OF
#define APX_OFFSET_OF(_s_, _f_) ((size_t)&((_s_*)0)->_f_)
#endif /* !APX_OFFSET_OF */

#ifndef APX_CONTAINER
#define APX_CONTAINER(_p_, _t_, _f_) ((_t_*)((UINT8*)(_p_) - APX_OFFSET_OF(_t_, _f_)))
#endif /* !APX_CONTAINING_STRUCT */

#ifndef APX_MULTIPLE_BITS_SET
#define APX_MULTIPLE_BITS_SET(_x_)  (((_x_) & ((_x_) - 1)) != 0)
#endif /* !APX_MULTIPLE_BITS_SET */

/*
 * this macro is intended to deal with VC's warning C4127 - "conditional
 * expression is constant". it explicitly states that the conditional
 * epxression may be constant so that the compiler wont freak out. so in
 * VC this macro will be defined differently while with other compilers
 * they use the default nothing.
 */
#ifndef APX_CONST_COND
#define APX_CONST_COND(_cond_)  _cond_
#endif /* APX_CONST_COND */

/*
 * this macro is primarily used to clarify with PREfast that the resource
 * pointed by _p_ has been taken ownership of (aliased). hence the PREfast
 * should NOT treat it as a resource leak.
 */
#ifndef APX_CONSUMED
#define APX_CONSUMED(_p_)       ((_p_) = NULL)
#endif /* !APX_CONSUMED */


/*******************************************************************************
 * string operate macros
 ******************************************************************************/
#ifndef APX_ISASCII
#define APX_ISASCII(_c_)            isascii(_c_)
#endif /* !APX_ISASCII */

#ifndef APX_TOLOWER
#define APX_TOLOWER(_c_)            tolower(_c_)
#endif /* !APX_TOLOWER */


/*******************************************************************************
 * memory access macros
 ******************************************************************************/

#if defined(APXENV_ALIGNMENT_ANY)
#define APX_ASSERT_ALIGN_2(_p_)
#define APX_ASSERT_ALIGN_4(_p_)
#define APX_ASSERT_ALIGN_8(_p_)
#elif defined(APXENV_ALIGNMENT_2)
#define APX_ASSERT_ALIGN_2(_p_)     APX_ASSERT(((size_t)(_p_) % 2) == 0)
#define APX_ASSERT_ALIGN_4(_p_)     APX_ASSERT(((size_t)(_p_) % 2) == 0)
#define APX_ASSERT_ALIGN_8(_p_)     APX_ASSERT(((size_t)(_p_) % 2) == 0)
#else
#define APX_ASSERT_ALIGN_2(_p_)     APX_ASSERT(((size_t)(_p_) % 2) == 0)
#define APX_ASSERT_ALIGN_4(_p_)     APX_ASSERT(((size_t)(_p_) % 4) == 0)
#define APX_ASSERT_ALIGN_8(_p_)     APX_ASSERT(((size_t)(_p_) % 8) == 0)
#endif /* APXENV_ALIGNMENT_* */


/*******************************************************************************
 * ring arithmetics.
 ******************************************************************************/

#define APX_RING_INC(_v_, _s_)      ((_v_) < (_s_) - 1 ? (_v_) + 1 : 0)
#define APX_RING_DEC(_v_, _s_)      ((_v_) > 0 ? (_v_) - 1 : (_s_) - 1)
#define APX_RING_ADD(_a_, _b_, _s_) ((_a_) + (_b_) < (_s_) ? (_a_) + (_b_) : (_a_) + (_b_) - (_s_))
#define APX_RING_SUB(_a_, _b_, _s_) ((_a_) >= (_b_) ? (_a_) - (_b_) : (_s_) + (_a_) - (_b_))


/*******************************************************************************
 * some platform-dependent algorithms. sorta stupid.
 ******************************************************************************/

#ifndef APX_U32xU32DivU32
#define APX_U32xU32DivU32(_x32_, _y32_, _z32_) \
( \
    (UINT64)(UINT32)(_x32_) * (UINT32)(_y32_) / (UINT32)(_z32_) \
)
#endif /* APX_U32xU32DivU32 */


/*******************************************************************************
 * double-linked list definitions.
 ******************************************************************************/

typedef struct _APX_LIST APX_LIST;

struct _APX_LIST
{
    APX_LIST*   Next;
    APX_LIST*   Prev;
};


APX_FORCE_INLINE
void
APX_ListInit(
    __out APX_LIST* List
    )
{
    List->Prev = List->Next = List;
}

APX_FORCE_INLINE
BOOL
APX_ListIsEmpty(
    __in APX_LIST const* List
    )
{
    return List->Next == List;
}

APX_FORCE_INLINE
BOOL
APX_ListIsNodeLinked(
    __in APX_LIST const* Node
    )
{
    return Node->Next != NULL;
}

APX_FORCE_INLINE
void
APX_ListInsertHeadNode(
    __inout APX_LIST* List,
    __inout APX_LIST* Node
    )
{
    APX_LIST* next;

    next = List->Next;
    Node->Next = next;
    Node->Prev = List;
    next->Prev = Node;
    List->Next = Node;
}

APX_FORCE_INLINE
void
APX_ListInsertTailNode(
    __inout APX_LIST* List,
    __inout APX_LIST* Node
    )
{
    APX_LIST* prev;

    prev = List->Prev;
    Node->Next = List;
    Node->Prev = prev;
    prev->Next = Node;
    List->Prev = Node;
}

APX_FORCE_INLINE
void
APX_ListRemoveNode(
    __inout APX_LIST* Node
    )
{
    APX_LIST* next;
    APX_LIST* prev;

    next = Node->Next;
    prev = Node->Prev;
    prev->Next = next;
    next->Prev = prev;
    Node->Next = NULL;
    Node->Prev = NULL;
}

APX_FORCE_INLINE
APX_LIST*
APX_ListRemoveHeadNode(
    __inout APX_LIST* List
    )
{
    APX_LIST* next;
    APX_LIST* node;

    node = List->Next;
    next = node->Next;
    List->Next = next;
    next->Prev = List;
    node->Next = NULL;
    node->Prev = NULL;
    return node;
}

APX_FORCE_INLINE
APX_LIST*
APX_ListRemoveTailNode(
    __inout APX_LIST* List
    )
{
    APX_LIST* prev;
    APX_LIST* node;

    node = List->Prev;
    prev = node->Prev;
    List->Prev = prev;
    prev->Next = List;
    node->Next = NULL;
    node->Prev = NULL;
    return node;
}

APX_FORCE_INLINE
void
APX_ListMoveHeadBeforeNode(
    __inout APX_LIST* List,
    __inout APX_LIST* Node
    )
{
    if (List != Node && List != Node->Prev)
    {
        APX_LIST* next;
        APX_LIST* prev;

        next = List->Next;
        prev = List->Prev;
        prev->Next = next;
        next->Prev = prev;
        prev = Node->Prev;
        List->Next = Node;
        List->Prev = prev;
        prev->Next = List;
        Node->Prev = List;
    }
}

/* insert all nodes in 'Source' into the beginning of 'Target' and empty 'Source'. */
APX_FORCE_INLINE
void
APX_ListJoin(
    __inout APX_LIST* Target,
    __inout APX_LIST* Source
    )
{
    if (Source->Next != Source)
    {
        Source->Next->Prev = Target;
        Source->Prev->Next = Target->Next;
        Target->Next->Prev = Source->Prev;
        Target->Next = Source->Next;
        Source->Prev = Source->Next = Source;
    }
}


/*******************************************************************************
 * single-headed double-linked list definitions:
 * the list head has only a single pointer to the first linked list node.
 * this saves space for structures like hash tables.
 ******************************************************************************/

typedef struct _APX_SH_LIST
{
    APX_LIST*   Head;
}
APX_SH_LIST;

APX_FORCE_INLINE
BOOL
APX_SHListIsEmpty(
    __in APX_SH_LIST const* List
    )
{
    return List->Head == NULL;
}

APX_FORCE_INLINE
BOOL
APX_SHListIsNodeLinked(
    __in APX_LIST const* Node
    )
{
    return Node->Next != NULL;
}

APX_FORCE_INLINE
void
APX_SHListInsertHeadNode(
    __inout APX_SH_LIST* List,
    __inout APX_LIST* Node
    )
{
    if (List->Head == NULL)
    {
        APX_ListInit(Node);
    }
    else
    {
        APX_ListInsertTailNode(List->Head, Node);
    }

    List->Head = Node;
}

APX_FORCE_INLINE
void
APX_SHListInsertTailNode(
    __inout APX_SH_LIST* List,
    __inout APX_LIST* Node
    )
{
    if (List->Head == NULL)
    {
        List->Head = Node;
        APX_ListInit(Node);
    }
    else
    {
        APX_ListInsertTailNode(List->Head, Node);
    }
}

APX_FORCE_INLINE
void
APX_SHListRemoveNode(
    __inout APX_SH_LIST* List,
    __inout APX_LIST* Node
    )
{
    if (!APX_ListIsEmpty(Node))
    {
        if (List->Head == Node)
        {
            List->Head = Node->Next;
        }

        APX_ListRemoveNode(Node);
    }
    else
    {
        List->Head = NULL;
        Node->Next = NULL;
        Node->Prev = NULL;
    }
}

APX_FORCE_INLINE
APX_LIST*
APX_SHListRemoveHeadNode(
    __inout APX_SH_LIST* List
    )
{
    APX_LIST* node;

    node = List->Head;

    if (!APX_ListIsEmpty(node))
    {
        List->Head = node->Next;
        APX_ListRemoveNode(node);
    }
    else
    {
        List->Head = NULL;
        node->Next = NULL;
        node->Prev = NULL;
    }

    return node;
}

APX_FORCE_INLINE
APX_LIST*
APX_SHListRemoveTailNode(
    __inout APX_SH_LIST* List
    )
{
    APX_LIST* node;

    node = List->Head->Prev;

    if (node != List->Head)
    {
        APX_ListRemoveNode(node);
    }
    else
    {
        List->Head = NULL;
        node->Next = NULL;
        node->Prev = NULL;
    }

    return node;
}

APX_FORCE_INLINE
void
APX_SHListMoveHeadBeforeNode(
    __inout APX_SH_LIST* List,
    __inout APX_LIST* Node
    )
{
    List->Head = Node->Prev;
}


#endif /* !__APPEX_DEFS_H__ */
