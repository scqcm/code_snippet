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
* FILE NAME :       linuxBaseIo.c
*
* DESCRIPTION :     Linux base implementations.
*
* AUTHOR :          Leo Sun
*
* HISTORY :         lsun     02/03/2008  created
*************************************************************************/
#include <linux/delay.h>
#include "linuxBase.h"
#include "linuxMPool.h"
#include "appexSafeStr.h"
#include "appexEngineClsf.h"

#undef __out
#include <linux/wait.h>
#include <linux/sched.h>

/* Engine ID. */
int gApxPcapMaxBufLen = 32 * 1024 * 1024;
/*
 * 1541 2.6.32.431
 * 1540 2.6.32.358
 * 1539 2.6.32.279
 */
#if defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE < 1541
static inline void *PDE_DATA(const struct inode *inode)
{
    return PROC_I(inode)->pde->data;
}
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline void *PDE_DATA(const struct inode *inode)
{
    return PROC_I(inode)->pde->data;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
module_param(gApxPcapMaxBufLen, int, 0644);
#else
MODULE_PARM(gApxPcapMaxBufLen, "i");
#endif

#if defined(APXENV_PCAP_ENABLE)
static BOOL _pcapStart(APX_OPAQUE_ENGINE *OpaqueEngine);
static void _pcapStop(APX_OPAQUE_ENGINE *OpaqueEngine);

static void _ioWqHandler(struct work_struct *data);
static int _settingsWriteFunc(APX_OPAQUE_ENGINE *OpaqueEngine, char *copyBuf, unsigned long len, void *data);
static int _settingsReadFunc(APX_OPAQUE_ENGINE *OpaqueEngine, char *page, unsigned long size, void *data);

static
BOOL
_appexIoQueueWork(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    UINT16 type,
    UINT16 len1,
    void *data1,
    UINT16 len2,
    void *data2,
    int padding
    );

/*******************************************************************************
 * PCAP implementation
 ******************************************************************************/
static APX_BASE_DECLARE_MUTEX(_pcapSem);

typedef struct _PCAP_FILE_HDR
{
    UINT32 Magic;
    UINT16 Major;
    UINT16 Minor;
    UINT32 Thiszone;
    UINT32 Sigfigs;
    UINT32 Snaplen;
    UINT32 Linktype;
} PCAP_FILE_HDR;

typedef struct _PCAP_PACKET_HDR
{
    UINT32 Secs;
    UINT32 USecs;
    UINT32 Caplen;
    UINT32 Len;
} PCAP_PACKET_HDR;

#define APX_IO_WRITE(filp, data, len) (void)_k_file_seq_write(filp, data, len)

struct file*
_k_file_open(
    char const* path,
    int flags,
    int mode
    )
{
    struct file* filp = NULL;
    mm_segment_t oldfs = get_fs();
    set_fs(KERNEL_DS);
    filp = filp_open(path, flags, mode);
    set_fs(oldfs);
    return !IS_ERR(filp) ? filp : NULL;
}

static void _k_file_close(struct file* filp)
{
    if (filp != NULL)
    {
        filp_close(filp, NULL);
    }
}

static int
_k_file_seq_write(
    struct file* filp,
    void const* buf,
    size_t size
    )
{
    int ret = 0;
    mm_segment_t oldfs = get_fs();
    set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
    ret = vfs_write(filp, buf, size, &filp->f_pos);
#else
    ret = filp->f_op->write(filp, buf, size, &filp->f_pos);
#endif
    if (ret != size)
    {
        if (ret < 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
            vfs_write(filp, buf, size, &filp->f_pos);
#else
            filp->f_op->write(filp, buf, size, &filp->f_pos);
#endif
        else if(ret < size)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
            vfs_write(filp, buf + ret, size - ret, &filp->f_pos);
#else
            filp->f_op->write(filp, buf + ret, size - ret, &filp->f_pos);
#endif
    }
    set_fs(oldfs);
    return ret;
}

static struct file*
_pcapOpenFile(
    APX_OPAQUE_ENGINE* OpaqueEngine,
    const char *fileName,
    const struct timeval* tm
    )
{
    static UINT8 const _START_ADDRS[] = "APPEX-START ";
    static UINT8 const _BUILD_NUM[4] = { APX_BUILD_NUMBER_VAL };

    struct _PCAP_FILE_START
    {
        PCAP_FILE_HDR   FileHeader;
        PCAP_PACKET_HDR PacketHeader;
        APX_ETH_HEADER  EthHeader;
        UINT8           BuildNum[4];
        UINT32          EngineFlags;
    } start;

    struct file *filp;
    APX_ENGINE_FLAGS flags;

    filp = _k_file_open(fileName, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
    if (filp == NULL)
#else
    if (filp == NULL || filp->f_op->write == NULL)
#endif
    {
        printk("appex: can't open pcap file %s\n", fileName);
        _k_file_close(filp);
        return NULL;
    }

    if (OpaqueEngine->Engine == NULL ||
        APX_FAILED(APX_EngineGetEngineFlags(OpaqueEngine->Engine, &flags)))
    {
        flags = APX_ENGINE_FLAG_NONE;
    }

    memset(&start, 0, sizeof(start));
    start.FileHeader.Magic = 0xa1b2c3d4;
    start.FileHeader.Major = 2;
    start.FileHeader.Minor = 4;
    start.FileHeader.Thiszone = 0;
    start.FileHeader.Sigfigs = 0;
    start.FileHeader.Snaplen = 0xffff;
    start.FileHeader.Linktype = 1;
    start.PacketHeader.Secs = tm->tv_sec;
    start.PacketHeader.USecs = tm->tv_usec;
    start.PacketHeader.Len = sizeof(start) - sizeof(start.FileHeader) - sizeof(start.PacketHeader);
    start.PacketHeader.Caplen = start.PacketHeader.Len;
    memcpy(&start.EthHeader, _START_ADDRS, 2 * APX_ETH_ADDR_LEN);
    start.EthHeader.TypeLen = 0xffff;
    memcpy(start.BuildNum, _BUILD_NUM, sizeof(start.BuildNum));
    start.EngineFlags = htonl(flags);
    APX_IO_WRITE(filp, (void *)&start, sizeof(start));

    return filp;
}

static BOOL _pcapStart(APX_OPAQUE_ENGINE* OpaqueEngine)
{
    struct timeval tm;
    char filename[100];

    down(&_pcapSem);
    {
        do_gettimeofday(&tm);

        APX_APRINTF(filename, "/appex/log/%d/lan%d.pcap", OpaqueEngine->EngineId, OpaqueEngine->PcapFileNum);
        if (!(OpaqueEngine->PcapLanFilp = _pcapOpenFile(OpaqueEngine, filename, &tm)))
        {
            up(&_pcapSem);
            return FALSE;
        }

        APX_APRINTF(filename, "/appex/log/%d/wan%d.pcap", OpaqueEngine->EngineId, OpaqueEngine->PcapFileNum);
        if (!(OpaqueEngine->PcapWanFilp = _pcapOpenFile(OpaqueEngine, filename, &tm)))
        {
            _k_file_close(OpaqueEngine->PcapLanFilp);
            up(&_pcapSem);
            return FALSE;
        }
    }

    OpaqueEngine->PcapFileLanLen = OpaqueEngine->PcapFileWanLen = 0;
    OpaqueEngine->PcapFileNum++;
    OpaqueEngine->PcapFileNum = OpaqueEngine->PcapFileNum % OpaqueEngine->PcapFileTotalNum;

    up(&_pcapSem);

    OpaqueEngine->PcapEnable = 1;
    smp_wmb();

    return TRUE;
}

static void _pcapStop(APX_OPAQUE_ENGINE* OpaqueEngine)
{
    OpaqueEngine->PcapEnable = 0;
    smp_wmb();

    down(&_pcapSem);
    if (OpaqueEngine->PcapLanFilp)
    {
        _k_file_close(OpaqueEngine->PcapLanFilp);
        OpaqueEngine->PcapLanFilp = NULL;
    }
    if (OpaqueEngine->PcapWanFilp)
    {
        _k_file_close(OpaqueEngine->PcapWanFilp);
        OpaqueEngine->PcapWanFilp = NULL;
    }
    up(&_pcapSem);
}

static
void
appexPcapLogData(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    struct sk_buff *Skb,
    UINT32 Len,
    UINT32 Padding,
    BOOL LanPkt
    )
{
    struct timeval tm;
    PCAP_PACKET_HDR h;

    do_gettimeofday(&tm);
    h.Secs  = tm.tv_sec;
    h.USecs = tm.tv_usec;

    h.Len = Len + Padding;
    if (OpaqueEngine->PcapPktLen != 0 && h.Len > OpaqueEngine->PcapPktLen &&
        OpaqueEngine->PcapPktLen > Padding)
    {
        Len = OpaqueEngine->PcapPktLen - Padding;
    }
    h.Caplen = Len + Padding;

    if (!_appexIoQueueWork(OpaqueEngine, LanPkt? APX_IO_EVENT_LAN_PCAP : APX_IO_EVENT_WAN_PCAP,
        sizeof(h), &h, Len, Skb, (int)Padding))
    {
        OpaqueEngine->PcapDiscard++;
    }
}

BOOL
appexFilterLogPacket(
    APX_OPAQUE_ENGINE const* OpaqueEngine,
    UINT32 SrcIp,
    UINT32 DstIp,
    UINT8 Proto
    )
{
    if (OpaqueEngine->PcapFilterIP[0] != 0)
    {
        UINT i = 0;
        for ( ; ; )
        {
            UINT32 ip4 = OpaqueEngine->PcapFilterIP[i];
            UINT8 mask = OpaqueEngine->PcapFilterIPMask[i];
            UINT8 shift = mask == 0 ? 0 : 32 - mask;
            if (((SrcIp ^ ip4) >> shift) == 0 || ((DstIp ^ ip4) >> shift) == 0)
            {
                break;
            }
            if (++i >= ARRAY_SIZE(OpaqueEngine->PcapFilterIP) ||
                OpaqueEngine->PcapFilterIP[i] == 0)
            {
                return TRUE;
            }
        }
    }

    DstIp ^= SrcIp;
    DstIp = (DstIp >> 16) ^ (DstIp & 0xFFFF);
    if (OpaqueEngine->PcapFilterSplit && (DstIp & ((1 << OpaqueEngine->PcapFilterSplit) - 1)))
    {
        return TRUE;
    }

    if (OpaqueEngine->PcapFilterProto && OpaqueEngine->PcapFilterProto != Proto)
    {
        return TRUE;
    }

    return FALSE;
}

void
appexPcapLogPacket(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    struct sk_buff *skb,
    BOOL LanPkt,
    APX_PCAP_TYPE Type
    )
{
    struct file *filp = LanPkt? OpaqueEngine->PcapLanFilp : OpaqueEngine->PcapWanFilp;
    UINT8 *data, padding, is_ipv4 = 1;
    UINT32 len, hasCopy = 0;

    if (!OpaqueEngine->PcapEnable)  return;

    if (!filp) return;

    if (skb_is_nonlinear(skb) && !pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    if (Type == APX_PCAP_NORMAL)
    {
        struct iphdr *ipHdr = (struct iphdr *)SKB_L3_HDR(skb);

        if (ipHdr->version == 4)
        {
            if (appexFilterLogPacket(OpaqueEngine,ntohl(ipHdr->saddr), ntohl(ipHdr->daddr), ipHdr->protocol))
            {
                return;
            }
        }
        else
        {
            /* if pcap filter is on, do NOT log v6 traffic. */
            if (OpaqueEngine->PcapFilterIP[0] != 0)
            {
                return;
            }
            if (OpaqueEngine->PcapFilterSplit != 0 || OpaqueEngine->PcapFilterProto != 0)
            {
                return;
            }
            is_ipv4 = 0;
        }
    }

    if (skb_is_nonlinear(skb))
    {
        if (!(skb = skb_copy(skb, GFP_ATOMIC)))
            return;
        hasCopy = 1;
    }

    if (Type == APX_PCAP_MARKER || OpaqueEngine->WanIF.WanBridgeMode)
    {
        data = SKB_L2_HDR(skb);
        padding = 0;
    }
    else
    {
        data = SKB_L3_HDR(skb);
        padding = 14;
    }
    len = SKB_TAIL(skb) - data;
    appexPcapLogData(OpaqueEngine, skb, len, padding, LanPkt);

    if (hasCopy)
        kfree_skb(skb);
}

static void
_delayedPcapLoss(
    struct file* Filp,
    APX_IO_EVENT const* Wq
    )
{
    if (Filp != NULL)
    {
        static UINT8 const _APX_PCAP_LOSS_ADDRS[] = "APPEX-LOSS*";

        typedef struct _APX_PCAP_LOSS
        {
            APX_ETH_HEADER          EthHeader;
            UINT16                  Params;
        }
        APX_PCAP_LOSS;

        struct _APX_PCAP_LOSS_MARKER
        {
            PCAP_PACKET_HDR         PcapHeader;
            APX_PCAP_LOSS           Data;
        }
        pcapMarker;

        APX_C_ASSERT(sizeof(_APX_PCAP_LOSS_ADDRS) == 12);

        APX_BaseMemZero(&pcapMarker, sizeof(pcapMarker));
        APX_BaseMemCopy(&pcapMarker.PcapHeader, Wq->Log.AuxData, sizeof(Wq->Log.AuxData));
        pcapMarker.PcapHeader.Caplen = sizeof(pcapMarker.Data);
        pcapMarker.PcapHeader.Len = sizeof(pcapMarker.Data);
        APX_BaseMemCopy(pcapMarker.Data.EthHeader.DstAddr, _APX_PCAP_LOSS_ADDRS, 12);
        pcapMarker.Data.EthHeader.TypeLen = APX_HTONS(0xFFFF);
        pcapMarker.Data.Params = APX_HTONS(Wq->SubType & 0x70);

        APX_IO_WRITE(Filp, &pcapMarker, sizeof(pcapMarker));
    }
}

static void
_delayedPcap(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    APX_IO_EVENT const* Wq
    )
{
    UINT32 *pPcapFileLen;
    struct file* filp;

    if (Wq->Type == APX_IO_EVENT_LAN_PCAP)
    {
        pPcapFileLen = &OpaqueEngine->PcapFileLanLen;
        filp = OpaqueEngine->PcapLanFilp;
    }
    else
    {
        pPcapFileLen = &OpaqueEngine->PcapFileWanLen;
        filp = OpaqueEngine->PcapWanFilp;
    }

    if (filp && OpaqueEngine->PcapEnable)
    {
        APX_IO_WRITE(filp, Wq->Log.Data, Wq->Log.Len);

        if (Wq->SubType != 0)
        {
            if ((Wq->SubType & 0x01) != 0)
            {
                _delayedPcapLoss(OpaqueEngine->PcapLanFilp, Wq);
            }

            if ((Wq->SubType & 0x02) != 0)
            {
                _delayedPcapLoss(OpaqueEngine->PcapWanFilp, Wq);
            }
        }

        *pPcapFileLen += Wq->Log.Len;
        if (*pPcapFileLen >= OpaqueEngine->PcapFileSize)
        {
            up(&_pcapSem);
            _pcapStop(OpaqueEngine);
            _pcapStart(OpaqueEngine);
            down(&_pcapSem);
        }
    }
}

/*******************************************************************************
 * SYN-retransmission
 ******************************************************************************/

#ifdef APXENV_SYN_RETRAN

static
int
_appexIoSetSynRetran(
    __inout APX_OPAQUE_ENGINE* OpaqueEngine,
    __in UINT16 SynRetranMS
    )
{
    int ret = 0;

    APX_UNREFERENCED(OpaqueEngine);

    if (gApxBaseSharedInfo != NULL)
    {
        UINT16* rttArray = NULL;
        enum _ACT { ACT_NONE, ACT_ALLOC, ACT_FREE } action = ACT_NONE;

        spin_lock_bh(&gApxBaseSharedInfo->RttMgr.Lock);

        rttArray = gApxBaseSharedInfo->RttMgr.RttArray;

        if (SynRetranMS > 0 && rttArray == NULL)
        {
            action = ACT_ALLOC;
        }
        else if (SynRetranMS == 0 && rttArray != NULL)
        {
            action = ACT_FREE;
            gApxBaseSharedInfo->RttMgr.RttArray = NULL;
            APX_ECfg.SynRetranMS = SynRetranMS;
        }
        else
        {
            APX_ECfg.SynRetranMS = SynRetranMS;
        }

        spin_unlock_bh(&gApxBaseSharedInfo->RttMgr.Lock);

        if (action == ACT_ALLOC)
        {
            rttArray = (UINT16*)vmalloc(sizeof(UINT16) * APX_NET24_ENTRIES);

            if (rttArray != NULL)
            {
                memset(rttArray, 0, sizeof(UINT16) * APX_NET24_ENTRIES);
                spin_lock_bh(&gApxBaseSharedInfo->RttMgr.Lock);

                if (gApxBaseSharedInfo->RttMgr.RttArray == NULL)
                {
                    gApxBaseSharedInfo->RttMgr.RttArray = rttArray;
                    rttArray = NULL;
                }

                APX_ECfg.SynRetranMS = SynRetranMS;
                spin_unlock_bh(&gApxBaseSharedInfo->RttMgr.Lock);
            }
            else
            {
                ret = -ENOMEM;
            }
        }

        if (action != ACT_NONE && rttArray != NULL)
        {
            vfree(rttArray);
        }
    }
    else
    {
        ret = -EAGAIN;
    }

    return ret;
}

#endif /* APXENV_SYN_RETRAN */

/*******************************************************************************
 * IO Work Queue
 ******************************************************************************/
static
BOOL
_appexIoQueueWork(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    UINT16 type,
    UINT16 len1,
    void *data1,
    UINT16 len2,
    void *data2,
    int padding
    )
{
    unsigned long flags;
    APX_IO_EVENT *wq;
    int maxBufLen = gApxPcapMaxBufLen;
    UINT8 subType = type == APX_IO_EVENT_LAN_PCAP ? 0x01 : 0x02; /* bitmap: 1 - LAN, 2 - WAN. */

    if (atomic_read(&OpaqueEngine->IoWqTotalLen) > maxBufLen)
    {
        subType |= 0x10;
    }
    else if (!(wq = (APX_IO_EVENT*)APX_BaseMemAlloc(sizeof(*wq) + len1 + len2 + padding)))
    {
        subType |= 0x20;
    }
    else
    {
        wq->Type = type;
        wq->SubType = 0;
        wq->Log.Len = len1 + len2 + padding;
        if (len1) APX_BaseMemCopy(wq->Log.Data, data1, len1);

        if (type == APX_IO_EVENT_LAN_PCAP || type == APX_IO_EVENT_WAN_PCAP)
        {
            struct sk_buff* skb = (struct sk_buff*)data2;

            if (!padding)
            {
                data2 = SKB_L2_HDR(skb);
            }
            else
            {
                APX_BaseMemSet(wq->Log.Data + len1, 0x02, padding);
                data2 = SKB_L3_HDR(skb);

                if (((struct iphdr const*)data2)->version == 4)
                {
                    wq->Log.Data[len1 + padding - 2] = 0x08;
                    wq->Log.Data[len1 + padding - 1] = 0x00;
                }
                else
                {
                    wq->Log.Data[len1 + padding - 2] = 0x86;
                    wq->Log.Data[len1 + padding - 1] = 0xdd;
                }

                if (padding >= 14)
                {
                    APX_OPAQUE_PACKET const* const opkt = (APX_OPAQUE_PACKET const*)skb->cb;
                    UINT8* d = wq->Log.Data + len1;
                    UINT32 tid = APX_IF_LTT(APX_OPAQUE_PACKET_TID(opkt) +) 0;
                    UINT32 policyId = opkt->PolicyId;
                    d[0] = (UINT8)(APX_OPAQUE_PACKET_FLAGS(opkt) >> 8);
                    d[1] = (UINT8)(APX_OPAQUE_PACKET_FLAGS(opkt));
                    d[2] = (UINT8)(tid >> 24);
                    d[3] = (UINT8)(tid >> 16);
                    d[4] = (UINT8)(tid >> 8);
                    d[5] = (UINT8)(tid);
                    d[6] = (UINT8)(policyId >> 24);
                    d[7] = (UINT8)(policyId >> 16);
                    d[8] = (UINT8)(policyId >> 8);
                    d[9] = (UINT8)(policyId);
                    d[10] = opkt->Priority;
                }
            }
        }

        if (len2) APX_BaseMemCopy(wq->Log.Data + len1 + padding, data2, len2);
        atomic_add(wq->Log.Len, &OpaqueEngine->IoWqTotalLen);

        spin_lock_irqsave(&OpaqueEngine->IoWqLock, flags);
        APX_ListInsertTailNode(&OpaqueEngine->IoWqList.List, &wq->List);
        spin_unlock_irqrestore(&OpaqueEngine->IoWqLock, flags);

        schedule_work(&OpaqueEngine->IoWq);
        return TRUE;
    }

    if (type == APX_IO_EVENT_LAN_PCAP || type == APX_IO_EVENT_WAN_PCAP)
    {
        BOOL marked = FALSE;
        spin_lock_irqsave(&OpaqueEngine->IoWqLock, flags);

        if (!APX_ListIsEmpty(&OpaqueEngine->IoWqList.List))
        {
            wq = APX_CONTAINER(OpaqueEngine->IoWqList.List.Prev, APX_IO_EVENT, List);

            if ((wq->Type == APX_IO_EVENT_LAN_PCAP || wq->Type == APX_IO_EVENT_WAN_PCAP) &&
                len1 >= sizeof(wq->Log.AuxData))
            {
                if (wq->SubType == 0)
                {
                    /* copy timestamp from PCAP header. */
                    APX_BaseMemCopy(wq->Log.AuxData, data1, sizeof(wq->Log.AuxData));
                }

                wq->SubType |= subType;
                marked = TRUE;
            }
        }

        if (!marked)
        {
            OpaqueEngine->PcapNoResource++;
        }

        spin_unlock_irqrestore(&OpaqueEngine->IoWqLock, flags);
    }

    return FALSE;
}

static void _ioWqHandler(struct work_struct *work)
{
    unsigned long flags;
    APX_IO_EVENT *wq, *next;
    APX_OPAQUE_ENGINE* opaqueEngine;
    APX_BASE_NETIF *wanIf;

    opaqueEngine = container_of(work, APX_OPAQUE_ENGINE, IoWq);
    wanIf = &opaqueEngine->WanIF;

#ifdef CONFIG_SMP
    if (test_and_clear_bit(APX_BASE_FLAG_IO_WQ_IPI, &wanIf->flags) &&
        !test_bit(TASKLET_STATE_RUN, &opaqueEngine->Tasklet.state) &&
        !test_bit(TASKLET_STATE_SCHED, &opaqueEngine->Tasklet.state) && wanIf->Tasklet)
    {
        int cpu = get_cpu();

        if (cpu == wanIf->CpuId)
        {
            tasklet_schedule(wanIf->Tasklet);
        }
        else
        {
            APX_SMP_CALL_FUNCTION(appexTaskletIpiFunc, wanIf, 0, 0, wanIf->CpuId);
        }

        put_cpu();

        wanIf->IpiNum++;
        if (APX_ListIsEmpty(&opaqueEngine->IoWqList.List)) return;
    }
#endif

    if (atomic_dec_and_test(&opaqueEngine->IoWqReEntry))
    {
        BOOL more = TRUE;
        UINT32 lastTime = jiffies;

        while (more)
        {
            more = FALSE;

            spin_lock_irqsave(&opaqueEngine->IoWqLock, flags);
            wq = APX_CONTAINER(opaqueEngine->IoWqList.List.Next, APX_IO_EVENT, List);
            APX_ListInit(&opaqueEngine->IoWqList.List);
            spin_unlock_irqrestore(&opaqueEngine->IoWqLock, flags);

            while (wq != &opaqueEngine->IoWqList)
            {
                more = TRUE;

                /* Add a little bit yield. */
                if ((UINT32)(jiffies - lastTime) >= HZ / 2)
                {
                    msleep(1);
                    lastTime = jiffies;
                }

                next = APX_CONTAINER(wq->List.Next, APX_IO_EVENT, List);
                switch (wq->Type)
                {
                    case APX_IO_EVENT_TRACE:
                    case APX_IO_EVENT_TRACE_HTTP:
                    case APX_IO_EVENT_TRACE_HTTP_START:
                    case APX_IO_EVENT_TRACE_HTTP_STOP:
                        break;
                    case APX_IO_EVENT_LAN_PCAP:
                    case APX_IO_EVENT_WAN_PCAP:
                        down(&_pcapSem);
                        _delayedPcap(opaqueEngine, wq);
                        up(&_pcapSem);
                        break;
                    default:
                        APX_ASSERT(0);
                        break;
                }

                atomic_sub(wq->Log.Len, &opaqueEngine->IoWqTotalLen);
                APX_BaseMemFree(wq);
                wq = next;
            }
        }
    }
    atomic_inc(&opaqueEngine->IoWqReEntry);
}
#endif /* !(APXENV_PCAP_ENABLE) */

APX_FORCE_INLINE void APX_TASKLET_SCHEDULE(APX_BASE_NETIF *wanIf)
{
#ifdef CONFIG_SMP
    int cpu = get_cpu();

    if (cpu == wanIf->CpuId)
    {
        tasklet_schedule(wanIf->Tasklet);
    }
    else
    {
        APX_SMP_CALL_FUNCTION(appexTaskletIpiFunc, wanIf, 0, 0, wanIf->CpuId);
    }

    put_cpu();
#else
    tasklet_schedule(wanIf->Tasklet);
#endif
}

/*******************************************************************************
 * PROC implementation
 ******************************************************************************/
static APX_BASE_DECLARE_MUTEX(_ioSem);

static int
_open(
    struct inode *inode,
    struct file *filp
    )
{
    filp->private_data = PDE_DATA(inode);
    return 0;
}

static int
_release(
    struct inode *inode,
    struct file *filp
    )
{
    return 0;
}

static int
_ioctlGet(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    unsigned long arg
    )
{
    int ret = 0;
    APX_BASE_IOCTL_INFO info;
    APX_CLSF_ENGINE *clsf = APX_EClsfGet(OpaqueEngine->Engine);

    if (copy_from_user(&info, (void *)arg, APX_OFFSET_OF(APX_BASE_IOCTL_INFO, Buf[0])))
    {
        printk(KERN_ERR "IoctlGet failed\n");
        return -EFAULT;
    }
    arg += APX_OFFSET_OF(APX_BASE_IOCTL_INFO, Buf[0]);

    switch (info.Type)
    {
        case APX_BASE_IOCTL_SYS_INFO:
        {
            APX_BASE_SYS_INFO data;
            APX_ENGINE_STATISTICS engStats;
            if (info.Len != sizeof(data))
            {
                return -EINVAL;
            }
            APX_BaseMemSet(&engStats, 0, sizeof(engStats));
            APX_EngineGetEngineStatistics(OpaqueEngine->Engine, &engStats);
            data.HostNum = clsf->HostAggrNum - 1;
            data.SessNum =  clsf->SystemAggrNode->Stats->Sessions;
            data.TcpAccSessNum = clsf->SystemAggrNode->Stats->TcpAccSessions;
            data.TotalTcpAccSessNum = engStats.V4.NumOfAccFlows + engStats.V6.NumOfAccFlows;
            data.TcpActSessNum =  clsf->SystemAggrNode->Stats->TcpActSessions;
            data.UdpSessNum = clsf->SystemAggrNode->Stats->UdpSessions;
            data.NumOfCompLinks = engStats.NumOfCompLinks;
            if (copy_to_user((void *)arg, &data, info.Len))
            {
                return -EFAULT;
            }
            break;
        }

        case APX_BASE_IOCTL_CLSF_STATS:
        {
            APX_IO_EVENT event;
            APX_STATUS ret;
            UINT32 offset = APX_OFFSET_OF(APX_CLSF_STATS, Stats[0]);
            APX_CLSF_STATS *stats = (APX_CLSF_STATS*)vmalloc(info.Len);

            if (!stats)
            {
                return -ENOMEM;
            }
            else if (info.Len < offset ||
                copy_from_user(stats, (void *)arg, info.Len) ||
                ((stats->Type & APX_CLSF_GET_STATS_DATA) && info.Len < offset +
                stats->NumStats * sizeof(APX_CLSF_STATS_INFO)))
            {
                vfree(stats);
                return -EINVAL;
            }

            event.Type = APX_IO_EVENT_IOCTL_GET_STATS;
            event.HoldMem = 1;
            event.ProcData.Done = 0;
            event.ProcData.Data = stats;
            event.ProcData.Result = APX_STATUS_OK;
            appexIoAddEvents(OpaqueEngine, &event);
            wait_event(OpaqueEngine->WaitQeue, event.ProcData.Done != 0);
            if (event.ProcData.Result != APX_STATUS_OK)
            {
                ret = -EINVAL;
            }
            else if (copy_to_user((void *)arg, stats, info.Len))
            {
                ret = -EFAULT;
            }

            vfree(stats);
            break;
        }

        case APX_BASE_IOCTL_COMP_STATS:
        {
            APX_IO_EVENT event;
            APX_BASE_COMP_STATS stats;

            if (info.Len != sizeof(stats))
            {
                return -EINVAL;
            }

            event.Type = APX_IO_EVENT_IOCTL_GET_COMP_STATS;
            event.HoldMem = 1;
            event.ProcData.Done = 0;
            event.ProcData.Data = &stats;
            event.ProcData.Result = APX_STATUS_OK;
            appexIoAddEvents(OpaqueEngine, &event);
            wait_event(OpaqueEngine->WaitQeue, event.ProcData.Done != 0);

            if (copy_to_user((void*)arg, &stats, sizeof(stats)))
            {
                return -EFAULT;
            }

            break;
        }

        default:
        {
            APX_TRACE_ERROR((_T("CONFIG_GET: unknown ID %u\n"), info.Type));
            ret = -EINVAL;
        }
    }

    return ret;
}

static int
_ioctlSet(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    unsigned long arg
    )
{
    int ret = 0;
    APX_BASE_IOCTL_INFO info;

    if (copy_from_user(&info, (void *)arg, APX_OFFSET_OF(APX_BASE_IOCTL_INFO, Buf[0])))
    {
        printk(KERN_ERR "IoctlSet failed\n");
        return -EFAULT;
    }
    arg += APX_OFFSET_OF(APX_BASE_IOCTL_INFO, Buf[0]);

    switch (info.Type)
    {
        case APX_BASE_IOCTL_CLSF_CFG:
        {
            APX_IO_EVENT event;
            APX_CLSF_CFG *cfg = (APX_CLSF_CFG*)vmalloc(info.Len);

            if (!cfg)
            {
                return -ENOMEM;
            }
            else if (copy_from_user((UINT8*)cfg, (UINT8 *)arg, info.Len) ||
                info.Len != cfg->Len + APX_OFFSET_OF(APX_CLSF_CFG, Cfg[0]))
            {
                printk(KERN_ERR "CLSF_CFG failed, bufLen=%u, cfg=%p, cfgLen=%u, arg=0x%lx\n",
                    info.Len, cfg, cfg?cfg->Len:-1, arg);
                vfree(cfg);
                return -EFAULT;
            }

            event.Type = APX_IO_EVENT_IOCTL_SET_CONFIG;
            event.SubType = cfg->Type;
            event.HoldMem = 1;
            event.ProcData.Done = 0;
            event.ProcData.Data = cfg;
            event.ProcData.Result = 0;

            if (cfg->Type >= APX_CLSF_CFG_TYPE_MAX)
            {
                printk(KERN_ERR "appex: invalid cfg type %d\n", cfg->Type);
                vfree(cfg);
                return -EINVAL;
            }

            appexIoAddEvents(OpaqueEngine, &event);
            wait_event(OpaqueEngine->WaitQeue, event.ProcData.Done != 0);
            if (event.ProcData.Result != APX_STATUS_OK)
            {
                ret = -EINVAL;
            }

            if (cfg) vfree(cfg);
            break;
        }

        default:
        {
            APX_TRACE_ERROR((_T("CONFIG_SET: unknown ID %u\n"), info.Type));
            ret = -EINVAL;
        }
    }

    return ret;
}

enum
{
    PROC_DATA_wanKbps,
    PROC_DATA_wanBurstBytes,
    PROC_DATA_tcpAccEnable,
    PROC_DATA_dataCompEnable,
    PROC_DATA_voipAccEnable,
    PROC_DATA_voipSkipPackets,
    PROC_DATA_advAccEnable,
    PROC_DATA_subnetAccEnable,
    PROC_DATA_shaperEnable,
    PROC_DATA_stats,
    PROC_DATA_version,
    PROC_DATA_hostFairTcpAccSessNum,
    PROC_DATA_pcapEnable,
    PROC_DATA_hostFairEnable,
    PROC_DATA_wanInKbps,
    PROC_DATA_wanInBurstBytes,
    PROC_DATA_hostFairUdpSessNum,
    PROC_DATA_wanRateAutoDetect,
    PROC_DATA_cmd,
    PROC_DATA_hostFairTcpActSessNum,
    PROC_DATA_trackRandomLoss,
    PROC_DATA_maxTxEnable,
    PROC_DATA_conservMode,
    PROC_DATA_engSysEnable,
    PROC_DATA_srtt,
};

#ifdef HAVE_UNLOCKED_IOCTL
static long
_ioctl(
    struct file *filp,
    unsigned int cmd,
    unsigned long arg
    )
#else
static int
_ioctl(
    struct inode *node,
    struct file *filp,
    unsigned int cmd,
    unsigned long arg
    )
#endif
{
    int ret = 0;
    APX_OPAQUE_ENGINE *opaqueEngine;

    if (_IOC_TYPE(cmd) != APX_IOCTL_MAGIC)
    {
        return -ENOTTY;
    }

    if (gApxTerminating) return -EFAULT;

    opaqueEngine = (APX_OPAQUE_ENGINE *)filp->private_data;

    down(&_ioSem);

    switch (cmd)
    {
        case APX_IOCTL_GET:
        {
            ret = _ioctlGet(opaqueEngine, arg);
            break;
        }

        case APX_IOCTL_SET:
        {
            ret = _ioctlSet(opaqueEngine, arg);
            break;
        }

        default:
        {
            ret = -EFAULT;
            break;
        }
    }

    up(&_ioSem);
    return ret;
}

#ifdef APX_FULL_CLSF
static void _vmaOpen(struct vm_area_struct *vma)
{
    APX_UNREFERENCED(vma);
    /*printk(KERN_INFO "ioctl: vma open, virt %lx, phys %x\n",
        vma->vm_start, (unsigned int) (vma->vm_pgoff << PAGE_SHIFT));*/
}

static void _vmaClose(struct vm_area_struct *vma)
{
    APX_UNREFERENCED(vma);
    /*printk(KERN_INFO "ioctl: vma close.\n");*/
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
struct page*
_vmaNoPage(
    struct vm_area_struct *vma,
    unsigned long address,
    int *type
    )
{
    /* For now this function is only used by clsf stats. */
    void *pageVirt;
    struct page *pagePtr;
    APX_OPAQUE_ENGINE *opaqueEngine = (APX_OPAQUE_ENGINE *)vma->vm_private_data;
    APX_MEM_POOL *pool = &opaqueEngine->MemPool[APX_MEM_POOL_CLSF_STATS];
    unsigned long num = (address - vma->vm_start) >> PAGE_SHIFT, num1, num2;

    num1 = num >> APX_MEM_POOL_TBL_ORDER;
    num2 = num - (num1 << APX_MEM_POOL_TBL_ORDER);

    if (num2 >= APX_MEM_POOL_TBL_SIZE || !pool->PageRoot || !pool->PageRoot->PageDir[num1] ||
        !(pageVirt = pool->PageRoot->PageDir[num1]->Page[num2]))
    {
        return NOPAGE_SIGBUS;
    }

    pagePtr = virt_to_page(pageVirt);
    get_page(pagePtr);

    if (type) *type = VM_FAULT_MINOR;

    return pagePtr;
}
#else /* >= 2.6.26, use fault() function instead of nopage(). */
static int
_vmaFault(
    struct vm_area_struct *vma,
    struct vm_fault *vmf
    )
{
    /* For now this function is only used by clsf stats. */
    void *pageVirt;
    APX_OPAQUE_ENGINE *opaqueEngine = (APX_OPAQUE_ENGINE *)vma->vm_private_data;
    APX_MEM_POOL *pool = &opaqueEngine->MemPool[APX_MEM_POOL_CLSF_STATS];
    unsigned long num = vmf->pgoff - vma->vm_pgoff;
    unsigned long num1 = num >> APX_MEM_POOL_TBL_ORDER;
    unsigned long num2 = num - (num1 << APX_MEM_POOL_TBL_ORDER);

    if (num2 >= APX_MEM_POOL_TBL_SIZE || !pool->PageRoot || !pool->PageRoot->PageDir[num1] ||
        !(pageVirt = pool->PageRoot->PageDir[num1]->Page[num2]))
    {
        return VM_FAULT_SIGBUS;
    }

    vmf->page = virt_to_page(pageVirt);
    get_page(vmf->page);
    return 0;
}
#endif

static struct vm_operations_struct _vmOps =
{
    .open = _vmaOpen,
    .close = _vmaClose,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
    .nopage = _vmaNoPage
#else
    .fault = _vmaFault
#endif
};

static int
_mmap(
    struct file *filp,
    struct vm_area_struct *vma
    )
{
    vma->vm_flags &= ~(VM_WRITE | VM_EXEC);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
    vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
#else
    vma->vm_flags |= VM_RESERVED;
#endif
    vma->vm_ops = &_vmOps;

    vma->vm_private_data = filp->private_data;

    _vmaOpen(vma);

    return 0;
}
#endif  /* !APX_FULL_CLSF */

static struct file_operations _ioctl_proc_ops =
{
    .open               = _open,
    .release            = _release,
#ifdef HAVE_UNLOCKED_IOCTL
    .unlocked_ioctl     = _ioctl,
#else
    .ioctl              = _ioctl,
#endif
#ifdef APX_FULL_CLSF
    .mmap               = _mmap,
#endif  /* !APX_FULL_CLSF */
    .owner              = THIS_MODULE
};

static int _printClsfInfo(APX_OPAQUE_ENGINE *OpaqueEngine, char *p, size_t size);
static int _printDefaultInfo(APX_OPAQUE_ENGINE *OpaqueEngine, char *p, size_t size);

#define _STRCMP_CONST(_str_, _const_str_) \
({ \
    static char const _CONST_STR_[] = _const_str_; \
    APX_SafeStrCmp((_str_), _CONST_STR_, ARRAY_SIZE(_CONST_STR_)-1); \
})


static void
_getBw(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    APX_BANDWIDTH *Bw,
    APX_DIRECTIONS direction
    )
{
    if (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER)
    {
        APX_EngineGetWanIfBandwidth(OpaqueEngine->Engine, direction, &Bw->Bpms);
        APX_EngineGetWanIfBurst(OpaqueEngine->Engine, direction, &Bw->BurstBytes);
    }
    else
    {
        if (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO)
        {
            *Bw = OpaqueEngine->Cfg.Bw[(direction==APX_OUTBOUND)? 0 : 1];
            (void)APX_EngineGetRadAdaptedBandwidth(OpaqueEngine->Engine, direction, &Bw->Bpms);
        }
        else
        {
            *Bw = OpaqueEngine->Cfg.Bw[(direction==APX_OUTBOUND)? 0 : 1];
        }
    }
}

static int
_settingsReadFunc(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    char *page,
    unsigned long size,
    void *data
    )
{
    APX_BANDWIDTH bw;
    UINT32 value = 0;
    APX_BASE_NETIF *wanIf = &OpaqueEngine->WanIF;
#if !defined(APXENV_NO_CLSF) || !defined(APXENV_NO_RAD)
    APX_CLSF_ENGINE const* clsf = APX_EClsfGet(OpaqueEngine->Engine);
#endif

    switch ((unsigned long) data)
    {
        case PROC_DATA_wanKbps:
            _getBw(OpaqueEngine, &bw, APX_OUTBOUND);
            value = bw.Bpms * 8;
            break;
        case PROC_DATA_wanBurstBytes:
            _getBw(OpaqueEngine, &bw, APX_OUTBOUND);
            value = bw.BurstBytes;
            break;
        case PROC_DATA_tcpAccEnable:
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_FLOW_CTRL)? 1 : 0;
            break;
        case PROC_DATA_dataCompEnable:
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_DATA_COMP)? 1 : 0;
            break;
        case PROC_DATA_voipAccEnable:
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_VOIP_FIRST)? 1 : 0;
            break;
        case PROC_DATA_voipSkipPackets:
            value = APX_ECfg.ClsfVoipSkipPackets;
            break;
        case PROC_DATA_advAccEnable:
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SPC_ACK)? 1 : 0;
            break;
        case PROC_DATA_subnetAccEnable:
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_ACC_SUBNET)? 1 : 0;
            break;
        case PROC_DATA_shaperEnable:
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER)? 1 : 0;
            break;
        case PROC_DATA_stats:
        {
            switch (OpaqueEngine->Cfg.DisplayLevel)
            {
                case 255:
                    return _printClsfInfo(OpaqueEngine, page, size);
                default:
                    return _printDefaultInfo(OpaqueEngine, page, size);
            }
        }
        case PROC_DATA_version:
            return APX_SNPrintf(page, size, "%s\n", APX_BUILD_NUMBER_STR);
        case PROC_DATA_hostFairTcpAccSessNum:
            value = APX_ECfg.ClsfHostFairMaxTcpAccSess;
            break;
        case PROC_DATA_pcapEnable:
            value = OpaqueEngine->PcapEnable? 1 : 0;
            break;
        case PROC_DATA_hostFairEnable:
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_HOST_FAIR)? 1 : 0;
            break;
        case PROC_DATA_wanInKbps:
            _getBw(OpaqueEngine, &bw, APX_INBOUND);
            value = bw.Bpms * 8;
            break;
        case PROC_DATA_wanInBurstBytes:
            _getBw(OpaqueEngine, &bw, APX_INBOUND);
            value = bw.BurstBytes;
            break;
        case PROC_DATA_hostFairUdpSessNum:
        {
            value = APX_ECfg.ClsfHostFairMaxUdpSess;
            break;
        }
        case PROC_DATA_wanRateAutoDetect:
        {
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO)? 1 : 0;
            break;
        }
        case PROC_DATA_cmd:
        {
            char *p = page;
            char const* end = page + size;
            p = APX_SEPrintf(p, end, "engine: %u %u %u\n",
                OpaqueEngine->Param.MaxNumOfFlows,
                OpaqueEngine->Param.MaxNumOfAccFlows,
                OpaqueEngine->Param.MaxNumOfCompFlows);
            p = APX_SEPrintf(p, end, "displayLevel: %u\n", (UINT32)OpaqueEngine->Cfg.DisplayLevel);
            p = APX_SEPrintf(p, end, "hz: %d\n", (int)HZ);
#ifndef APXENV_NO_RAD
            p = APX_SEPrintf(p, end, "tcpRttVarThreshold: %d\n", clsf->TcpRttVarThreshold);
            p = APX_SEPrintf(p, end, "inRateReductFactor: %d\n", APX_ECfg.ClsfWanAutoInRateReductFactor);
            p = APX_SEPrintf(p, end, "outRateReductFactor: %d\n", APX_ECfg.ClsfWanAutoOutRateReductFactor);
            p = APX_SEPrintf(p, end, "inRateDiscount: %d\n", APX_ECfg.ClsfWanAutoInRateDiscount);
            p = APX_SEPrintf(p, end, "inStartRate: %u\n", clsf->WanStartRate[1]/1024);
            p = APX_SEPrintf(p, end, "outStartRate: %u\n", clsf->WanStartRate[0]/1024);
#endif
            p = APX_SEPrintf(p, end, "maxInDebitBytes: %d\n", (int)APX_ECfg.ClsfMaxInDebitBytes);
            p = APX_SEPrintf(p, end, "udpBurst: %d\n", (int)APX_ECfg.ClsfHostFairUdpBurst);
            p = APX_SEPrintf(p, end, "voipDefaultPriority: %d\n", (int)APX_ECfg.ClsfVoipDefaultPriority);
#ifndef APXOPT_SINGLE_PRIORITY
            p = APX_SEPrintf(p, end, "bandDist: %u %u %u %u %u %u %u %u\n", OpaqueEngine->Cfg.BandDist[0],
            OpaqueEngine->Cfg.BandDist[1], OpaqueEngine->Cfg.BandDist[2], OpaqueEngine->Cfg.BandDist[3],
            OpaqueEngine->Cfg.BandDist[4], OpaqueEngine->Cfg.BandDist[5], OpaqueEngine->Cfg.BandDist[6],
            OpaqueEngine->Cfg.BandDist[7]);
            {
                UINT i = 0;
                APX_PRIORITY_BW const* const pbw = OpaqueEngine->Cfg.BandLimit;
                UINT const cnt = ARRAY_SIZE(OpaqueEngine->Cfg.BandLimit);
                p = APX_SEPrintf(p, end, "bandLimit:");
                for (i = 0; i < cnt && pbw[i].Priority != 0; i++)
                {
                    p = APX_SEPrintf(p, end, " %u:%u,%u", pbw[i].Priority, pbw[i].InBpms * 8, pbw[i].OutBpms * 8);
                }
                p = APX_SEPrintf(p, end, "\n");
            }
#endif /* !APXOPT_SINGLE_PRIORITY*/
#ifndef APXENV_NO_CLSF
            p = APX_SEPrintf(p, end, "p2pSessThreshold: %u %u %u %u\n",
                APX_ECfg.ClsfP2PFlowNumLowUdp, APX_ECfg.ClsfP2PFlowNumHighUdp,
                APX_ECfg.ClsfP2PFlowNumLowTcp, APX_ECfg.ClsfP2PFlowNumHighTcp);
            p = APX_SEPrintf(p, end, "p2pPriorities: %u\n", (UINT32)APX_ECfg.ClsfP2pPriorities);
            p = APX_SEPrintf(p, end, "inboundDropMax: %u\n", (UINT32)clsf->InboundDropMax);
            {
                UINT32 maxOutBurst = 0;
                UINT32 maxInBurst = 0;
                APX_EngineGetWanIfMaxBurst(OpaqueEngine->Engine, APX_OUTBOUND, &maxOutBurst);
                APX_EngineGetWanIfMaxBurst(OpaqueEngine->Engine, APX_INBOUND, &maxInBurst);
                p = APX_SEPrintf(p, end, "maxWanBurstBytes: %u\n", maxOutBurst);
                p = APX_SEPrintf(p, end, "maxWanInBurstBytes: %u\n", maxInBurst);
            }
#endif
            p = APX_SEPrintf(p, end, "noPingRtt: %u\n",
                (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_PING_RTT)? 0 : 1);
            p = APX_SEPrintf(p, end, "rxLoopCnt1: %u\n", (int)wanIf->RxLoopCnt1);
            p = APX_SEPrintf(p, end, "rxLoopCnt2: %u\n", (int)wanIf->RxLoopCnt2);

#ifdef APXENV_LAN_SEGMENT
            {
                int i;
                p = APX_SEPrintf(p, end, "lanSegment:");
                for (i=0; i<sizeof(OpaqueEngine->LanSegment) / sizeof(OpaqueEngine->LanSegment[0]); i++)
                {
                    if (!OpaqueEngine->LanSegment[i]) break;
                    p = APX_SEPrintf(p, end, " %X/%u", (int)OpaqueEngine->LanSegment[i],
                        OpaqueEngine->LanSegmentLen[i]);
                }
                if (OpaqueEngine->LanSegmentAcc)
                    p = APX_SEPrintf(p, end, " 1");
                p = APX_SEPrintf(p, end, "\n");
            }
#endif

#ifdef APXENV_PCAP_ENABLE
            {
                UINT i;
                p = APX_SEPrintf(p, end, "pcapFilterIp:");
                for (i = 0; i < ARRAY_SIZE(OpaqueEngine->PcapFilterIP); i++)
                {
                    UINT32 ip4 = OpaqueEngine->PcapFilterIP[i];
                    UINT8 mask = OpaqueEngine->PcapFilterIPMask[i];
                    if (ip4 == 0) break;
                    p = mask == 0 ?
                        APX_SEPrintf(p, end, " %08x", ip4) :
                        APX_SEPrintf(p, end, " %08x/%u", ip4, mask);
                }
                p = APX_SEPrintf(p, end, "\n");
            }
            p = APX_SEPrintf(p, end, "pcapFilterProto: %u\n", OpaqueEngine->PcapFilterProto);
            p = APX_SEPrintf(p, end, "pcapFilterSplit(1~16): %u\n", OpaqueEngine->PcapFilterSplit);
            p = APX_SEPrintf(p, end, "pcapFileSize: %u\n", OpaqueEngine->PcapFileSize);
            p = APX_SEPrintf(p, end, "pcapPktLen: %u\n", OpaqueEngine->PcapPktLen);
            p = APX_SEPrintf(p, end, "pcapFileNum: %u\n", OpaqueEngine->PcapFileTotalNum);
#endif
            p = APX_SEPrintf(p, end, "reservePage: %u\n", OpaqueEngine->PageReserve);
            
            p = APX_SEPrintf(p, end, "lan2wanHostBw: %u\n", APX_ECfg.ClsfL2WHostBw);
            p = APX_SEPrintf(p, end, "wan2lanHostBw: %u\n", APX_ECfg.ClsfW2LHostBw);

            p = APX_SEPrintf(p, end, "initialCwndLan: %u\n", APX_ECfg.InitialCwndLan);
            p = APX_SEPrintf(p, end, "initialCwndWan: %u\n", APX_ECfg.InitialCwndWan);
            p = APX_SEPrintf(p, end, "maxCwndLan: %u\n", APX_ECfg.MaxCwndLan);
            p = APX_SEPrintf(p, end, "maxCwndWan: %u\n", APX_ECfg.MaxCwndWan);
            p = APX_SEPrintf(p, end, "maxAdvWinLan: %u\n", APX_ECfg.LanMaxBuff);
            p = APX_SEPrintf(p, end, "maxAdvWinWan: %u\n", APX_ECfg.MaxAdvWinWan);
            p = APX_SEPrintf(p, end, "halfCwndMinSRtt: %u\n", APX_ECfg.HalfCwndMinSRtt);
            p = APX_SEPrintf(p, end, "halfCwndLossRateShift: %u\n", APX_ECfg.HalfCwndLossRateShift);
            p = APX_SEPrintf(p, end, "halfCwndLowLimit: %u\n", APX_ECfg.HalfCwndLowLimit);
            p = APX_SEPrintf(p, end, "srttThresh: %u\n", APX_ECfg.SRttThresh);
            p = APX_SEPrintf(p, end, "maxTxMinSsThresh: %u\n", APX_ECfg.MaxTxMinSsThresh);
            p = APX_SEPrintf(p, end, "maxTxMinAdvWinWan: %u\n", APX_ECfg.MaxTxMinAdvWinWan);
            p = APX_SEPrintf(p, end, "maxTxEffectiveMS: %u\n", APX_ECfg.MaxTxEffectiveMS);
            p = APX_SEPrintf(p, end, "minSsThresh: %u %u\n", APX_ECfg.MinSsThreshLow, APX_ECfg.MinSsThreshHigh);
            p = APX_SEPrintf(p, end, "flowShortTimeout: %u\n", (UINT32)APX_ECfg.FlowShortTimeoutCnt * APX_FLOW_TIMEOUT_INTERVAL);
            p = APX_SEPrintf(p, end, "maxAccFlowTxKbps: %u\n", APX_ECfg.MaxAccFlowTxBpms * 8);
            p = APX_SEPrintf(p, end, "MaxReasL4Size: %u\n", APX_ECfg.MaxReasL4Size);
            p = APX_SEPrintf(p, end, "retranDupAckCnt: %u\n", APX_ECfg.RetranNumDupAckWan);
            p = APX_SEPrintf(p, end, "retranWaitListMS: %u\n", APX_ECfg.RetranWaitListMS);
            p = APX_SEPrintf(p, end, "reseqPacketCnt: %u\n", APX_ECfg.ReseqPacketCnt);
            p = APX_SEPrintf(p, end, "rtoScale: %u\n", APX_ECfg.RtoScale);
            p = APX_SEPrintf(p, end, "rtoLimit: %u %u\n", APX_ECfg.MaxRtoBackOffCnt, APX_ECfg.MaxRtoMS);
            p = APX_SEPrintf(p, end, "ipFilter: %X/%u\n", (int)OpaqueEngine->IpFilter[0],
                OpaqueEngine->IpFilter[1]);
            p = APX_SEPrintf(p, end, "l2wQLimit: %u %u\n", APX_ECfg.L2WLinkLimitMin, APX_ECfg.L2WLinkLimitMax);
            p = APX_SEPrintf(p, end, "w2lQLimit: %u %u\n", APX_ECfg.W2LLinkLimitMin, APX_ECfg.W2LLinkLimitMax);
            p = APX_SEPrintf(p, end, "tcpFlags: 0x%x\n", APX_ECfg.TcpFlags);
            p = APX_SEPrintf(p, end, "bypassOverFlows: %u\n",
                (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_BYPASS_OVFL)? 1 : 0);
            p = APX_SEPrintf(p, end, "smBurstMS: %u\n", APX_ECfg.SmBurstMS);
            p = APX_SEPrintf(p, end, "smBurstMin: %u\n", APX_ECfg.SmBurstMin);
            p = APX_SEPrintf(p, end, "smBurstTolerance: %u\n", APX_ECfg.SmBurstTolerance);
            p = APX_SEPrintf(p, end, "smMinKbps: %u\n", APX_ECfg.SmMinBpms * 8);
            p = APX_SEPrintf(p, end, "dbcMinInFlight: %u\n", APX_ECfg.DbcMinInFlight);
            p = APX_SEPrintf(p, end, "dbcRttThreshMS: %u %u\n", APX_ECfg.DbcRttThreshLowMS, APX_ECfg.DbcRttThreshMS);

#ifdef APXENV_LIGHT_TCP_TUNNEL
            p = APX_SEPrintf(p, end, "lttPort: %u\n", APX_ECfg.LttPort);
            p = APX_SEPrintf(p, end, "lttSipPort: %u\n", APX_ECfg.LttSipPort);
            p = APX_SEPrintf(p, end, "lttSynRetries: %u\n", APX_ECfg.LttMaxSynRetries);
            p = APX_SEPrintf(p, end, "lttFailWaitSec: %u\n", APX_ECfg.LttMaxFailWaitSec);
            p = APX_SEPrintf(p, end, "lttMaxDelayMS: %u %u\n", APX_ECfg.LttMaxTDelayMS, APX_ECfg.LttMaxUDelayMS);
            p = APX_SEPrintf(p, end, "lttL2WQLimit: %u %u\n", APX_ECfg.LttL2WTLinkLimit, APX_ECfg.LttL2WULinkLimit);
            p = APX_SEPrintf(p, end, "lttW2LQLimit: %u %u\n", APX_ECfg.LttW2LTLinkLimit, APX_ECfg.LttW2LULinkLimit);
            p = APX_SEPrintf(p, end, "lttIdleSec: %u\n", (UINT32)APX_ECfg.LttIdleTimeoutCnt * APX_FLOW_TIMEOUT_INTERVAL / 1000);
#endif /* APXENV_LIGHT_TCP_TUNNEL */

            p = APX_SEPrintf(p, end, "tcpOnly: %u\n", OpaqueEngine->IsTcpOnly ? 1 : 0);
#ifdef APXENV_SHORT_RTT_BYPASS
            p = APX_SEPrintf(p, end, "shortRttMS: %u\n", APX_ECfg.ShortRttMS);
#endif /* APXENV_SHORT_RTT_BYPASS */
#ifdef APXENV_SYN_RETRAN
            p = APX_SEPrintf(p, end, "synRetranMS: %u\n", APX_ECfg.SynRetranMS);
#endif /* APXENV_SYN_RETRAN */

            p = APX_SEPrintf(p, end, "pmtuBhRetrans: %u\n", APX_ECfg.PmtuMaxBHRetranCnt);
            p = APX_SEPrintf(p, end, "ultraBoostWin: %u\n", APX_ECfg.UltraBoostWin);
            p = APX_SEPrintf(p, end, "shrinkPacket: %u\n", OpaqueEngine->IsShrinkPacket ? 1 : 0);
            p = APX_SEPrintf(p, end, "taskSchedDelay: %u %u\n", wanIf->TaskletSchedLocalDelay,
                wanIf->TaskletSchedNonLocalDelay);
            p = APX_SEPrintf(p, end, "rsc: %u\n", OpaqueEngine->RscSupport);
            p = APX_SEPrintf(p, end, "gso: %u\n", OpaqueEngine->GsoSupport);
            p = APX_SEPrintf(p, end, "mpoolMaxCache: %zu\n",
                APX_LinuxMPoolGetMaxCache(OpaqueEngine->MPools));

            return (p - page);
        }
        case PROC_DATA_hostFairTcpActSessNum:
        {
            value = APX_ECfg.ClsfHostFairMaxTcpActiveSess;
            break;
        }
        case PROC_DATA_trackRandomLoss:
        {
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_TRACK_LOSS)? 1 : 0;
            break;
        }
        case PROC_DATA_maxTxEnable:
        {
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_MAX_TX)? 1 : 0;
            break;
        }
        case PROC_DATA_conservMode:
        {
            value = (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_CONSERV)? 1 : 0;
            break;
        }
        case PROC_DATA_engSysEnable:
            value = test_bit(APX_BASE_FLAG_HOOK_ENABLE, &wanIf->flags)? 1 : 0;
            break;

        case PROC_DATA_srtt:
        {
            APX_ENGINE_STATISTICS engStats;
            
            APX_BaseMemSet(&engStats, 0, sizeof(engStats));
            APX_EngineGetEngineStatistics(OpaqueEngine->Engine, &engStats);
            value = engStats.Rtt;
            break;
        }

        default:
            return -EFAULT;
    }

    return APX_SNPrintf(page, size, "%u\n", value);
}

static int
_settingsRead(
    char *page,
    char **start,
    off_t off,
    int count,
    int *eof,
    void *data
    )
{
    APX_IO_EVENT event;
    APX_OPAQUE_ENGINE *opaqueEngine = (APX_OPAQUE_ENGINE *)((unsigned long)data & ~(OPAQUE_ENGINE_ALIGN_SIZE - 1));
    APX_BASE_NETIF *wanIf = &opaqueEngine->WanIF;

    if (gApxTerminating)
        return -EFAULT;

    if (off > 0)
    {
        *eof = 1;
        return 0;
    }

    down(&_ioSem);

    event.Type = APX_IO_EVENT_PROC_GET;
    event.HoldMem = 1;
    event.ProcData.Done = 0;
    event.ProcData.Buf = page;
    event.ProcData.Len = count;
    event.ProcData.Data = (void *)((unsigned long)data & (OPAQUE_ENGINE_ALIGN_SIZE - 1));
    appexIoAddEvents(opaqueEngine, &event);
    APX_TASKLET_SCHEDULE(wanIf);

    wait_event(opaqueEngine->WaitQeue, event.ProcData.Done != 0);

    up(&_ioSem);

    return event.ProcData.Result;
}

static int
_settingsWriteFunc(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    char *copyBuf,
    unsigned long len,
    void *data
    )
{
    BOOL updateAdapter = FALSE;
    UINT32 value, flags;
    APX_BASE_NETIF *wanIf = &OpaqueEngine->WanIF;
#if !defined(APXENV_NO_CLSF) || !defined(APXENV_NO_RAD)
    APX_CLSF_ENGINE* clsf = APX_EClsfGet(OpaqueEngine->Engine);
#endif

    value = simple_strtoul(copyBuf, NULL, 0);
    flags = OpaqueEngine->Cfg.Flags;

    switch ((unsigned long) data)
    {
        case PROC_DATA_wanKbps:
        {
            if (value == 0)
                return -EINVAL;
            value = (value < 8)? (128*8) : value;
            if (OpaqueEngine->Cfg.Bw[0].Bpms != value / 8)
            {
                OpaqueEngine->Cfg.Bw[0].Bpms = value / 8;
                if (!(OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO))
                {
                    appexNetIfUpdateConfig(OpaqueEngine);
                }
                return len;
            }
            break;
        }
        case PROC_DATA_wanBurstBytes:
        {
            if (value == 0)
                return -EINVAL;
            if (OpaqueEngine->Cfg.Bw[0].BurstBytes != value)
            {
                OpaqueEngine->Cfg.Bw[0].BurstBytes = value;
                if (!(OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO))
                {
                    appexNetIfUpdateConfig(OpaqueEngine);
                }
                return len;
            }
            break;
        }
        case PROC_DATA_tcpAccEnable:
        {
            if (value) flags |= APX_ENGINE_FLAG_FLOW_CTRL;
            else flags &= ~APX_ENGINE_FLAG_FLOW_CTRL;
            break;
        }
        case PROC_DATA_dataCompEnable:
        {
            if (value) flags |= APX_ENGINE_FLAG_DATA_COMP;
            else flags &= ~APX_ENGINE_FLAG_DATA_COMP;
            break;
        }
        case PROC_DATA_voipAccEnable:
        {
            if (value) flags |= APX_ENGINE_FLAG_VOIP_FIRST;
            else flags &= ~APX_ENGINE_FLAG_VOIP_FIRST;
            break;
        }
        case PROC_DATA_voipSkipPackets:
        {
            APX_ECfg.ClsfVoipSkipPackets = value;
            break;
        }
        case PROC_DATA_advAccEnable:
        {
            if (value) flags |= APX_ENGINE_FLAG_SPC_ACK;
            else flags &= ~APX_ENGINE_FLAG_SPC_ACK;
            break;
        }
        case PROC_DATA_subnetAccEnable:
        {
            if (value) flags |= APX_ENGINE_FLAG_ACC_SUBNET;
            else flags &= ~APX_ENGINE_FLAG_ACC_SUBNET;
            break;
        }
        case PROC_DATA_shaperEnable:
        {
            if (value && !(OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER))
            {
                flags |= APX_ENGINE_FLAG_SHAPER;
                updateAdapter = TRUE;
            }
            else if (!value && (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER))
            {
                flags &= ~APX_ENGINE_FLAG_SHAPER;
                updateAdapter = TRUE;
            }
            else
            {
                return len;
            }
            break;
        }
        case PROC_DATA_hostFairTcpAccSessNum:
        {
            APX_ECfg.ClsfHostFairMaxTcpAccSess = (UINT32)value;
            break;
        }
        case PROC_DATA_pcapEnable:
        {
#ifdef APXENV_PCAP_ENABLE

            _pcapStop(OpaqueEngine);
            if (value)
            {
                if (!_pcapStart(OpaqueEngine))
                {
                    return -EFAULT;
                }
            }
#endif
            break;
        }
        case PROC_DATA_hostFairEnable:
        {
            if (value) flags |= APX_ENGINE_FLAG_HOST_FAIR;
            else flags &= ~APX_ENGINE_FLAG_HOST_FAIR;
            updateAdapter = TRUE;
            break;
        }
        case PROC_DATA_wanInKbps:
        {
            if (value == 0)
                return -EINVAL;
            value = (value < 8)? (128*8) : value;
            if (OpaqueEngine->Cfg.Bw[1].Bpms != value / 8)
            {
                OpaqueEngine->Cfg.Bw[1].Bpms = value / 8;
                if (!(OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO))
                {
                    appexNetIfUpdateConfig(OpaqueEngine);
                }
                return len;
            }
            break;
        }
        case PROC_DATA_wanInBurstBytes:
        {
            if (value == 0)
                return -EINVAL;
            if (OpaqueEngine->Cfg.Bw[1].BurstBytes != value)
            {
                OpaqueEngine->Cfg.Bw[1].BurstBytes = value;
                if (!(OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO))
                {
                    appexNetIfUpdateConfig(OpaqueEngine);
                }
                return len;
            }
            break;
        }
        case PROC_DATA_hostFairUdpSessNum:
        {
            APX_ECfg.ClsfHostFairMaxUdpSess = (UINT32)value;
            break;
        }
        case PROC_DATA_wanRateAutoDetect:
        {
            if (value && !(OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO))
            {
                APX_ENGINE* engine = OpaqueEngine->Engine;
                flags |= APX_ENGINE_FLAG_SHAPER_AUTO;
                (void)APX_EngineSetRadAdaptedBandwidth(
                    engine,
                    APX_OUTBOUND,
                    APX_ECfg.ClsfWanAutoOutAdaptRate / 8
                    );
                (void)APX_EngineSetRadAdaptedBandwidth(
                    engine,
                    APX_INBOUND,
                    APX_ECfg.ClsfWanAutoInAdaptRate / 8
                    );
                (void)APX_EngineSetWanIfBandwidth(
                    engine,
                    APX_OUTBOUND,
                    APX_ECfg.ClsfWanAutoOutAdaptRate / 8
                    );
                (void)APX_EngineSetWanIfBurst(
                    engine,
                    APX_OUTBOUND,
                    OpaqueEngine->Cfg.Bw[0].BurstBytes
                    );
                (void)APX_EngineSetWanIfBandwidth(
                    engine,
                    APX_INBOUND,
                    APX_ECfg.ClsfWanAutoInAdaptRate / 8
                    );
                (void)APX_EngineSetWanIfBurst(
                    engine,
                    APX_INBOUND,
                    OpaqueEngine->Cfg.Bw[1].BurstBytes
                    );
            }
            else if (!value && (OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO))
            {
                updateAdapter = TRUE;
                flags &= ~APX_ENGINE_FLAG_SHAPER_AUTO;
            }
            else
            {
                return len;
            }
            break;
        }
        case PROC_DATA_cmd:
        {
            char key[128];
            UINT32 value, num1, num2, num3;
            char const* p = APX_SafeStrGetStr(copyBuf, key, ARRAY_SIZE(key));

            if (p == NULL)
            {
                return -EINVAL;
            }

            #define _KEY_IS(_str_)          (_STRCMP_CONST(key, _str_) == 0)
            #define _READ_U32(_outval_)     (p = APX_SafeStrGetU32(p, 0, (_outval_)))
            #define _READ_X32(_outval_)     (p = APX_SafeStrGetU32(p, 16, (_outval_)))

#ifndef APXOPT_SINGLE_PRIORITY
            if (_KEY_IS("bandDist"))
            {
                UINT32 i, v[8];
                UINT8 v8[8];
                _READ_U32(&v[0]); _READ_U32(&v[1]); _READ_U32(&v[2]); _READ_U32(&v[3]);
                _READ_U32(&v[4]); _READ_U32(&v[5]); _READ_U32(&v[6]); _READ_U32(&v[7]);
                if (p == NULL) return -EINVAL;
                for (i=0; i<8; i++) v8[i] = (UINT8)v[i];
                if (!APX_SUCCEEDED(APX_EngineSetBandwidthDistribution(OpaqueEngine->Engine, v8)))
                {
                    return -EINVAL;
                }
                APX_BaseMemCopy(OpaqueEngine->Cfg.BandDist, v, sizeof(v));
                break;
            }
            else if (_KEY_IS("bandLimit"))
            {
                APX_PRIORITY_BW pbw[ARRAY_SIZE(OpaqueEngine->Cfg.BandLimit)];
                UINT n;

                APX_BaseMemZero(pbw, sizeof(pbw));
                for (n = 0; *p != 0 && n < ARRAY_SIZE(pbw); n++)
                {
                    UINT32 v;
                    if (_READ_U32(&v) == NULL || v == 0 || v >= APX_PRIORITY_COUNT || *p != ':')
                    {
                        p = NULL;
                        break;
                    }
                    pbw[n].Priority = (UINT8)v;
                    p++;
                    if (_READ_U32(&v) == NULL || v < 64 || *p != ',')
                    {
                        p = NULL;
                        break;
                    }
                    pbw[n].InBpms = v / 8;
                    p++;
                    if (_READ_U32(&v) == NULL || v < 64)
                    {
                        p = NULL;
                        break;
                    }
                    pbw[n].OutBpms = v / 8;
                }
                if (p == NULL ||
                    APX_FAILED(APX_EngineSetBandwidthLimits(OpaqueEngine->Engine, pbw, n)))
                {
                    return -EINVAL;
                }
                for (n = 0; n < ARRAY_SIZE(pbw); n++)
                {
                    OpaqueEngine->Cfg.BandLimit[n] = pbw[n];
                }
                break;
            }
#endif /* !APXOPT_SINGLE_PRIORITY */
            else if (_KEY_IS("displayLevel"))
            {
                _READ_U32(&value);
                OpaqueEngine->Cfg.DisplayLevel = (UINT8)value;
                break;
            }
#ifndef APXENV_NO_RAD
            else if (_KEY_IS("tcpRttVarThreshold"))
            {
                _READ_U32(&value);
                clsf->TcpRttVarThreshold = value;
                break;
            }
            else if (_KEY_IS("inStartRate"))
            {
                _READ_U32(&value);
                clsf->WanStartRate[1] = value * 1024;
                break;
            }
            else if (_KEY_IS("outStartRate"))
            {
                _READ_U32(&value);
                clsf->WanStartRate[0] = value * 1024;
                break;
            }
#endif
            else if (_KEY_IS("inRateReductFactor"))
            {
                _READ_U32(&value);
                APX_ECfg.ClsfWanAutoInRateReductFactor = value;
                break;
            }
            else if (_KEY_IS("outRateReductFactor"))
            {
                _READ_U32(&value);
                APX_ECfg.ClsfWanAutoOutRateReductFactor = value;
                break;
            }
            else if (_KEY_IS("inRateDiscount"))
            {
                _READ_U32(&value);
                APX_ECfg.ClsfWanAutoInRateDiscount = value;
                break;
            }
            else if (_KEY_IS("udpBurst"))
            {
                _READ_U32(&value);
                APX_ECfg.ClsfHostFairUdpBurst = (UINT32)value & 0x7FFFFFFF;
                break;
            }
            else if (_KEY_IS("maxInDebitBytes"))
            {
                _READ_U32(&value);
                APX_ECfg.ClsfMaxInDebitBytes = value;
                break;
            }
            else if (_KEY_IS("engine"))
            {
                _READ_U32(&num1); _READ_U32(&num2); _READ_U32(&num3);
                if (p == NULL || num1 == 0 || num2 == 0)
                {
                    return -EINVAL;
                }
                APX_EngineSetMaxNumOfFlows(OpaqueEngine->Engine, num1);
                APX_EngineSetMaxNumOfAccFlows(OpaqueEngine->Engine, num2);
                APX_EngineSetMaxNumOfCompFlows(OpaqueEngine->Engine, num3);
                OpaqueEngine->Param.MaxNumOfFlows = num1;
                OpaqueEngine->Param.MaxNumOfAccFlows = num2;
                OpaqueEngine->Param.MaxNumOfCompFlows = num3;
            }
            else if (_KEY_IS("voipDefaultPriority"))
            {
                _READ_U32(&value);
                APX_ECfg.ClsfVoipDefaultPriority = (UINT8)value;
                break;
            }
            else if (_KEY_IS("p2pSessThreshold"))
            {
                unsigned int cnt = 0;
                cnt += (_READ_U32(&value) != NULL);
                cnt += (_READ_U32(&num1)  != NULL);
                cnt += (_READ_U32(&num2)  != NULL);
                cnt += (_READ_U32(&num3)  != NULL);

                if (cnt == 2)
                {
                    APX_ECfg.ClsfP2PFlowNumLowUdp = value;
                    APX_ECfg.ClsfP2PFlowNumHighUdp = num1;
                    break;
                }
                else if (cnt == 4)
                {
                    APX_ECfg.ClsfP2PFlowNumLowUdp = value;
                    APX_ECfg.ClsfP2PFlowNumHighUdp = num1;
                    APX_ECfg.ClsfP2PFlowNumLowTcp = num2;
                    APX_ECfg.ClsfP2PFlowNumHighTcp = num3;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("p2pPriorities"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.ClsfP2pPriorities = ((UINT8)value) | (1 << APX_PRIORITY_DEFAULT_0);
                    break;
                }
                else return -EINVAL;
            }
#ifndef APXENV_NO_CLSF
            else if (_KEY_IS("inboundDropMax"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    clsf->InboundDropMax = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
#endif
#ifdef APXENV_LAN_SEGMENT
            else if (_KEY_IS("lanSegment"))
            {
                unsigned int i;
                memset(OpaqueEngine->LanSegment, 0, sizeof(OpaqueEngine->LanSegment));
                memset(OpaqueEngine->LanSegmentLen, 0, sizeof(OpaqueEngine->LanSegmentLen));
                OpaqueEngine->LanSegmentAcc = FALSE;
                OpaqueEngine->HasLanSegment = FALSE;

                for (i = 0; i < ARRAY_SIZE(OpaqueEngine->LanSegment); i++)
                {
                    char const* p0 = p;
                    UINT32 v = 0, masklen = 0;
                    if (_READ_X32(&v) == NULL) break;
                    if (*p != '/') { p = p0; break; }
                    if ((++p, _READ_U32(&masklen)) == NULL) break;
                    if (*p != 0 && !isspace((unsigned char)*(p - 1))) { p = NULL; break; }
                    OpaqueEngine->LanSegment[i] = v;
                    OpaqueEngine->LanSegmentLen[i] = masklen <= 32 ? masklen : 32;
                }
                if (OpaqueEngine->LanSegment[0])
                {
                    UINT32 acc;
                    _READ_U32(&acc);
                    OpaqueEngine->HasLanSegment = TRUE;
                    OpaqueEngine->LanSegmentAcc = (acc != 0);
                }
            }
#endif
#ifdef APXENV_PCAP_ENABLE
            else if (_KEY_IS("pcapFilterIp"))
            {
                UINT i;
                memset(OpaqueEngine->PcapFilterIP, 0, sizeof(OpaqueEngine->PcapFilterIP));
                memset(OpaqueEngine->PcapFilterIPMask, 0, sizeof(OpaqueEngine->PcapFilterIPMask));

                for (i = 0; i < ARRAY_SIZE(OpaqueEngine->PcapFilterIP); i++)
                {
                    UINT32 v = 0, mask = 0;
                    if (_READ_X32(&v) == NULL) break;
                    if (*p == '/' && (++p, _READ_U32(&mask)) == NULL) break;
                    if (*p != 0 && !isspace((unsigned char)*(p - 1))) break;
                    OpaqueEngine->PcapFilterIP[i] = v;
                    OpaqueEngine->PcapFilterIPMask[i] = mask <= 32 ? mask : 32;
                }
            }
            else if (_KEY_IS("pcapFilterProto"))
            {
                UINT32 proto = 0;
                _READ_U32(&proto);
                OpaqueEngine->PcapFilterProto = proto;
            }
            else if (_KEY_IS("pcapFilterSplit"))
            {
                _READ_U32(&OpaqueEngine->PcapFilterSplit);
                if (OpaqueEngine->PcapFilterSplit > 16) OpaqueEngine->PcapFilterSplit = 16;
            }
            else if (_KEY_IS("pcapFileSize"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    OpaqueEngine->PcapFileSize = (value < 0xFFFF)? 0xFFFF : value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("pcapPktLen"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    OpaqueEngine->PcapPktLen = (UINT32)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("pcapFileNum"))
            {
                if (_READ_U32(&value) != NULL && value >= 1 && value <= 0xFF)
                {
                    OpaqueEngine->PcapFileTotalNum = value;
                    break;
                }
                else return -EINVAL;
            }
#endif
            else if (_KEY_IS("reservePage"))
            {
                if (_READ_U32(&value) != NULL)
                {
#ifdef MKVAR_APPEX_MINI_ROUTER
                printk(KERN_INFO "appex: reservPage %d, freePages %lu\n", value, nr_free_pages());
#else
                printk(KERN_INFO "appex: reservPage %d, freePages %d\n", value, nr_free_pages());
#endif
                    OpaqueEngine->PageReserve = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("lan2wanHostBw"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.ClsfL2WHostBw = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("wan2lanHostBw"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.ClsfW2LHostBw = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("initialCwndLan"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.InitialCwndLan = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("initialCwndWan"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.InitialCwndWan = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxCwndLan"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.MaxCwndLan = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxCwndWan"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.MaxCwndWan = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxAdvWinLan"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.LanMaxBuff = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxAdvWinWan"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.MaxAdvWinWan = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("halfCwndMinSRtt"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.HalfCwndMinSRtt = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("halfCwndLossRateShift"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.HalfCwndLossRateShift = (UINT8)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("halfCwndLowLimit"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.HalfCwndLowLimit = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("srttThresh"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.SRttThresh = (UINT8)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxTxMinSsThresh"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.MaxTxMinSsThresh = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxTxMinAdvWinWan"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.MaxTxMinAdvWinWan = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxTxEffectiveMS"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.MaxTxEffectiveMS = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("minSsThresh"))
            {
                if (_READ_U32(&num1) != NULL && _READ_U32(&num2) != NULL && num1 <= num2)
                {
                    APX_ECfg.MinSsThreshLow = num1;
                    APX_ECfg.MinSsThreshHigh = num2;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("flowShortTimeout"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.FlowShortTimeoutCnt = (UINT16)(value / APX_FLOW_TIMEOUT_INTERVAL);
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxWanBurstBytes"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_EngineSetWanIfMaxBurst(OpaqueEngine->Engine, APX_OUTBOUND, value);
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxWanInBurstBytes"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_EngineSetWanIfMaxBurst(OpaqueEngine->Engine, APX_INBOUND, value);
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("maxAccFlowTxKbps"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.MaxAccFlowTxBpms = value / 8;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("MaxReasL4Size"))
            {
                if (sscanf(copyBuf, "%s %d", key, &value) == 2)
                {
                    if (value > 65515)
                        value = 65515;
                    APX_ECfg.MaxReasL4Size = value;
                    break;
                }
            }
            else if (_KEY_IS("retranDupAckCnt"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.RetranNumDupAckWan = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("retranWaitListMS"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.RetranWaitListMS = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("reseqPacketCnt"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.ReseqPacketCnt = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("rtoScale"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.RtoScale = (UINT8)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("rtoLimit"))
            {
                if (_READ_U32(&num1) == NULL || _READ_U32(&num2) == NULL)
                {
                    return -EINVAL;
                }
                APX_ECfg.MaxRtoBackOffCnt = (UINT8)num1;
                APX_ECfg.MaxRtoMS = num2;
            }
            else if (_KEY_IS("ipFilter"))
            {
                UINT32 ipaddr, masklen;
                memset(OpaqueEngine->IpFilter, 0, sizeof(OpaqueEngine->IpFilter));
                if (_READ_X32(&ipaddr) != NULL && *p == '/' &&
                    (++p, _READ_U32(&masklen)) != NULL && masklen <= 32)
                {
                    OpaqueEngine->IpFilter[0] = ipaddr;
                    OpaqueEngine->IpFilter[1] = masklen;
                    OpaqueEngine->HasIpFilter = (ipaddr != 0);
                }
                else
                {
                    OpaqueEngine->IpFilter[0] = 0;
                    OpaqueEngine->IpFilter[1] = 0;
                    OpaqueEngine->HasIpFilter = FALSE;
                    return -EINVAL;
                }
            }
            else if (_KEY_IS("rxLoopCnt1"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    wanIf->RxLoopCnt1 = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("rxLoopCnt2"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    wanIf->RxLoopCnt2 = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("noPingRtt"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    if (value) flags &= ~APX_ENGINE_FLAG_PING_RTT;
                    else flags |= APX_ENGINE_FLAG_PING_RTT;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("l2wQLimit"))
            {
                if (_READ_U32(&num1) == NULL || _READ_U32(&num2) == NULL ||
                    num1 == 0 || num2 == 0 || num1 > num2 || num2 > USHRT_MAX)
                {
                    return -EINVAL;
                }
                APX_ECfg.L2WLinkLimitMin = (UINT16)num1;
                APX_ECfg.L2WLinkLimitMax = (UINT16)num2;
            }
            else if (_KEY_IS("w2lQLimit"))
            {
                if (_READ_U32(&num1) == NULL || _READ_U32(&num2) == NULL ||
                    num1 == 0 || num2 == 0 || num1 > num2 || num2 > USHRT_MAX)
                {
                    return -EINVAL;
                }
                APX_ECfg.W2LLinkLimitMin = (UINT16)num1;
                APX_ECfg.W2LLinkLimitMax = (UINT16)num2;
            }
            else if (_KEY_IS("tcpFlags"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.TcpFlags = (UINT32)value;
                    return len;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("bypassOverFlows"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    if (value) flags |= APX_ENGINE_FLAG_BYPASS_OVFL;
                    else flags &= ~APX_ENGINE_FLAG_BYPASS_OVFL;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("smBurstMS"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.SmBurstMS = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("smBurstMin"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.SmBurstMin = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("smBurstTolerance"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.SmBurstTolerance = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("smMinKbps"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.SmMinBpms = value / 8;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("dbcMinInFlight"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.DbcMinInFlight = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("dbcRttThreshMS"))
            {
                if (_READ_U32(&num1) != NULL && _READ_U32(&num2) != NULL &&
                    num1 <= num2 && num2 <= USHRT_MAX)
                {
                    APX_ECfg.DbcRttThreshLowMS = (UINT16)num1;
                    APX_ECfg.DbcRttThreshMS = (UINT16)num2;
                    break;
                }
                else return -EINVAL;
            }
#ifdef APXENV_LIGHT_TCP_TUNNEL
            else if (_KEY_IS("lttPort"))
            {
                if (_READ_U32(&value) != NULL && value > 0 && value <= USHRT_MAX)
                {
                    APX_ECfg.LttPort = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("lttSipPort"))
            {
                if (_READ_U32(&value) != NULL && value <= USHRT_MAX)
                {
                    APX_ECfg.LttSipPort = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("lttSynRetries"))
            {
                if (_READ_U32(&value) != NULL && value <= USHRT_MAX)
                {
                    APX_ECfg.LttMaxSynRetries = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("lttFailWaitSec"))
            {
                if (_READ_U32(&value) != NULL && value <= USHRT_MAX)
                {
                    APX_ECfg.LttMaxFailWaitSec = (UINT16)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("lttMaxDelayMS"))
            {
                if (_READ_U32(&num1) == NULL || _READ_U32(&num2) == NULL ||
                    num1 > USHRT_MAX || num2 > USHRT_MAX)
                {
                    return -EINVAL;
                }
                APX_ECfg.LttMaxTDelayMS = (UINT16)num1;
                APX_ECfg.LttMaxUDelayMS = (UINT16)num2;
                break;
            }
            else if (_KEY_IS("lttL2WQLimit"))
            {
                if (_READ_U32(&num1) == NULL || _READ_U32(&num2) == NULL || num1 == 0 || num2 == 0)
                {
                    return -EINVAL;
                }
                APX_ECfg.LttL2WTLinkLimit = num1;
                APX_ECfg.LttL2WULinkLimit = num2;
                break;
            }
            else if (_KEY_IS("lttW2LQLimit"))
            {
                if (_READ_U32(&num1) == NULL || _READ_U32(&num2) == NULL || num1 == 0 || num2 == 0)
                {
                    return -EINVAL;
                }
                APX_ECfg.LttW2LTLinkLimit = num1;
                APX_ECfg.LttW2LULinkLimit = num2;
                break;
            }
            else if (_KEY_IS("lttIdleSec"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    value = value < INT_MAX / 1000 ? value * 1000 / APX_FLOW_TIMEOUT_INTERVAL : 0;
                    APX_ECfg.LttIdleTimeoutCnt = (UINT16)min_t(u32, value, APX_FLOW_TIMEOUT_COUNT);
                    break;
                }
                else return -EINVAL;
            }
#endif /* APXENV_LIGHT_TCP_TUNNEL */
            else if (_KEY_IS("tcpOnly"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    if (value) OpaqueEngine->IsTcpOnly = 1;
                    else OpaqueEngine->IsTcpOnly = 0;
                    break;
                }
                else return -EINVAL;
            }
#ifdef APXENV_SHORT_RTT_BYPASS
            else if (_KEY_IS("shortRttMS"))
            {
                if (_READ_U32(&num1) != NULL)
                {
                    UINT16 origShortRtt = APX_ECfg.ShortRttMS;
                    APX_ECfg.ShortRttMS = (UINT16)num1;
                    if (origShortRtt != 0 && APX_ECfg.ShortRttMS == 0)
                    {
                        APX_EngineResetShortRtt(OpaqueEngine->Engine);
                    }
                    break;
                }
                else return -EINVAL;
            }
#endif /* APXENV_SHORT_RTT_BYPASS */
            else if (_KEY_IS("pmtuBhRetrans"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.PmtuMaxBHRetranCnt = (UINT8)value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("ultraBoostWin"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_ECfg.UltraBoostWin = value;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("cpuId"))
            {
                if (_READ_U32(&value) != NULL)
                {
#ifdef CONFIG_SMP
                    if (value >= num_online_cpus()) return -EINVAL;
                    if (wanIf->CpuId != smp_processor_id())
                    {
                        APX_SMP_CALL_FUNCTION(appexTimerStop, wanIf, 0, 1, value);
                    }
                    else
                    {
                        del_timer(&wanIf->Timer);
                    }
                    smp_mb();
                    wanIf->CpuId = value;
                    smp_mb();
                    APX_SMP_CALL_FUNCTION(appexTimerIpiFunc, wanIf, 0, 1, value);
#endif
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("shrinkPacket"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    if (value) OpaqueEngine->IsShrinkPacket = 1;
                    else OpaqueEngine->IsShrinkPacket = 0;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("taskSchedDelay"))
            {
                if (_READ_U32(&num1) == NULL || _READ_U32(&num2) == NULL) return -EINVAL;
                wanIf->TaskletSchedLocalDelay = num1;
                wanIf->TaskletSchedNonLocalDelay = num2;
            }
            else if (_KEY_IS("rsc"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    if (value) OpaqueEngine->RscSupport = 1;
                    else OpaqueEngine->RscSupport = 0;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("gso"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    if (value) OpaqueEngine->GsoSupport = 1;
                    else OpaqueEngine->GsoSupport = 0;
                    break;
                }
                else return -EINVAL;
            }
            else if (_KEY_IS("mpoolMaxCache"))
            {
                if (_READ_U32(&value) != NULL)
                {
                    APX_LinuxMPoolSetMaxCache(OpaqueEngine->MPools, value);
                    break;
                }
                else return -EINVAL;
            }
            break;
        }
        case PROC_DATA_hostFairTcpActSessNum:
        {
            APX_ECfg.ClsfHostFairMaxTcpActiveSess = (UINT32)value;
            break;
        }
        case PROC_DATA_trackRandomLoss:
        {
            if (value) flags |= APX_ENGINE_FLAG_TRACK_LOSS;
            else flags &= ~APX_ENGINE_FLAG_TRACK_LOSS;
            break;
        }
        case PROC_DATA_maxTxEnable:
        {
            if (value) flags |= APX_ENGINE_FLAG_MAX_TX;
            else flags &= ~APX_ENGINE_FLAG_MAX_TX;
            break;
        }
        case PROC_DATA_conservMode:
        {
            if (value) flags |= APX_ENGINE_FLAG_CONSERV;
            else flags &= ~APX_ENGINE_FLAG_CONSERV;
            break;
        }
        case PROC_DATA_engSysEnable:
            if (value) set_bit(APX_BASE_FLAG_HOOK_ENABLE, &wanIf->flags);
            else clear_bit(APX_BASE_FLAG_HOOK_ENABLE, &wanIf->flags);
            break;
            
        default:
            return -EFAULT;
    }

    if (flags != OpaqueEngine->Cfg.Flags)
    {
        BOOL resetRad = (flags & ~OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO) != 0;
        OpaqueEngine->Cfg.Flags = flags;
        OpaqueEngine->HasSubnetAcc = (flags & APX_ENGINE_FLAG_ACC_SUBNET)? 1 : 0;
        APX_BaseSetEngineFlags(OpaqueEngine->Engine, OpaqueEngine->Cfg.Flags);
        if (resetRad)
        {
            (void)APX_EngineResetRad(OpaqueEngine->Engine, FALSE);
        }
        if (updateAdapter)
        {
            appexNetIfUpdateConfig(OpaqueEngine);
        }
    }

#ifndef APX_LOTSERVER
    /* set traffic hook when need. */
    if (OpaqueEngine->Cfg.Flags &
        (APX_ENGINE_FLAG_FLOW_CTRL | APX_ENGINE_FLAG_SHAPER | APX_ENGINE_FLAG_VOIP_FIRST |
         APX_ENGINE_FLAG_HOST_FAIR | APX_ENGINE_FLAG_SPC_ACK))
    {
        set_bit(APX_BASE_FLAG_HOOK_ENABLE, &wanIf->flags);
    }
    else
    {
        if (test_bit(APX_BASE_FLAG_HOOK_ENABLE, &wanIf->flags))
        {
            printk(KERN_ALERT "appex: unset traffic hook\n");
        }
        clear_bit(APX_BASE_FLAG_HOOK_ENABLE, &wanIf->flags);
    }
#endif

    return len;
}

static int
_settingsWrite(
    struct file *filp,
    const char *buff,
    unsigned long len,
    void *data
    )
{
    #define APX_VALUE_BUF_SIZE  1024

    /* NOTE: using a char array on stack would be too big for kernel frame size. */
    char* valueBuf = NULL;
    int ret = 0, id;
    APX_OPAQUE_ENGINE *opaqueEngine = (APX_OPAQUE_ENGINE *)((unsigned long)data & ~(OPAQUE_ENGINE_ALIGN_SIZE - 1));

    if (gApxTerminating || len >= APX_VALUE_BUF_SIZE)
    {
        ret = -EFAULT;
        goto CommonReturn;
    }

    down(&_ioSem);

    valueBuf = (char*)kzalloc(APX_VALUE_BUF_SIZE, GFP_ATOMIC);

    if (valueBuf == NULL)
    {
        up(&_ioSem);
        ret = -ENOMEM;
        goto CommonReturn;
    }

    if (copy_from_user(valueBuf, buff, len))
    {
        up(&_ioSem);
        ret = -EFAULT;
        goto CommonReturn;
    }

    valueBuf[len] = 0; /* force string terminator. */

    id = (int)((unsigned long)data & (OPAQUE_ENGINE_ALIGN_SIZE - 1));

    switch (id)
    {
        case PROC_DATA_pcapEnable:
        {
            up(&_ioSem);
            ret = _settingsWriteFunc(opaqueEngine, valueBuf, len, (void *)(uintptr_t)id);
            break;
        }
#ifdef APXENV_SYN_RETRAN
        case PROC_DATA_cmd:    /* cmd */
        {
            char key[128];
            char const* p = APX_SafeStrGetStr(valueBuf, key, ARRAY_SIZE(key));

            if (p == NULL)
            {
                up(&_ioSem);
                ret = -EINVAL;
                break;
            }

            if (_KEY_IS("synRetranMS"))
            {
                /* vmalloc() may be called which MUST NOT be in tasklet. */
                UINT32 num1;
                up(&_ioSem);
                if (_READ_U32(&num1) != NULL)
                {
                    int r = _appexIoSetSynRetran(opaqueEngine, (UINT16)num1);
                    ret = r == 0 ? len : r;
                }
                else ret = -EINVAL;
                break;
            }

            __fallthrough;
        }
#endif /* APXENV_SYN_RETRAN */
        default:
        {
            APX_IO_EVENT event;
            event.Type = APX_IO_EVENT_PROC_SET;
            event.HoldMem = 1;
            event.ProcData.Done = 0;
            event.ProcData.Buf = valueBuf;
            event.ProcData.Len = len;
            event.ProcData.Data = (void*)(uintptr_t)id;
            smp_wmb();
            appexIoAddEvents(opaqueEngine, &event);
            APX_TASKLET_SCHEDULE(&opaqueEngine->WanIF);

            wait_event(opaqueEngine->WaitQeue, event.ProcData.Done != 0);
            up(&_ioSem);
            ret = event.ProcData.Result;
            break;
        }
    }

CommonReturn:

    if (valueBuf != NULL)
    {
        kfree(valueBuf);
    }

    return ret;
}

typedef struct PROC_ENTRY
{
    unsigned long Data;
    char *Name;
    int Mode;
} PROC_ENTRY;
static PROC_ENTRY _procEntries[] =
{
    { PROC_DATA_wanKbps,                "wanKbps",                0600 },
    { PROC_DATA_wanBurstBytes,          "wanBurstBytes",          0600 },
    { PROC_DATA_tcpAccEnable,           "tcpAccEnable",           0600 },
    { PROC_DATA_dataCompEnable,         "dataCompEnable",         0600 },
    { PROC_DATA_voipAccEnable,          "voipAccEnable",          0600 },
    { PROC_DATA_voipSkipPackets,        "voipSkipPackets",        0600 },
    { PROC_DATA_advAccEnable,           "advAccEnable",           0600 },
    { PROC_DATA_subnetAccEnable,        "subnetAccEnable",        0600 },
    { PROC_DATA_shaperEnable,           "shaperEnable",           0600 },
    { PROC_DATA_stats,                  "stats",                  0400 },
    { PROC_DATA_version,                "version",                0400 },
    { PROC_DATA_hostFairTcpAccSessNum,  "hostFairTcpAccSessNum",  0600 },
    { PROC_DATA_pcapEnable,             "pcapEnable",             0600 },
    { PROC_DATA_hostFairEnable,         "hostFairEnable",         0600 },
    { PROC_DATA_wanInKbps,              "wanInKbps",              0600 },
    { PROC_DATA_wanInBurstBytes,        "wanInBurstBytes",        0600 },
    { PROC_DATA_hostFairUdpSessNum,     "hostFairUdpSessNum",     0600 },
    { PROC_DATA_wanRateAutoDetect,      "wanRateAutoDetect",      0600 },
    { PROC_DATA_cmd,                    "cmd",                    0600 },
    { PROC_DATA_hostFairTcpActSessNum,  "hostFairTcpActSessNum",  0600 },
    { PROC_DATA_trackRandomLoss,        "trackRandomLoss",        0600 },
    { PROC_DATA_maxTxEnable,            "maxTxEnable",            0600 },
    { PROC_DATA_conservMode,            "conservMode",            0600 },
    { PROC_DATA_engSysEnable,           "engSysEnable",           0600 },
    { PROC_DATA_srtt,                       "srtt",           0400 },
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static ssize_t
_io_proc_read(
    struct file *filp,
    char __user *buf,
    size_t size,
    loff_t *off
    )
{
    int eof = 0, len;
    char *p;
    if (off != NULL && *off != 0)
        return 0;
    if ((p = kmalloc(size, GFP_KERNEL)) == NULL)
        return -ENOMEM;
    len = _settingsRead(p, NULL, 0, size, &eof, PDE_DATA(file_inode(filp)));
    if (len > 0 && len <= size)
    {
        if (copy_to_user(buf, p, len))
        {
            kfree(p);
            return -EFAULT;
        }
    }
    if (off && len >= 0)
        *off = (loff_t)len;
    kfree(p);
    return len;
}

static ssize_t
_io_proc_write(
    struct file *filp,
    const char __user *buf,
    size_t size, loff_t *data
    )
{
    return _settingsWrite(filp, buf, size, PDE_DATA(file_inode(filp)));
}

static const struct file_operations _io_proc_fops = {
    .owner = THIS_MODULE,
    .write = _io_proc_write,
    .read = _io_proc_read,
};
#endif

static BOOL _procInit(APX_OPAQUE_ENGINE *OpaqueEngine)
{
    int i;
    unsigned long data;
    char name[32];
    struct proc_dir_entry *entry;

    if (OpaqueEngine->EngineId)
    {
        APX_APRINTF(name, "appex%d", OpaqueEngine->EngineId);
    }
    else
    {
        APX_APRINTF(name, "appex");
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
    APX_ALERT((OpaqueEngine->ProcRoot = proc_mkdir(name, gApxNet->proc_net)) != NULL);
#else
    APX_ALERT((OpaqueEngine->ProcRoot = proc_mkdir(name, proc_net)) != NULL);
#endif

    for (i = 0; i < sizeof(_procEntries)/sizeof(PROC_ENTRY); i++)
    {
        APX_ASSERT(_procEntries[i].Data < OPAQUE_ENGINE_ALIGN_SIZE);
        data = (unsigned long)OpaqueEngine + _procEntries[i].Data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
        APX_ALERT((entry = proc_create_data(
            _procEntries[i].Name,
            _procEntries[i].Mode,
            OpaqueEngine->ProcRoot,
            &_io_proc_fops,
            (void*)data)) != NULL);
#else
        APX_ALERT((entry = create_proc_read_entry(
            _procEntries[i].Name,
            _procEntries[i].Mode,
            OpaqueEngine->ProcRoot,
            _settingsRead,
            (void*)data)) != NULL);

        if (_procEntries[i].Mode & 0200)
        {
            entry->write_proc = _settingsWrite;
        }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
        entry->owner = THIS_MODULE;
#endif
#endif
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    entry = proc_create_data("ioctl", S_IWUSR | S_IRUGO, OpaqueEngine->ProcRoot, &_ioctl_proc_ops, OpaqueEngine);
    if (entry != NULL)
        return TRUE;
#else
    entry = create_proc_entry("ioctl", S_IWUSR | S_IRUGO, OpaqueEngine->ProcRoot);
    if (entry)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
        entry->owner = THIS_MODULE;
#endif
        entry->proc_fops = &_ioctl_proc_ops;
        entry->data = OpaqueEngine;
        return TRUE;
    }
#endif
    return FALSE;
}

static void _procRelease(APX_OPAQUE_ENGINE *OpaqueEngine)
{
    int i;
    char name[32];

    if (!OpaqueEngine->ProcRoot) return;

    if (OpaqueEngine->EngineId)
    {
        APX_APRINTF(name, "appex%d", OpaqueEngine->EngineId);
    }
    else
    {
        APX_APRINTF(name, "appex");
    }

    for (i = 0; i < sizeof(_procEntries)/sizeof(PROC_ENTRY); i++)
    {
        remove_proc_entry(_procEntries[i].Name, OpaqueEngine->ProcRoot);
    }
    remove_proc_entry("ioctl", OpaqueEngine->ProcRoot);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 23)
    //remove_proc_entry(name, init_net.proc_net);
    remove_proc_entry(name, gApxNet->proc_net);
#else
    remove_proc_entry(name, proc_net);
#endif
}

/*******************************************************************************
 * External event process
 ******************************************************************************/
void
appexIoAddEvents(
    APX_OPAQUE_ENGINE* OpaqueEngine,
    APX_IO_EVENT *event
    )
{
    unsigned long flags;
    spin_lock_irqsave(&OpaqueEngine->EventLock, flags);
    APX_ListInsertTailNode(&OpaqueEngine->EventList.List, &event->List);
    spin_unlock_irqrestore(&OpaqueEngine->EventLock, flags);
}

void
appexIoCancelEvent(
    APX_OPAQUE_ENGINE* OpaqueEngine,
    APX_IO_EVENT *event
    )
{
    unsigned long flags;
    spin_lock_irqsave(&OpaqueEngine->EventLock, flags);
    APX_ListRemoveNode(&event->List);
    spin_unlock_irqrestore(&OpaqueEngine->EventLock, flags);
}

BOOL appexIoProcessEvents(APX_OPAQUE_ENGINE* OpaqueEngine)
{
    unsigned long flags;
    APX_IO_EVENT *event, *next;
    int holdMem;
    BOOL reschedule = FALSE;

    spin_lock_irqsave(&OpaqueEngine->EventLock, flags);
    next = APX_CONTAINER(OpaqueEngine->EventList.List.Next, APX_IO_EVENT, List);
    APX_ListInit(&OpaqueEngine->EventList.List);
    spin_unlock_irqrestore(&OpaqueEngine->EventLock, flags);

    while ((event = next) != &OpaqueEngine->EventList)
    {
        next = APX_CONTAINER(event->List.Next, APX_IO_EVENT, List);
        holdMem = event->HoldMem;
        switch (event->Type)
        {
            case APX_IO_EVENT_IF_UP:
            case APX_IO_EVENT_IF_DOWN:
            case APX_IO_EVENT_IF_DEL:
            break;
 
            case APX_IO_EVENT_PROC_SET:
            {
                event->ProcData.Result = _settingsWriteFunc(OpaqueEngine, event->ProcData.Buf,
                    event->ProcData.Len, event->ProcData.Data);
                smp_wmb();
                event->ProcData.Done = 1;
                wake_up(&OpaqueEngine->WaitQeue);
                break;
            }
            case APX_IO_EVENT_PROC_GET:
            {
                event->ProcData.Result = _settingsReadFunc(OpaqueEngine, event->ProcData.Buf,
                    event->ProcData.Len, event->ProcData.Data);
                smp_wmb();
                event->ProcData.Done = 1;
                wake_up(&OpaqueEngine->WaitQeue);
                break;
            }
            case APX_IO_EVENT_IOCTL_SET_CONFIG:
            {
                if (event->SubType == APX_CLSF_CFG_TYPE_VIEW)
                {
                    event->ProcData.Result = APX_ClsfSetConfig(OpaqueEngine->Engine,
                        (APX_CLSF_CFG*)event->ProcData.Data);
                }
                else
                {
                    event->ProcData.Result = APX_STATUS_FAIL;
                }
                smp_wmb();
                event->ProcData.Done = 1;
                wake_up(&OpaqueEngine->WaitQeue);
                break;
            }
            case APX_IO_EVENT_IOCTL_GET_STATS:
            {
                event->ProcData.Result = APX_ClsfGetStats(OpaqueEngine->Engine,
                    (APX_CLSF_STATS*)event->ProcData.Data);
                smp_wmb();
                event->ProcData.Done = 1;
                wake_up(&OpaqueEngine->WaitQeue);
                break;
            }
            case APX_IO_EVENT_IOCTL_GET_COMP_STATS:
            {
                APX_ENGINE_STATISTICS engStats;
                APX_BASE_COMP_STATS* stats = (APX_BASE_COMP_STATS*)event->ProcData.Data;

                APX_BaseMemSet(&engStats, 0, sizeof(engStats));
                (void)APX_EngineGetEngineStatistics(OpaqueEngine->Engine, &engStats);
                stats->CompLanInBytes = engStats.CompBytes[0][0];
                stats->CompLanOutBytes = engStats.CompBytes[0][1];
                stats->CompWanOutBytes = engStats.CompBytes[1][0];
                stats->CompWanInBytes = engStats.CompBytes[1][1];
                stats->CompLanInBytesL4 = engStats.CompBytesL4[0][0];
                stats->CompLanOutBytesL4 = engStats.CompBytesL4[0][1];
                stats->CompWanOutBytesL4 = engStats.CompBytesL4[1][0];
                stats->CompWanInBytesL4 = engStats.CompBytesL4[1][1];
                smp_wmb();
                event->ProcData.Done = 1;
                wake_up(&OpaqueEngine->WaitQeue);
                break;
            }
#ifdef APXENV_LTT_IF
            case APX_IO_EVENT_LTT_TUNNEL_CREATE:
            {
                APX_STATUS rc;
                APX_FLOW_KEY *key;

                key = (APX_FLOW_KEY *)(event + 1);
                rc = APX_EngineLttCreate(OpaqueEngine->Engine, key, FALSE);
                if (!APX_SUCCEEDED(rc))
                {
                    printk(KERN_ERR "Failed to create ltt tunnel for tid 0x%x, rc=0x%x\n",
                        key->Viid, rc);
                }
                else
                {
                    reschedule = TRUE;
                }
                break;
            }
            case APX_IO_EVENT_LTT_TUNNEL_DELETE:
            {
                u32 tid = (u32)(uintptr_t)event->ProcData.Data;
                BOOL force = event->SubType? TRUE : FALSE;
                APX_EngineLttDestroy(OpaqueEngine->Engine, tid, force);
                reschedule = TRUE;
                break;
            }
#endif
            default: break;
        }

        if (!holdMem)
        {
            APX_BaseMemFree(event);
        }
    }

    return reschedule;
}

void appexIoCleanupEvents(APX_OPAQUE_ENGINE* OpaqueEngine)
{
    unsigned long flags;
    APX_IO_EVENT *event, *next;

    spin_lock_irqsave(&OpaqueEngine->EventLock, flags);
    next = APX_CONTAINER(OpaqueEngine->EventList.List.Next, APX_IO_EVENT, List);
    APX_ListInit(&OpaqueEngine->EventList.List);
    spin_unlock_irqrestore(&OpaqueEngine->EventLock, flags);

    while ((event = next) != &OpaqueEngine->EventList)
    {
        next = APX_CONTAINER(event->List.Next, APX_IO_EVENT, List);

        if (!event->HoldMem)
        {
            APX_BaseMemFree(event);
        }
        else
        {
            event->ProcData.Result = APX_STATUS_CANCELLED;
            event->ProcData.Done = 1;
        }
    }

    smp_wmb();
    wake_up(&OpaqueEngine->WaitQeue);
}

/*******************************************************************************
 * appexIoInit() and appexIoRelease()
 ******************************************************************************/
void appexIoInit(APX_OPAQUE_ENGINE *OpaqueEngine)
{
    APX_ListInit(&OpaqueEngine->IoWqList.List);
    init_waitqueue_head(&OpaqueEngine->WaitQeue);
    spin_lock_init(&OpaqueEngine->IoWqLock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
    INIT_WORK(&OpaqueEngine->IoWq, _ioWqHandler);
#else
    INIT_WORK(&OpaqueEngine->IoWq, _ioWqHandler, &OpaqueEngine->IoWq);
#endif
    atomic_set(&OpaqueEngine->IoWqReEntry, 1);

#ifdef APXENV_SYN_RETRAN
    {
        int r = _appexIoSetSynRetran(OpaqueEngine, APX_ECfg.SynRetranMS);

        if (r != 0 && r != -EAGAIN)
        {
            printk(KERN_WARNING "appex: failed to create RTT array (%d).\n", r);
        }
    }
#endif /* APXENV_SYN_RETRAN */

    _procInit(OpaqueEngine);

#ifdef APXENV_UAPI
    if (OpaqueEngine->EngineId == 0)
    {
        (void)APX_UApiInit(OpaqueEngine);
    }
#endif /* APXENV_UAPI */
}

void appexIoRelease(APX_OPAQUE_ENGINE *OpaqueEngine)
{
#if defined(APXENV_PCAP_ENABLE)
    flush_scheduled_work();
#endif

#ifdef APXENV_PCAP_ENABLE
    _pcapStop(OpaqueEngine);
#endif

#ifdef APXENV_UAPI
    if (OpaqueEngine->EngineId == 0)
    {
        APX_UApiUninit(OpaqueEngine);
    }
#endif /* APXENV_UAPI */

    _procRelease(OpaqueEngine);

#ifdef APXENV_SYN_RETRAN
    (void)_appexIoSetSynRetran(OpaqueEngine, 0);
#endif /* APXENV_SYN_RETRAN */
}

/*******************************************************************************
 * util functions
 ******************************************************************************/

#define CLSF_PRINT_INFO_END 256
static char*
_printClsfViewInfo(
    char *P,
    char const* End,
    APX_CLSF_VIEW *View,
    int level
    );

static char*
_printClsfProfileInfo(
    char *P,
    char const* End,
    APX_CLSF_AGGR_NODE *AggrNode,
    int level
    )
{
    int i, j;
    APX_CLSF_PROFILE *node;
    APX_CLSF_FILTER *filter;

    for (i=0; i<level; i++) P = APX_SEPrintf(P, End, "  ");

    node = (APX_CLSF_PROFILE*)AggrNode->Info;
    P = APX_SEPrintf(P, End, "PROFILE(%s): ID=0x%x Action=0x%x/0x%x Priority=%d-%d Dscp=%d, Bw=%d-%d-%u-%u-%u-%u "
        "BwHost=%u-%u sessLimit=%u-%u-%u\n",
        node->Cfg.Name, node->Cfg.ID, node->Cfg.Action, node->Cfg.ActionExclude, node->Cfg.Priority[0],
        node->Cfg.Priority[1], node->Cfg.Dscp,
        node->Cfg.PriorityGurantee[0], node->Cfg.PriorityGurantee[1],
        node->Cfg.BwGurantee[0], node->Cfg.BwGurantee[1],
        node->Cfg.BwMax[0], node->Cfg.BwMax[1],
        node->Cfg.BwMaxHost[0], node->Cfg.BwMaxHost[1],
        node->Cfg.HostFairMaxTcpAccSess, node->Cfg.HostFairMaxTcpActSess, node->Cfg.HostFairMaxUdpSess);
        /* AggrNode->Stats.Sessions, (UINT32)AggrNode->Stats.Bytes[0][0], (UINT32)AggrNode->Stats.Bytes[0][1]); */
    if (End - P < CLSF_PRINT_INFO_END) return P;

    for (i=0; i<node->Cfg.NumFilters; i++)
    {
        filter = &node->Cfg.Filters[i];
        for (j=0; j<level; j++) P = APX_SEPrintf(P, End, "  ");
        if (filter->Field & APX_CLSF_FILTER_SRC_IP)
        {
            P = APX_SEPrintf(P, End, "  SRC_IP: 0x%x-0x%x\n", filter->u.Ip.Val1, filter->u.Ip.Val2);
        }
        else if (filter->Field & APX_CLSF_FILTER_DST_IP)
        {
            P = APX_SEPrintf(P, End, "  DST_IP: 0x%x-0x%x\n", filter->u.Ip.Val1, filter->u.Ip.Val2);
        }
        else if (filter->Field & APX_CLSF_FILTER_SRC_PORT)
        {
            P = APX_SEPrintf(P, End, "  SRC_PORT: %u - %u\n", filter->u.Port.Val1, filter->u.Port.Val2);
        }
        else if (filter->Field & APX_CLSF_FILTER_DST_PORT)
        {
            P = APX_SEPrintf(P, End, "  DST_PORT: %u - %u\n", filter->u.Port.Val1, filter->u.Port.Val2);
        }
        else if (filter->Field & APX_CLSF_FILTER_DSCP)
        {
            P = APX_SEPrintf(P, End, "  DSCP: %u - %u\n", filter->u.Dscp.Val1, filter->u.Dscp.Val2);
        }
        else if (filter->Field & APX_CLSF_FILTER_PROTO)
        {
            P = APX_SEPrintf(P, End, "  PROTO: %d\n", filter->u.Protocol.Val);
        }
        else if (filter->Field & APX_CLSF_FILTER_L7RULE)
        {
            P = APX_SEPrintf(P, End, "  L7_ID: %d\n", filter->u.L7Rule.ID);
        }
        if (End - P < CLSF_PRINT_INFO_END) return P;
    }

    if (node->AttachView && level < 3)
    {
        P = _printClsfViewInfo(P, End, node->AttachView, level + 1);
    }

    return P;
}

static char*
_printClsfGroupInfo(
    char *P,
    char const* End,
    APX_CLSF_AGGR_NODE *AggrNode,
    int level
    )
{
    int i;
    APX_CLSF_AGGR_NODE *subNode;
    APX_CLSF_GROUP *node;
    APX_LIST *pos;

    for (i=0; i<level; i++) P = APX_SEPrintf(P, End, "  ");

    node = (APX_CLSF_GROUP*)AggrNode->Info;
    P = APX_SEPrintf(P, End, "GROUP(%s): ID=0x%x Action=0x%x/0x%x Priority=%d-%d Dscp=%d, Bw=%d-%d-%u-%u-%u-%u, "
        "BwHost=%u-%u, sessLimit=%u-%u-%u\n",
        node->Cfg.Name, node->Cfg.ID, node->Cfg.Action, node->Cfg.ActionExclude, node->Cfg.Priority[0],
        node->Cfg.Priority[1], node->Cfg.Dscp,
        node->Cfg.PriorityGurantee[0], node->Cfg.PriorityGurantee[1],
        node->Cfg.BwGurantee[0], node->Cfg.BwGurantee[1],
        node->Cfg.BwMax[0], node->Cfg.BwMax[1],
        node->Cfg.BwMaxHost[0], node->Cfg.BwMaxHost[1],
        node->Cfg.HostFairMaxTcpAccSess, node->Cfg.HostFairMaxTcpActSess, node->Cfg.HostFairMaxUdpSess);
    if (End - P < CLSF_PRINT_INFO_END) return P;

    APX_LIST_FOR_EACH(&AggrNode->u.SubNodes.StaticAggrNodes.Profiles, pos)
    {
        subNode = (APX_CLSF_AGGR_NODE*)((APX_CLSF_LIST_NODE*)pos)->Info;
        P = _printClsfProfileInfo(P, End, subNode, level + 1);
        if (End - P < CLSF_PRINT_INFO_END) return P;
    }

    return P;
}

static char*
_printClsfViewInfo(
    char *P,
    char const* End,
    APX_CLSF_VIEW *View,
    int level
    )
{
    int i;
    APX_CLSF_AGGR_NODE *subNode;
    APX_LIST *pos;

    for (i=0; i<level; i++) P = APX_SEPrintf(P, End, "  ");

    P = APX_SEPrintf(P, End, "VIEW(%s): ID=0x%x DynFields=%x\n", View->Name, View->ID, (UINT32)View->DynAggrFieldMask);
    if (End - P < CLSF_PRINT_INFO_END) return P;

    if (View->AggrNode.u.SubNodes.IsStatic)
    {
        APX_LIST_FOR_EACH(&View->AggrNode.u.SubNodes.StaticAggrNodes.Groups, pos)
        {
            subNode = (APX_CLSF_AGGR_NODE*)((APX_CLSF_LIST_NODE*)pos)->Info;
            P = _printClsfGroupInfo(P, End, subNode, level + 1);
            if (End - P < CLSF_PRINT_INFO_END) return P;
        }
        APX_LIST_FOR_EACH(&View->AggrNode.u.SubNodes.StaticAggrNodes.Profiles, pos)
        {
            subNode = (APX_CLSF_AGGR_NODE*)((APX_CLSF_LIST_NODE*)pos)->Info;
            P = _printClsfProfileInfo(P, End, subNode, level + 1);
            if (End - P < CLSF_PRINT_INFO_END) return P;
        }
        if (View->AggrNode.u.SubNodes.StaticAggrNodes.DefaultAggr)
        {
            level++;
            for (i=0; i<level; i++) P = APX_SEPrintf(P, End, "  ");
            P = APX_SEPrintf(P, End, "PROFILE(default): Action=0x%x/0x%x Priority=%d-%d Dscp=%u\n",
                View->DefaultAction, View->DefaultActionExclude, View->DefaultPriority[0],
                View->DefaultPriority[1], View->DefaultDscp);
            if (View->AggrNode.u.SubNodes.StaticAggrNodes.DefaultAggr->Info)
            {
                P = _printClsfViewInfo(P, End,
                    (APX_CLSF_VIEW*)View->AggrNode.u.SubNodes.StaticAggrNodes.DefaultAggr->Info, level + 1);
            }
        }
    }

    return P;
}

static int
_printClsfInfo(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    char *buf,
    size_t size
    )
{
    char *p = buf;
    APX_CLSF_VIEW *view;
    APX_CLSF_ENGINE *clsf = APX_EClsfGet(OpaqueEngine->Engine);
    for (view = clsf->Views[0]; view != NULL; view = view->Next)
    {
        p = _printClsfViewInfo(p, buf + size, view, 0);
    }
    return p - buf;
}

static int
_printDefaultInfo(
    APX_OPAQUE_ENGINE *OpaqueEngine,
    char *buf,
    size_t size
    )
{
    char *p = buf;
    char const* end = buf + size;
    APX_ENGINE_STATISTICS engStats;
    APX_CLSF_ENGINE *clsf = APX_EClsfGet(OpaqueEngine->Engine);
    APX_CLSF_VIEW *view = clsf->Views[0];
    UINT32 i, curTime;

    APX_BaseMemSet(&engStats, 0, sizeof(engStats));
    APX_EngineGetEngineStatistics(OpaqueEngine->Engine, &engStats);

    #define PRINT_COUNTER2(_format_, _value_) { p = APX_SEPrintf(p, end, _format_, _value_); }
    #define PRINT_COUNTER(_format_, _value_)  { if ((_value_)) PRINT_COUNTER2(_format_, _value_); }

    if (OpaqueEngine->Cfg.DisplayLevel >= 5)
    {
    PRINT_COUNTER2("NumOfFlows      = %u\n", engStats.V4.NumOfFlows + engStats.V6.NumOfFlows);
    PRINT_COUNTER2("NumOfTcpFlows   = %u\n", engStats.V4.NumOfTcpFlows + engStats.V6.NumOfTcpFlows);
    PRINT_COUNTER2("NumOfAccFlows   = %u\n", engStats.V4.NumOfAccFlows + engStats.V6.NumOfAccFlows);
    PRINT_COUNTER2("NumOfActFlows   = %u\n", engStats.V4.NumOfActFlows + engStats.V6.NumOfActFlows);
    PRINT_COUNTER2("LanInBytes      = %llu\n", engStats.V4.TotalBytes[0][0] + engStats.V6.TotalBytes[0][0]);
    PRINT_COUNTER2("LanOutBytes     = %llu\n", engStats.V4.TotalBytes[0][1] + engStats.V6.TotalBytes[0][1]);
    PRINT_COUNTER2("WanInBytes      = %llu\n", engStats.V4.TotalBytes[1][1] + engStats.V6.TotalBytes[1][1]);
    PRINT_COUNTER2("WanOutBytes     = %llu\n", engStats.V4.TotalBytes[1][0] + engStats.V6.TotalBytes[1][0]);
    PRINT_COUNTER2("LanInPackets    = %llu\n", engStats.V4.TotalPackets[0][0] + engStats.V6.TotalBytes[0][0]);
    PRINT_COUNTER2("LanOutPackets   = %llu\n", engStats.V4.TotalPackets[0][1] + engStats.V6.TotalBytes[0][1]);
    PRINT_COUNTER2("WanInPackets    = %llu\n", engStats.V4.TotalPackets[1][1] + engStats.V6.TotalBytes[1][1]);
    PRINT_COUNTER2("WanOutPackets   = %llu\n", engStats.V4.TotalPackets[1][0] + engStats.V6.TotalBytes[1][0]);

    }

    if (OpaqueEngine->Cfg.DisplayLevel > 5)
    {
    /* mpool stats */
    size_t memCached = APX_LinuxMPoolGetCached(OpaqueEngine->MPools);
    size_t memAlloc = APX_LinuxMPoolGetAlloc(OpaqueEngine->MPools);
    PRINT_COUNTER2("MPoolCached     = %zu\n", memCached);
    PRINT_COUNTER2("MPoolAlloc      = %zu\n", memAlloc);

    /* engine stats */
    PRINT_COUNTER("CorruptedPackets     = %u\n", engStats.CorruptedPackets);
    PRINT_COUNTER("AcquirePackets       = %lld\n", engStats.AcquirePackets);
    PRINT_COUNTER("ReleasePackets       = %lld\n", engStats.ReleasePackets);
    PRINT_COUNTER("TcpPacketLimitFails  = %lld\n", engStats.TcpPacketLimitFails);
    PRINT_COUNTER("AcquirePacketFails   = %lld\n", engStats.AcquirePacketFails);
    PRINT_COUNTER("AcquireOpaquePacketFails = %lld\n", engStats.AcquireOpaquePacketFails);
    PRINT_COUNTER("CloneOpaquePacketFails   = %lld\n", engStats.CloneOpaquePacketFails);
    PRINT_COUNTER("CreateFlowFails      = %lld\n", engStats.CreateFlowFails);
    PRINT_COUNTER("CreateTcpFlowFails   = %lld\n", engStats.CreateTcpFlowFails);
    PRINT_COUNTER("CreateCompLinkFails  = %lld\n", engStats.CreateCompLinkFails);
    PRINT_COUNTER("BadComps             = %lld\n", engStats.BadComps);
    PRINT_COUNTER("WanIfCongests        = %u\n",  engStats.WanIfCongests);
    PRINT_COUNTER("AvailPackets         = %u\n",  engStats.AvailPackets);
    PRINT_COUNTER("AcquirePacketBaseFails = %u\n",  engStats.AcquirePacketBaseFails);
    PRINT_COUNTER("ReasDiscards         = %u\n", engStats.V4.ReasDiscards + engStats.V6.ReasDiscards);

    PRINT_COUNTER("Tcp.IntfLanOutDiscards         = %u\n", engStats.Tcp.IntfLanOutDiscards);
    PRINT_COUNTER("Tcp.IntfWanOutDiscards         = %u\n", engStats.Tcp.IntfWanOutDiscards);
    PRINT_COUNTER("Tcp.ClsfRecvDiscards           = %u\n", engStats.Tcp.ClsfRecvDiscards);
    PRINT_COUNTER("Tcp.ClsfSendDiscards           = %u\n", engStats.Tcp.ClsfSendDiscards);
    PRINT_COUNTER("Tcp.PacketPoolLowDiscards      = %u\n", engStats.Tcp.PacketPoolLowDiscards);
//    PRINT_COUNTER("CorruptedPackets     = %u\n", engStats.CorruptedPackets);
    PRINT_COUNTER("Tcp.PacketBasePoolLowDiscards  = %u\n", engStats.Tcp.PacketBasePoolLowDiscards);
    PRINT_COUNTER("Tcp.FlowNullDiscards           = %u\n", engStats.Tcp.FlowNullDiscards);
    PRINT_COUNTER("Tcp.FlowDropDiscards           = %u\n", engStats.Tcp.FlowDropDiscards);
    PRINT_COUNTER("Tcp.FlowDestroyDiscards        = %u\n", engStats.Tcp.FlowDestroyDiscards);
    PRINT_COUNTER("Tcp.FlowDestroyAckDiscards     = %u\n", engStats.Tcp.FlowDestroyAckDiscards);
    PRINT_COUNTER("Tcp.SchdQueueFullDiscards      = %u\n", engStats.Tcp.SchdQueueFullDiscards);
    PRINT_COUNTER("Tcp.SchdAckQueueFullDiscards   = %u\n", engStats.Tcp.SchdAckQueueFullDiscards);
    PRINT_COUNTER("Tcp.SchdAckMergeDiscards       = %u\n", engStats.Tcp.SchdAckMergeDiscards);
    PRINT_COUNTER("Tcp.SchdAckCreates             = %u\n", engStats.Tcp.SchdAckCreates);
    PRINT_COUNTER("Tcp.AccClsfNoSends             = %u\n", engStats.Tcp.AccClsfNoSends);
    PRINT_COUNTER("Tcp.AccClsfSendDiscards        = %u\n", engStats.Tcp.AccClsfSendDiscards);
    PRINT_COUNTER("Tcp.AccPacketPoolLowDiscards   = %u\n", engStats.Tcp.AccPacketPoolLowDiscards);
    PRINT_COUNTER("Tcp.AccPacketMemLowDiscards    = %u\n", engStats.Tcp.AccPacketMemLowDiscards);

    PRINT_COUNTER("Udp.IntfLanOutDiscards         = %u\n", engStats.Udp.IntfLanOutDiscards);
    PRINT_COUNTER("Udp.IntfWanOutDiscards         = %u\n", engStats.Udp.IntfWanOutDiscards);
    PRINT_COUNTER("Udp.ClsfRecvDiscards           = %u\n", engStats.Udp.ClsfRecvDiscards);
    PRINT_COUNTER("Udp.ClsfSendDiscards           = %u\n", engStats.Udp.ClsfSendDiscards);
    PRINT_COUNTER("Udp.PacketPoolLowDiscards      = %u\n", engStats.Udp.PacketPoolLowDiscards);
    PRINT_COUNTER("Udp.PacketBasePoolLowDiscards  = %u\n", engStats.Udp.PacketBasePoolLowDiscards);
    PRINT_COUNTER("Udp.FlowNullDiscards           = %u\n", engStats.Udp.FlowNullDiscards);
    PRINT_COUNTER("Udp.FlowDropDiscards           = %u\n", engStats.Udp.FlowDropDiscards);
    PRINT_COUNTER("Udp.FlowDestroyDiscards        = %u\n", engStats.Udp.FlowDestroyDiscards);
    PRINT_COUNTER("Udp.SchdQueueFullDiscards      = %u\n", engStats.Udp.SchdQueueFullDiscards);

    PRINT_COUNTER("Misc.IntfLanOutDiscards        = %u\n", engStats.Misc.IntfLanOutDiscards);
    PRINT_COUNTER("Misc.IntfWanOutDiscards        = %u\n", engStats.Misc.IntfWanOutDiscards);
    PRINT_COUNTER("Misc.ClsfRecvDiscards          = %u\n", engStats.Misc.ClsfRecvDiscards);
    PRINT_COUNTER("Misc.ClsfSendDiscards          = %u\n", engStats.Misc.ClsfSendDiscards);
    PRINT_COUNTER("Misc.PacketPoolLowDiscards     = %u\n", engStats.Misc.PacketPoolLowDiscards);
    PRINT_COUNTER("Misc.PacketBasePoolLowDiscards = %u\n", engStats.Misc.PacketBasePoolLowDiscards);
    PRINT_COUNTER("Misc.FlowNullDiscards          = %u\n", engStats.Misc.FlowNullDiscards);
    PRINT_COUNTER("Misc.FlowDropDiscards          = %u\n", engStats.Misc.FlowDropDiscards);
    PRINT_COUNTER("Misc.FlowDestroyDiscards       = %u\n", engStats.Misc.FlowDestroyDiscards);
    PRINT_COUNTER("Misc.SchdQueueFullDiscards     = %u\n", engStats.Misc.SchdQueueFullDiscards);

    PRINT_COUNTER("Rtt                  = %u\n",  engStats.Rtt);

#ifdef APXENV_LIGHT_TCP_TUNNEL
    PRINT_COUNTER("Ltt.NumOfV1Tunnels             = %u\n",   engStats.Ltt.NumOfV1Tunnels);
    PRINT_COUNTER("Ltt.NumOfV2Tunnels             = %u\n",   engStats.Ltt.NumOfV2Tunnels);
    PRINT_COUNTER("Ltt.TunnelNatSipFails          = %u\n",   engStats.Ltt.TunnelNatSipFails);
    PRINT_COUNTER("Ltt.TunnelT.InBytes            = %llu\n", engStats.Ltt.TunnelT.InBytes);
    PRINT_COUNTER("Ltt.TunnelT.InPackets          = %llu\n", engStats.Ltt.TunnelT.InPackets);
    PRINT_COUNTER("Ltt.TunnelT.OutBytes           = %llu\n", engStats.Ltt.TunnelT.OutBytes);
    PRINT_COUNTER("Ltt.TunnelT.OutPackets         = %llu\n", engStats.Ltt.TunnelT.OutPackets);
    PRINT_COUNTER("Ltt.TunnelU.InBytes            = %llu\n", engStats.Ltt.TunnelU.InBytes);
    PRINT_COUNTER("Ltt.TunnelU.InPackets          = %llu\n", engStats.Ltt.TunnelU.InPackets);
    PRINT_COUNTER("Ltt.TunnelU.OutBytes           = %llu\n", engStats.Ltt.TunnelU.OutBytes);
    PRINT_COUNTER("Ltt.TunnelU.OutPackets         = %llu\n", engStats.Ltt.TunnelU.OutPackets);
    PRINT_COUNTER("Ltt.TunnelNoRouteDiscards      = %llu\n", engStats.Ltt.TunnelNoRouteDiscards);
    PRINT_COUNTER("Ltt.TunnelMtuDiscards          = %llu\n", engStats.Ltt.TunnelMtuDiscards);
    PRINT_COUNTER("Ltt.TunnelFullDiscards         = %llu\n", engStats.Ltt.TunnelFullDiscards);
    PRINT_COUNTER("Ltt.TunnelResDiscards          = %llu\n", engStats.Ltt.TunnelResDiscards);
    PRINT_COUNTER("Ltt.TunnelNatDiscards          = %llu\n", engStats.Ltt.TunnelNatDiscards);
    PRINT_COUNTER("Ltt.NoTunnelDiscards           = %llu\n", engStats.Ltt.NoTunnelDiscards);
#endif /* APXENV_LIGHT_TCP_TUNNEL */

    for (i=0; i<APX_CLSF_CNT_MAX; i++)
    {
        if (clsf->Cnt[i]) p = APX_SEPrintf(p, end, "ClsfCnt[%d]      = %u\n", i, clsf->Cnt[i]);
    }

    /* base stats */
    /* netif counters. */
    PRINT_COUNTER("NfTxRoutedNotHost    = %llu\n", OpaqueEngine->NfTxRoutedNotHost);
    PRINT_COUNTER("NfRxRoutedNotHost    = %llu\n", OpaqueEngine->NfRxRoutedNotHost);
    PRINT_COUNTER("NfRxBridgedNotOthers = %llu\n", OpaqueEngine->NfRxBridgedNotOthers);
    PRINT_COUNTER("devTxWanCongest      = %llu\n", OpaqueEngine->devTxWanCongest);
    }
    PRINT_COUNTER("NfIpNotV4            = %llu\n", OpaqueEngine->NfIpNotV4);
    PRINT_COUNTER("NfIpLenTooBig        = %llu\n", OpaqueEngine->NfIpLenTooBig);
    PRINT_COUNTER("NfIpPayloadExceed    = %llu\n", OpaqueEngine->NfIpPayloadExceed);
    PRINT_COUNTER("NfIpFragments        = %llu\n", OpaqueEngine->NfIpFragments);
    PRINT_COUNTER("NfIpNonLinear        = %llu\n", OpaqueEngine->NfIpNonLinear);
    PRINT_COUNTER("NfIpLinerizeFail     = %llu\n", OpaqueEngine->NfIpLinerizeFail);
    PRINT_COUNTER("NfIpMcasts           = %llu\n", OpaqueEngine->NfIpMcasts);
    PRINT_COUNTER("NfIpShared           = %llu\n", OpaqueEngine->NfIpShared);
    PRINT_COUNTER("NfBypass             = %llu\n", OpaqueEngine->NfBypass);
    PRINT_COUNTER("NfIpBadHeaderLen     = %llu\n", OpaqueEngine->NfIpBadHeaderLen);
    PRINT_COUNTER("NfTcpBadHeaderLen    = %llu\n", OpaqueEngine->NfTcpBadHeaderLen);
    PRINT_COUNTER("NfTcpPayloadExceed   = %llu\n", OpaqueEngine->NfTcpPayloadExceed);
    PRINT_COUNTER("NfUdpPayloadExceed   = %llu\n", OpaqueEngine->NfUdpPayloadExceed);
    PRINT_COUNTER("NfLanBypass          = %llu\n", OpaqueEngine->NfLanBypass);
    PRINT_COUNTER("NfSkbShrunk          = %llu\n", OpaqueEngine->NfSkbShrunk);
    PRINT_COUNTER("NfRxTcpChecksumError = %llu\n", OpaqueEngine->NfRxTcpChecksumError);
    PRINT_COUNTER("NfRxUdpChecksumError = %llu\n", OpaqueEngine->NfRxUdpChecksumError);
    PRINT_COUNTER("NfRxMiscChecksumError = %llu\n", OpaqueEngine->NfRxMiscChecksumError);
    PRINT_COUNTER("NfTxTcpChecksumError = %llu\n", OpaqueEngine->NfTxTcpChecksumError);
    PRINT_COUNTER("NfTxUdpChecksumError = %llu\n", OpaqueEngine->NfTxUdpChecksumError);
    PRINT_COUNTER("NfTxMiscChecksumError = %llu\n", OpaqueEngine->NfTxMiscChecksumError);
    PRINT_COUNTER("NfRxRsc              = %llu\n", OpaqueEngine->NfRxRsc);
    PRINT_COUNTER("NfRxRscFail          = %llu\n", OpaqueEngine->NfRxRscFail);
    PRINT_COUNTER("NfIpCloneLinerizeFail= %llu\n", OpaqueEngine->NfIpCloneLinerizeFail);
    PRINT_COUNTER("NfTxGso              = %llu\n", OpaqueEngine->NfTxGso);
    PRINT_COUNTER("NfTxGsoFail          = %llu\n", OpaqueEngine->NfTxGsoFail);
    PRINT_COUNTER("devTxFail            = %llu\n", OpaqueEngine->devTxFail);
    PRINT_COUNTER("queueFullDisc0Tcp    = %u\n", OpaqueEngine->queueFullDiscTcp[0]);
    PRINT_COUNTER("queueFullDisc0Udp    = %u\n", OpaqueEngine->queueFullDiscUdp[0]);
    PRINT_COUNTER("queueFullDisc0Misc   = %u\n", OpaqueEngine->queueFullDiscMisc[0]);
    PRINT_COUNTER("queueFullDisc1Tcp    = %u\n", OpaqueEngine->queueFullDiscTcp[1]);
    PRINT_COUNTER("queueFullDisc1Udp    = %u\n", OpaqueEngine->queueFullDiscUdp[1]);
    PRINT_COUNTER("queueFullDisc1Misc   = %u\n", OpaqueEngine->queueFullDiscMisc[1]);
#ifdef APXENV_PCAP_ENABLE
    PRINT_COUNTER("pcapDiscard          = %u\n", OpaqueEngine->PcapDiscard);
    PRINT_COUNTER("pcapNoResource       = %u\n", OpaqueEngine->PcapNoResource);
#endif
    PRINT_COUNTER("AcclinksLanInBytes    = %llu\n", OpaqueEngine->acclinkBytes[0][0]);
    PRINT_COUNTER("AcclinksLanOutBytes   = %llu\n", OpaqueEngine->acclinkBytes[0][1]);
    PRINT_COUNTER("AcclinksWanInBytes    = %llu\n", OpaqueEngine->acclinkBytes[1][1]);
    PRINT_COUNTER("AcclinksWanOutBytes   = %llu\n", OpaqueEngine->acclinkBytes[1][0]);
    PRINT_COUNTER("AcclinksLanInPackets  = %llu\n", OpaqueEngine->acclinkPkts[0][0]);
    PRINT_COUNTER("AcclinksLanOutPackets = %llu\n", OpaqueEngine->acclinkPkts[0][1]);
    PRINT_COUNTER("AcclinksWanInPackets  = %llu\n", OpaqueEngine->acclinkPkts[1][1]);
    PRINT_COUNTER("AcclinksWanOutPackets = %llu\n", OpaqueEngine->acclinkPkts[1][0]);
    PRINT_COUNTER("acclinksRxBypassPkts  = %llu\n", OpaqueEngine->acclinkRxBypassPkts);
    PRINT_COUNTER("vxlanRxOk             = %llu\n", OpaqueEngine->vxlanRxOk);
    PRINT_COUNTER("vxlanRxBypass         = %llu\n", OpaqueEngine->vxlanRxBypass);
    PRINT_COUNTER("vxlanTxOk             = %llu\n", OpaqueEngine->vxlanTxOk);

    curTime = (UINT32)APX_BaseGetMilliSecondTicks();

#ifdef CONFIG_SMP
    p = APX_SEPrintf(p, end, "cpuId=%d, curCpu=%d, engId=%d, engNum=%d, ipiNum=%u, msec=%u, usec=%u\n",
        OpaqueEngine->WanIF.CpuId, smp_processor_id(), OpaqueEngine->EngineId, engine_num,
        (UINT32)OpaqueEngine->WanIF.IpiNum, gApxCurMilliSecondTick, gApxCurMicroSecondTick);
#endif

#ifndef APXENV_NO_RAD
    /* system stats */
    if ((OpaqueEngine->Cfg.Flags & APX_ENGINE_FLAG_SHAPER_AUTO) == 0)
    {
        p = APX_SEPrintf(p, end, "inRate=%u, adaptedRate=%u, shapeRate=%u, burst=%u\n",
            clsf->SystemAggrNode->WeightedRate[1] / 1024,
            APX_ESchdGetBandwidth(OpaqueEngine->Engine, APX_INBOUND) * 8,
            OpaqueEngine->Engine->Scheduler.InAdjusted.Bpms * 8,
            OpaqueEngine->Engine->Scheduler.InAdjusted.BurstBytes);
        p = APX_SEPrintf(p, end, "outRate=%u, adaptedRate=%u, shapeRate=%u, burst=%u\n",
            clsf->SystemAggrNode->WeightedRate[0] / 1024,
            APX_ESchdGetBandwidth(OpaqueEngine->Engine, APX_OUTBOUND) * 8,
            OpaqueEngine->Engine->Scheduler.OutAdjusted.Bpms * 8,
            OpaqueEngine->Engine->Scheduler.OutAdjusted.BurstBytes);
    }
    else
    {
        p = APX_SEPrintf(p, end,
            "inRate=%u, adaptedRate=%u, startRate=%u, shapeRate=%u, congest=%u, rtt=%u, rttVar=%d/%d, "
            "noLossPkt=%d, conserv=%d-%d, msec=%u\n",
            (UINT32)(clsf->SystemAggrNode->WeightedRate[1] / 1024),
            (UINT32)(clsf->WanAdaptedRate[1] / 1024),
            (UINT32)(clsf->WanStartRate[1] / 1024),
            (UINT32)(OpaqueEngine->Engine->Scheduler.InAdjusted.Bpms * 8),
            (UINT32)clsf->WanCongest[1],
            (UINT32)engStats->Rtt,
            (int)clsf->TcpRttVar[0], (int)clsf->TcpRttVar[1], (int)clsf->RadState._noLossPkt[1],
            (int)clsf->RadState._conservMode[1], (int)clsf->RadState._speedingLevel[1],
            curTime
            );
        p = APX_SEPrintf(p, end,
            "outRate=%u, adaptedRate=%u, startRate=%u, shapeRate=%u, congest=%u, rtt=%u, rttVar=%d/%d, "
            "rttCnt=%d, noLossPkt=%d, conserv=%d-%d, msec=%u, voipRate=%u\n",
            (UINT32)(clsf->SystemAggrNode->WeightedRate[0] / 1024),
            (UINT32)(clsf->WanAdaptedRate[0] / 1024),
            (UINT32)(clsf->WanStartRate[0] / 1024),
            (UINT32)(OpaqueEngine->Engine->Scheduler.OutAdjusted.Bpms*8),
            (UINT32)clsf->WanCongest[0],
            (UINT32)engStats.Rtt,
            (int)clsf->TcpRttVar[0], (int)clsf->TcpRttVar[1],
            (int)OpaqueEngine->Engine->RttCnt, (int)clsf->RadState._noLossPkt[0],
            (int)clsf->RadState._conservMode[0], (int)clsf->RadState._speedingLevel[0],
            curTime,
            (UINT32)(clsf->VoipRate / 1024)
            );
    }
    p = APX_SEPrintf(p, end, "aveInTx=%d, aveInReTx=%d, curInTx=%d, curInReTx=%d, aveOutTx=%d, aveOutReTx=%d, "
        "curOutTx=%d, curOutReTx=%d\n",
        (int)clsf->RadState._smoothTxPackets[1], (int)clsf->RadState._smoothReTxPackets[1],
        (int)clsf->RadState._curTxPacket[1], (int)clsf->RadState._curReTxPacket[1],
        (int)clsf->RadState._smoothTxPackets[0], (int)clsf->RadState._smoothReTxPackets[0],
        (int)clsf->RadState._curTxPacket[0], (int)clsf->RadState._curReTxPacket[0]);
    p = APX_SEPrintf(p, end, "hostNum=%u, sess=%u, voipSess=%u, tcpAccSess=%u, tcpActSess=%u, passThruSess=%u, "
                    "msec=%u, maxPeriod=%u\n",
        clsf->HostAggrNum-1,
        clsf->SystemAggrNode->Stats->Sessions,
        clsf->SystemAggrNode->Stats->VoipSessions,
        clsf->SystemAggrNode->Stats->TcpAccSessions,
        clsf->SystemAggrNode->Stats->TcpActSessions,
        clsf->PassthruSessNum,
        curTime,
        OpaqueEngine->MaxPeriod);
#endif
    OpaqueEngine->MaxPeriod = 0;       /* reset it */

    /* host stats */
    if (view)
    {
        UINT32 srcIp;
        int linked = -1;
        APX_LIST *pos;
        APX_CLSF_AGGR_NODE *aggrNode;
        APX_CLSF_AGGR_STATS stats;
        APX_CLSF_AGGR_SUB_NODES *subNodes = &view->AggrNode.u.SubNodes;

        APX_LIST_FOR_EACH(&subNodes->DynAggrNodes, pos)
        {
            aggrNode = (APX_CLSF_AGGR_NODE*)((APX_CLSF_LIST_NODE*)pos)->Info;
            stats = *aggrNode->Stats;
            srcIp = aggrNode->Stats->DynAggrFields.SrcIp;
            if (aggrNode->SchdAggr)
            {
                int i;
                linked = 0;
                for (i=0; i<8; i++)
                {
                    linked |= (APX_ListIsNodeLinked(&aggrNode->SchdAggr->Ack[i].AggrNode)? 1 : 0) << i;
                }
            }

#ifndef APXENV_LTT_IF
            p = APX_SEPrintf(p, end,
                "busy=%u, inRate=%u, outRate=%u, ip=0x%x, sess=%u, "
                "tcpAccSess=%u, udpSess=%u, voipSess=%u, tcpActSess=%u, udpDeficit=%d:"
#ifndef APXOPT_SINGLE_PRIORITY
                "%u-%u-%u-%u-%u-%u-%u"
#endif
                "%u, msec=%u, isP2P=%d-%u-%u\n",
                aggrNode->BusyLevel,
                aggrNode->WeightedRate[1] / 1024,
                aggrNode->WeightedRate[0] / 1024,
                srcIp,
                stats.Sessions,
                stats.TcpAccSessions,
                stats.UdpSessions,
                stats.VoipSessions,
                stats.TcpActSessions,
                linked,
#ifndef APXOPT_SINGLE_PRIORITY
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[7].InDebtBytes : 0),
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[6].InDebtBytes : 0),
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[5].InDebtBytes : 0),
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[4].InDebtBytes : 0),
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[3].InDebtBytes : 0),
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[2].InDebtBytes : 0),
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[1].InDebtBytes : 0),
#endif
                (UINT32)APX_UDP_DROP_LEVEL(aggrNode->SchdAggr? aggrNode->SchdAggr->Ack[0].InDebtBytes : 0),
                curTime,
                (int)aggrNode->IsP2P,
                aggrNode->LowPriSessions[0],
                aggrNode->LowPriSessions[1]
                );
#endif
            if (p - buf > 2048) break;
        }
    }

    return p - buf;
}
