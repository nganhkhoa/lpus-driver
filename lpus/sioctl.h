/*++

Copyright (c) 1997  Microsoft Corporation

Module Name:

    SIOCTL.H

Abstract:


    Defines the IOCTL codes that will be used by this driver.  The IOCTL code
    contains a command identifier, plus other information about the device,
    the type of access with which the file must have been opened,
    and the type of buffering.

Environment:

    Kernel mode only.

--*/

#ifndef _IOCTL_PROTOCOL_H
#define _IOCTL_PROTOCOL_H

// Device type
#define SIOCTL_TYPE 40000 // 32768 to 65535

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_SETUP_OFFSETS \
    CTL_CODE(SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define GET_KERNEL_BASE \
    CTL_CODE(SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define SCAN_PS_ACTIVE_HEAD \
    CTL_CODE(SIOCTL_TYPE, 0x902, METHOD_NEITHER, FILE_ANY_ACCESS)

#define SCAN_POOL \
    CTL_CODE(SIOCTL_TYPE, 0x903, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define SCAN_POOL_REMOTE \
    CTL_CODE(SIOCTL_TYPE, 0x904, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define DEREFERENCE_ADDRESS \
    CTL_CODE(SIOCTL_TYPE, 0xA00, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define DEREFERENCE_PHYSICAL_ADDRESS \
    CTL_CODE(SIOCTL_TYPE, 0xA01, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define HIDE_PROCESS_BY_NAME \
    CTL_CODE(SIOCTL_TYPE, 0xA02, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define GET_PTE_BASE_ADDRESS \
    CTL_CODE(SIOCTL_TYPE, 0xB01, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)


#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02

#define DRIVER_NAME       "poolscanner"

typedef struct _OFFSET_VALUE {
    ULONG64 eprocessNameOffset;
    ULONG64 eprocessLinkOffset;
    ULONG64 listBLinkOffset;
    ULONG64 processHeadOffset;
    ULONG64 miStateOffset;
    ULONG64 hardwareOffset;
    ULONG64 systemNodeOffset;
    ULONG64 firstVaOffset;
    ULONG64 lastVaOffset;
    ULONG64 largePageTableOffset;
    ULONG64 largePageSizeOffset;
    ULONG64 poolChunkSize;
    ULONG64 functionMiGetPteAddressOffset;
} OFFSET_VALUES, *POFFSET_VALUE;

typedef struct _DEREF_ADDR {
    ULONG64 addr;
    ULONG64 size;   // bytes
} DEREF_ADDR, *PDEREF_ADDR;

typedef struct _SCAN_RANGE {
    ULONG64 start;
    ULONG64 end;
    ULONG tag;
} SCAN_RANGE, *PSCAN_RANGE;

typedef struct _HIDE_PROCESS {
    CHAR name[15];
    ULONG64 size;
} HIDE_PROCESS, *PHIDE_PROCESS;

typedef union _INPUT_DATA {
    OFFSET_VALUES offsetValues;
    DEREF_ADDR derefAddr;
    SCAN_RANGE scanRange;
    HIDE_PROCESS processHide;
} INPUT_DATA, *PINPUT_DATA;

typedef struct _POOL_CHUNK {
    ULONG64 addr;
} POOL_CHUNK, *PPOOL_CHUNK;

typedef union _OUTPUT_DATA {
    ULONG64 ulong64Value;   // for gereral addresses, value fit in 64 bit
    POOL_CHUNK poolChunk;
} OUTPUT_DATA, *POUTPUT_DATA;

#endif
