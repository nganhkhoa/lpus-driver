#ifndef _DRIVER_H
#define _DRIVER_H

typedef struct _POOL_HEADER {
    PVOID  addr;
    USHORT prevBlockSize;
    USHORT poolIndex;
    USHORT blockSize;
    USHORT poolType;
    ULONG  tag;
} POOL_HEADER, *PPOOL_HEADER;

enum VERSION_BY_POOL {
  WINDOWS_2018,
  WINDOWS_2019,
  WINDOWS_2020,
  WINDOWS_2020_FASTRING,
  WINDOWS_NOT_SUPPORTED
};

VOID
setup();

VOID
scan_ps_active_head();

VOID
toPoolHeader(PPOOL_HEADER p, PVOID chunkAddr);

VOID
tryNextChunk(PPOOL_HEADER p);

bool
validTag(PPOOL_HEADER p);

bool
validPool(PPOOL_HEADER p);

VOID
printChunkInfo(PPOOL_HEADER p);

VOID
scanNormalPool(ULONG64 nonPagedPoolStart, ULONG64 nonPagedPoolEnd);

VOID
scanLargePool(PVOID largePageTableArray, ULONG64 largePageTableSize);

PVOID
scanRemote(ULONG64 startAddress, ULONG64 endAddress, ULONG tag);

VOID
hideProcess(CHAR* name, ULONG64 size);

#endif
