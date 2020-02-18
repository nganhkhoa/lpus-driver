#include <ntddk.h>
#include <wdf.h>
#include <ntdef.h>

#include "sioctl.h"
#include "Driver.h"
// #include "peformat.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD UnloadRoutine;
extern "C" PDBGKD_GET_VERSION64 FindKdVersionBlock(void);

#define NT_DEVICE_NAME      L"\\Device\\poolscanner"
#define DOS_DEVICE_NAME     L"\\DosDevices\\poolscanner"

#define F_DbgPrint(...) \
                DbgPrint("[NAK] :: ");\
                DbgPrint(__VA_ARGS__);

#define POOL_HEADER_SIZE 0x10 // windows 10
#define CHUNK_SIZE 16         // 64 bit
// #define PAGE_SIZE 4096        // 4KB

PVOID SelfAllocKernelBuffer = nullptr;
PVOID ChunkAddr             = nullptr;
constexpr ULONG POOL_TAG    = 'NakD';

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    /* RegistryPath */
) {
    DbgPrint("[NAK] :: [+] Hello from Kernel\n");
    NTSTATUS returnStatus = STATUS_SUCCESS;
    UNICODE_STRING ntUnicodeString;
    UNICODE_STRING ntWin32NameString;
    PDEVICE_OBJECT  deviceObject = nullptr;
    constexpr SIZE_T POOL_BUFFER_SIZE = 0x100;    // a small chunk

    // PVOID kernelBuffer   = nullptr;

    DriverObject->DriverUnload = UnloadRoutine;

    RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);
    returnStatus = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        0,                              // We don't use a device extension
        &ntUnicodeString,               // Device name "\Device\poolscanner"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,        // Device characteristics
        FALSE,                          // Not an exclusive device
        &deviceObject);                 // Returned ptr to Device Object
    if (!NT_SUCCESS(returnStatus)) {
        DbgPrint(("[NAK] :: [-] Couldn't create the device object\n"));
        return returnStatus;
    }

    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
    returnStatus = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
    if (!NT_SUCCESS(returnStatus)) {
        DbgPrint("[NAK] :: [-] Couldn't create symbolic link for driver\n");
        IoDeleteDevice(deviceObject);
    }

    DbgPrint("[NAK] :: [+] GO GO GO !");

    // DbgPrint("[NAK] :: [+] Allocating a chunk in NonPagedPool...\n");
    SelfAllocKernelBuffer = ExAllocatePoolWithTag(NonPagedPool, POOL_BUFFER_SIZE, POOL_TAG);
    PVOID kernelBuffer = SelfAllocKernelBuffer;

    // if (!kernelBuffer) {
    //     DbgPrint("[NAK] :: [-] Unable to allocate Pool chunk\n");
    //     returnStatus = STATUS_NO_MEMORY;
    //     return returnStatus;
    // }

    // DbgPrint("[NAK] :: [+] Successfully allocated a chunk in NonPagedPool");
    ChunkAddr    = (PVOID)((long long int)kernelBuffer - POOL_HEADER_SIZE);
    POOL_HEADER p;    // use one POOL_HEADER to index
    toPoolHeader(&p, ChunkAddr);
    printChunkInfo(&p);

    // if (p.tag == 'NakD') {
    //     DbgPrint("[NAK] :: [+] tag == 'NakD'");
    // }
    // else if (p.tag == 'DkaN') {
    //     DbgPrint("[NAK] :: [+] tag == 'DkaN'");
    // }
    // else {
    //     DbgPrint("[NAK] :: [-] tag equals something else");
    // }

    // Try to find `MmNonPagedPoolStart` and `MmNonPagedPoolEnd`
    // https://web.archive.org/web/20061110120809/http://www.rootkit.com/newsread.php?newsid=153
    // KPCR->Version Data->Debugger Data List Entry->Flink
    ULONG64 nonPagedPoolStart = 0;
    ULONG64 nonPagedPoolEnd = 0;

    PDBGKD_GET_VERSION64 kdVersionBlock = nullptr;
    // PKDDEBUGGER_DATA64 dbgBlock = nullptr;

    kdVersionBlock = (PDBGKD_GET_VERSION64) FindKdVersionBlock();
    DbgPrint("[NAK] :: [ ] KdVersionBlock         : 0x%p\n", kdVersionBlock);

    if (kdVersionBlock == nullptr) {
        // The below can be summarized in these few lines of this README
        // https://github.com/nganhkhoa/pdb_for_nonpagedpool
        DbgPrint("[NAK] :: [ ] Cannot get KdVersionBlock try ntoskrnl+pdb\n");

        // https://www.unknowncheats.me/forum/general-programming-and-reversing/259921-finding-kernel-function-address-user-mode.html

        // seems like this shellcode is wrong for Windows insider Feb 2020 upgrade
        // shellcode: https://gist.github.com/Barakat/34e9924217ed81fd78c9c92d746ec9c6
        // shellcode is useless in Windows internal 2020
        // static const UCHAR getNtoskrnlBaseShellcode[] = {
        //     0x65, 0x48, 0x8B, 0x04, 0x25, 0x38, 0x00, 0x00, 0x00, 0xB9, 0x4D, 0x5A, 0x00, 0x00, 0x48, 0x8B,
        //     0x40, 0x04, 0x48, 0x25, 0x00, 0xF0, 0xFF, 0xFF, 0xEB, 0x06, 0x48, 0x2D, 0x00, 0x10, 0x00, 0x00,
        //     0x66, 0x39, 0x08, 0x75, 0xF5, 0xC3
        // };
        // const auto shellPool = ExAllocatePoolWithTag(NonPagedPoolExecute, sizeof(getNtoskrnlBaseShellcode), 'NakD');
        // RtlCopyMemory(shellPool, getNtoskrnlBaseShellcode, sizeof(getNtoskrnlBaseShellcode));
        // const auto get_ntoskrnl_base_address = reinterpret_cast<void *(*)()>(shellPool);
        // PVOID ntosbase = get_ntoskrnl_base_address();

        // IoGetCurrentProcess -> PEPROCESS -> ActiveProcessLinks -> FLINK until ImageFileName == "ntoskrnl.exe", get Peb->ImageBaseAddress
        // because this is driver, so it will return the System, as the system loads the driver
        // system is the first key in ProcessLinks so go back to get the PsActiveProcessHead
        // minus the offset from pdb to get the ntoskrnl

        PVOID eprocess = (PVOID)IoGetCurrentProcess();
        DbgPrint("[NAK] :: [ ] eprocess               : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + 0x5a8));
        PVOID processHead = (PVOID)(*(ULONG64*)((ULONG64)eprocess + 0x448 + 0x8));
        DbgPrint("[NAK] :: [ ] PsActiveProcessHead    : 0x%p\n", processHead);
        PVOID ntosbase = (PVOID)((ULONG64)processHead - 0xc1f970);
        DbgPrint("[NAK] :: [ ] ntoskrnl.exe           : 0x%p\n", ntosbase);

        // ExFreePoolWithTag(shellPool, 'NakD');

        // parsing PE file
        // https://stackoverflow.com/a/4316804
        // https://stackoverflow.com/a/47898643
        // https://github.com/Reetus/RazorRE/blob/42f441093bd85443b39fcff5d2a02069b524b114/Crypt/Misc.cpp#L63
        // if (ntosbase->e_magic == IMAGE_DOS_SIGNATURE) {
        //     DbgPrint("[NAK] :: [ ] DOS Signature (MZ) Matched \n");
        //     const PIMAGE_NT_HEADERS32 peHeader = (PIMAGE_NT_HEADERS32) ((unsigned char*)ntosbase+ntosbase->e_lfanew);
        //     if(peHeader->Signature == IMAGE_NT_SIGNATURE) {
        //         DbgPrint("[NAK] :: [ ] PE Signature (PE) Matched \n");
        //         // yeah we really got ntoskrnl.exe base
        //     }
        // }

        // In Windows 10, the global debug is MiState
        // dt (_MI_SYSTEM_NODE_NONPAGED_POOL*) (<nt!MiState> + <HARDWHARE_OFFSET> + <NODE_INFO_OFFSET>)
        // Sample output

        // +0x000 DynamicBitMapNonPagedPool : _MI_DYNAMIC_BITMAP
        // +0x048 CachedNonPagedPoolCount : 0
        // +0x050 NonPagedPoolSpinLock : 0
        // +0x058 CachedNonPagedPool : (null)
        // +0x060 NonPagedPoolFirstVa : 0xffffe580`00000000 Void
        // +0x068 NonPagedPoolLastVa : 0xfffff580`00000000 Void
        // +0x070 SystemNodeInformation : 0xffffe58f`9283b050 _MI_SYSTEM_NODE_INFORMATION

        PVOID miState = (PVOID)((ULONG64)ntosbase + 0xc4f200);
        PVOID systemNonPageInfo = (PVOID)*(ULONG64*)((ULONG64)miState + 0x1580 + 0x20);
        DbgPrint("[NAK] :: [ ] nt!MiState             : 0x%p\n", miState);
        DbgPrint("[NAK] :: [ ] &systemNonPageInfo     : 0x%p\n", systemNonPageInfo);
        DbgPrint("[NAK] :: [ ] &NonPagedPoolFirstVa   : 0x%p\n", (ULONG64*)((ULONG64)systemNonPageInfo + 0x60));
        DbgPrint("[NAK] :: [ ] &NonPagedPoolLastVa    : 0x%p\n", (ULONG64*)((ULONG64)systemNonPageInfo + 0x68));
        nonPagedPoolStart = *(ULONG64*)((ULONG64)systemNonPageInfo + 0x60);
        nonPagedPoolEnd = *(ULONG64*)((ULONG64)systemNonPageInfo + 0x68);
    } else {
        // x32 windows, KdVersionBlock get is usable
        DbgPrint("[NAK] :: [ ] Successfully get KdVersionBlock, not sure whether this works\n");
        // dbgBlock = (PKDDEBUGGER_DATA64) ((PLIST_ENTRY)kdVersionBlock->DebuggerDataList)->Flink;
    }

    DbgPrint("[NAK] :: [ ] nonPagedPoolStart      : 0x%llx\n", nonPagedPoolStart);
    DbgPrint("[NAK] :: [ ] nonPagedPoolEnd        : 0x%llx\n", nonPagedPoolEnd);

    // now wait for user call to scan
    // current debug mode, scan now
    // scan(&p, nonPagedPoolStart, nonPagedPoolEnd);

    return returnStatus;
}

VOID
UnloadRoutine(_In_ PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    if (SelfAllocKernelBuffer != nullptr) {
        ExFreePoolWithTag(SelfAllocKernelBuffer, POOL_TAG);
    }

    RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != nullptr) {
        IoDeleteDevice(deviceObject);
    }

    DbgPrint("[NAK] :: [+] Goodbye from Kernel\n");
}

PPOOL_HEADER
toPoolHeader(PPOOL_HEADER p, PVOID chunkAddr) {
    p->addr = chunkAddr;
    __try {
        p->prevBlockSize = *(USHORT*)((long long int) chunkAddr + 0x0) & 0xff;
        p->poolIndex     = *(USHORT*)((long long int) chunkAddr + 0x0) >> 8;
        p->blockSize     = *(USHORT*)((long long int) chunkAddr + 0x2) & 0xff;
        p->poolType      = *(USHORT*)((long long int) chunkAddr + 0x2) >> 8;
        p->tag           = *(ULONG*)((long long int) chunkAddr + 0x4);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        p->prevBlockSize = 0;
        p->poolIndex     = 0;
        p->poolType      = 0;
        p->tag           = 0;
    }
    return p;
}

PPOOL_HEADER
tryNextChunk(PPOOL_HEADER p) {
    return toPoolHeader(p, (PVOID)((long long int)p->addr + CHUNK_SIZE));
}

bool
validTag(PPOOL_HEADER p) {
    // I know the compiler will optimize for me, so meeh :)
    __try {
        const char a = (char)(p->tag & 0xff);
        const char b = (char)((p->tag & 0xff00) >> 8);
        const char c = (char)((p->tag & 0xff0000) >> 16);
        const char d = (char)(p->tag >> 24);

        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag
        // > Each ASCII character in the tag must be a value in the range 0x20 (space) to 0x7E (tilde)
        if (!(a >= 0x20 && a <= 0x7e) ||
            !(b >= 0x20 && b <= 0x7e) ||
            !(c >= 0x20 && c <= 0x7e) ||
            !(d >= 0x20 && d <= 0x7e))
        return false;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool
checkValidPool(PPOOL_HEADER /* p */) {
    // https://subs.emis.de/LNI/Proceedings/Proceedings97/GI-Proceedings-97-9.pdf
    // long long int offsetInPage = (long long int)p->addr % PAGE_SIZE;   // OffsetInPage = addr % pagesize
    // (offsetInPage % CHUNK_SIZE == 0) &&       // rule 1
    // (p->blockSize > 0) &&             // rule 2
    // (p->blockSize * CHUNK_SIZE + offsetInPage == PAGE_SIZE) &&  // rule 3
    // (p->prevBlockSize * CHUNK_SIZE <= offsetInPage) // rule 5
    return true;
}

VOID
printChunkInfo(PPOOL_HEADER p) {
    DbgPrint("[NAK] :: [+] ==== PoolStart 0x%p ====\n", p->addr);
    DbgPrint("[NAK] :: [|] \tPreviousSize  : 0x%x\n", p->prevBlockSize);
    DbgPrint("[NAK] :: [|] \tPoolIndex     : 0x%x\n", p->poolIndex);
    DbgPrint("[NAK] :: [|] \tBlockSize     : 0x%x\n", p->blockSize * CHUNK_SIZE);
    DbgPrint("[NAK] :: [|] \tPoolType      : 0x%x\n", p->poolType);
    DbgPrint("[NAK] :: [|] \tPoolTag       : 0x%lx [%c%c%c%c]\n", p->tag, p->tag, p->tag >> 8, p->tag >> 16, p->tag >> 24);
    DbgPrint("[NAK] :: [+] ==== PoolEnd   0x%p ====\n", p->addr);
}

VOID
scan(PPOOL_HEADER p, ULONG64 /* nonPagedPoolStart */, ULONG64 /* nonPagedPoolEnd */) {
    DbgPrint("[NAK] :: [+] Scanning\n");

    // scan by moving up and down 16 bytes?
    // Or by moving by BlockSize and PreviousBlockSize?

    // Also, when to stop?

    // int i = 0;
    for (p = tryNextChunk(p);
         (long long int)p->addr < 0xFFFFFFFFFFFFFFFF;
         p = tryNextChunk(p))
    {
        // if (i++ >= 100000) break;
        if (p->tag == 0) continue;
        if (!validTag(p)) continue;

        printChunkInfo(p);

        // if (p->poolIndex == 0) {
        //     DbgPrint("[NAK] :: [+] Seems like we hit the first pool chunk");
        //     break;
        // }
        if (p->tag != 'Proc' && p->tag != 'corP')
            continue;
        DbgPrint("[NAK] :: [+] HEY EPROCESS POOL CHUNK");
		break;
    }

    DbgPrint("[NAK] :: [+] Finish scanning");

    // go up
    // for (;
    //     KernelBuffer = (PVOID)((long long int)chunk_addr + blockSize);
    //     ) {
    // }

    // go down
    // for (;
    //     KernelBuffer = (PVOID)((long long int)chunk_addr - prevBlockSize);
    //     ) {
    // }
}
