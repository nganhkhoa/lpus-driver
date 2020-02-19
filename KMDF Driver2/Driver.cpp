#include <ntddk.h>
#include <wdf.h>
#include <ntdef.h>

#include "sioctl.h"
#include "Driver.h"
// #include "peformat.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD UnloadRoutine;
// extern "C" PDBGKD_GET_VERSION64 FindKdVersionBlock(void);

#define NT_DEVICE_NAME      L"\\Device\\poolscanner"
#define DOS_DEVICE_NAME     L"\\DosDevices\\poolscanner"

#define F_DbgPrint(...) \
                DbgPrint("[NAK] :: ");\
                DbgPrint(__VA_ARGS__);

#define POOL_HEADER_SIZE 0x10 // windows 10
#define CHUNK_SIZE 16         // 64 bit
// #define PAGE_SIZE 4096        // 4KB

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    /* RegistryPath */
) {
    DbgPrint("[NAK] :: [ ] Hello from Kernel, setup a few things\n");

    NTSTATUS returnStatus = STATUS_SUCCESS;
    UNICODE_STRING ntUnicodeString;
    UNICODE_STRING ntWin32NameString;
    PDEVICE_OBJECT  deviceObject = nullptr;

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

    DbgPrint("[NAK] :: [+] Setup completed, GO GO GO !!!!\n");

    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
    returnStatus = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
    if (!NT_SUCCESS(returnStatus)) {
        DbgPrint("[NAK] :: [-] Couldn't create symbolic link for driver\n");
        IoDeleteDevice(deviceObject);
    }

    OSVERSIONINFOW windowsVersionInfo;
    RtlGetVersion(&windowsVersionInfo);
    DbgPrint("[NAK] :: [ ] Windows version        : %lu.%lu.%lu\n",
            windowsVersionInfo.dwMajorVersion, windowsVersionInfo.dwMinorVersion, windowsVersionInfo.dwBuildNumber);

    if (windowsVersionInfo.dwMajorVersion != 10) {
        DbgPrint("[NAK] :: [-] Windows version outside 10 is not supported yet!");
        return returnStatus;
    }

    // https://en.wikipedia.org/wiki/Windows_10_version_history
    VERSION_BY_POOL windowsVersionByPool = WINDOWS_NOT_SUPPORTED;
    // TODO: automatically get from parsed PDB file
    ULONG64 eprocessNameOffset = 0;
    ULONG64 eprocessLinkOffset = 0;
    ULONG64 listBLinkOffset = 0;
    ULONG64 processHeadOffset = 0;
    ULONG64 miStateOffset = 0;
    ULONG64 hardwareOffset = 0;
    ULONG64 systemNodeOffset = 0;
    ULONG64 firstVaOffset = 0;
    ULONG64 lastVaOffset = 0;

    // setup offset
    if (windowsVersionInfo.dwBuildNumber == 17134 || windowsVersionInfo.dwBuildNumber == 17763) {
        DbgPrint("[NAK] :: [ ] Detected windows       : 2018\n");
        windowsVersionByPool = WINDOWS_2018;
    }
    else if (windowsVersionInfo.dwBuildNumber == 18362 || windowsVersionInfo.dwBuildNumber == 18363) {
        DbgPrint("[NAK] :: [ ] Detected windows       : 2019\n");
        windowsVersionByPool = WINDOWS_2019;
    }
    else if (windowsVersionInfo.dwBuildNumber == 19041) {
        DbgPrint("[NAK] :: [ ] Detected windows       : 2020\n");
        windowsVersionByPool = WINDOWS_2020;
    }
    else if (windowsVersionInfo.dwBuildNumber >= 19536) {
        DbgPrint("[NAK] :: [ ] Detected windows       : 2020 Fast Ring\n");
        windowsVersionByPool = WINDOWS_2020_FASTRING;
        eprocessNameOffset = 0x5a8;
        eprocessLinkOffset = 0x448;
        listBLinkOffset = 0x8;
        processHeadOffset = 0xc1f970;
        miStateOffset = 0xc4f200;
        hardwareOffset = 0x1580;
        systemNodeOffset = 0x20;
        firstVaOffset = 0x60;
        lastVaOffset = 0x68;
    }

    if (windowsVersionByPool == WINDOWS_NOT_SUPPORTED) {
        DbgPrint("[NAK] :: [-] Windows 10 with this build number is not supported yet!");
        return returnStatus;
    }

    /**
     * Try to find `MmNonPagedPoolStart` and `MmNonPagedPoolEnd`
     *
     * https://web.archive.org/web/20061110120809/http://www.rootkit.com/newsread.php?newsid=153
     * KPCR->KdVersionBlock->Debugger Data List Entry->Flink
     *
     * This technique is old and cannot be used in Windows 10, Windows 7/8 may fail too,
     * After research, the result is summary into this README
     * https://github.com/nganhkhoa/pdb_for_nonpagedpool
     *
     * Basically, find ntoskrnl.exe module address (kernel base) in memory and use offsets parsed from PDB file,
     * Finding the kernel base by shellcode is not usable in Windows 2020 Insider Preview,
     * I use IoGetCurrentProcess and traverse the ActiveProcessLinks linked list,
     * Luckily, the process returned by IoGetCurrentProcess is System (the first process), so the BLINK is nt!PsActiveProcessHead
     * With offset of nt!PsActiveProcessHead parsed from PDB file, we can get the kernel base by subtracting.
     *
     * Then offset to find NonPagedPool{First,Last}Va
     *
     * In Windows 10, we must use nt!MiState and look into Hardware->NodeInfo,
     * there is a slightly different layout/offset to each version of Windows by year?
     * 2015 -> 2016 -> 2018 -> 2019 -> 2020 all have a slight (or big) different
     *
    **/

    // TODO: Exception?????
    PVOID eprocess = (PVOID)IoGetCurrentProcess();
    DbgPrint("[NAK] :: [ ] eprocess               : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + eprocessNameOffset));
    PVOID processHead = (PVOID)(*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset + listBLinkOffset));
    DbgPrint("[NAK] :: [ ] PsActiveProcessHead    : 0x%p\n", processHead);
    PVOID ntosbase = (PVOID)((ULONG64)processHead - processHeadOffset);
    DbgPrint("[NAK] :: [ ] ntoskrnl.exe           : 0x%p\n", ntosbase);

    // TODO: Check if ntosbase is a PE, and the name is ntoskrnl.exe
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

    /**
     * In Windows 10 Insider Preview Feb 2020, the global debug is MiState, try this in windbg and see
     * `x nt!MiState` to get address of MiState
     * `dt _MI_SYSTEM_INFORMATION` to get offset to Hardware
     * `dt _MI_HARDWARE_STATE` to get offset to SystemNodeNonPagedPool
     * with those offset, use the following command to list the NonPagedPool{First,Last}Va
     * `dt (_MI_SYSTEM_NODE_NONPAGED_POOL*) (<nt!MiState> + <HARDWHARE_OFFSET> + <NODE_INFO_OFFSET>)`
     * Sample output
     *
     * +0x000 DynamicBitMapNonPagedPool : _MI_DYNAMIC_BITMAP
     * +0x048 CachedNonPagedPoolCount : 0
     * +0x050 NonPagedPoolSpinLock : 0
     * +0x058 CachedNonPagedPool : (null)
     * +0x060 NonPagedPoolFirstVa : 0xffffe580`00000000 Void
     * +0x068 NonPagedPoolLastVa : 0xfffff580`00000000 Void
     * +0x070 SystemNodeInformation : 0xffffe58f`9283b050 _MI_SYSTEM_NODE_INFORMATION
     *
     **/

    PVOID miState = (PVOID)((ULONG64)ntosbase + miStateOffset);
    DbgPrint("[NAK] :: [ ] nt!MiState             : 0x%p\n", miState);
    PVOID systemNonPageInfo = nullptr;

    ULONG64 nonPagedPoolStart = 0;
    ULONG64 nonPagedPoolEnd = 0;

    // use defined formula by windows build number to get those two values
    switch (windowsVersionByPool) {
        case WINDOWS_2020_FASTRING:
            systemNonPageInfo = (PVOID)*(ULONG64*)((ULONG64)miState + hardwareOffset + systemNodeOffset);
            DbgPrint("[NAK] :: [ ] &systemNonPageInfo     : 0x%p\n", systemNonPageInfo);
            DbgPrint("[NAK] :: [ ] &NonPagedPoolFirstVa   : 0x%p\n", (ULONG64*)((ULONG64)systemNonPageInfo + firstVaOffset));
            DbgPrint("[NAK] :: [ ] &NonPagedPoolLastVa    : 0x%p\n", (ULONG64*)((ULONG64)systemNonPageInfo + lastVaOffset));
            nonPagedPoolStart = *(ULONG64*)((ULONG64)systemNonPageInfo + firstVaOffset);
            nonPagedPoolEnd = *(ULONG64*)((ULONG64)systemNonPageInfo + lastVaOffset);
            break;
        default:
            break;
    }

    DbgPrint("[NAK] :: [+] nonPagedPoolStart      : 0x%llx\n", nonPagedPoolStart);
    DbgPrint("[NAK] :: [+] nonPagedPoolEnd        : 0x%llx\n", nonPagedPoolEnd);

    scan(nonPagedPoolStart, nonPagedPoolEnd);

    return returnStatus;
}

VOID
UnloadRoutine(_In_ PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != nullptr) {
        IoDeleteDevice(deviceObject);
    }

    DbgPrint("[NAK] :: [+] Goodbye from Kernel\n");
}

VOID
toPoolHeader(PPOOL_HEADER p, PVOID chunkAddr) {
    p->addr          = chunkAddr;
    p->prevBlockSize = *(USHORT*)((ULONG64) chunkAddr + 0x0) & 0xff;
    p->poolIndex     = *(USHORT*)((ULONG64) chunkAddr + 0x0) >> 8;
    p->blockSize     = *(USHORT*)((ULONG64) chunkAddr + 0x2) & 0xff;
    p->poolType      = *(USHORT*)((ULONG64) chunkAddr + 0x2) >> 8;
    p->tag           = *(ULONG*)((ULONG64) chunkAddr + 0x4);
}

VOID
tryNextChunk(PPOOL_HEADER p) {
    toPoolHeader(p, (PVOID)((ULONG64)p->addr + CHUNK_SIZE));
}

bool
validTag(PPOOL_HEADER p) {
    // I know the compiler will optimize for me, so meeh :)
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
scan(ULONG64 nonPagedPoolStart, ULONG64 nonPagedPoolEnd) {
    DbgPrint("[NAK] :: [+] Scanning\n");

    /*
     * The name nonpaged pool is quite misunderstanding,
     * the correct definition of a nonpaged pool is a pool which remains on the nonpaged region
     * nonpaged region is a range of address inside the kernel virtual address that has
     * a correspoding page in the physical memory (RAM)
     *
     * Which is, if there is a **valid** page in nonpaged pool, there is a correspoding page in RAM
     * The OS will allocate a page in this nonpaged region with a page in RAM when a new page
     * is requested to be nonpaged and there is no space left in current allocated nonpaged region.
     *
     * That is, if the address lies in the nonpaged region but is not allocated yet to have a
     * backed paged on RAM, then a bug check will occur. The name is `PAGE FAULT IN NONPAGED AREA`
     *
     **/

    POOL_HEADER p;
    const ULONG64 headerSize = 0x10;
    PVOID currentAddr = (PVOID)(nonPagedPoolStart);
    while (true) {
        if ((ULONG64)currentAddr >= nonPagedPoolEnd)
                break;

        /*
         * BOOLEAN MmIsAddressValid(PVOID)
         *
         * Warning  We do not recommend using this function.
         *
         * If no page fault would occur from reading or writing at the given virtual address,
         * MmIsAddressValid returns TRUE.
         *
         * Even if MmIsAddressValid returns TRUE, accessing the address can cause page faults
         * unless the memory has been locked down or the address **is a valid nonpaged pool address**.
         *
         * Well, we got a nonpaged pool address, so it is good
         *
         **/
        if (!MmIsAddressValid(currentAddr)) {
            // Because a chunk pool reside on a page, so we check on page alignment
            currentAddr = (PVOID)((ULONG64)currentAddr + PAGE_SIZE);
            continue;
        }

        // TODO: perform scan in one page, use BlockSize/PreviousBlockSize
        toPoolHeader(&p, (PVOID)currentAddr);
        currentAddr = (PVOID)((ULONG64)currentAddr + headerSize);

        if (p.tag == 0) continue;
        if (!validTag(&p)) continue;

        if (p.tag != 'Proc' && p.tag != 'corP')
            continue;

        // TODO: Parse data as _EPROCESS
        // The first Proc found seems to be the EPROCESS from IoGetCurrentProcess
        // But it was offset 0x40
        printChunkInfo(&p);
        DbgPrint("[NAK] :: [+] HEY EPROCESS POOL CHUNK");
        break;
    }

    DbgPrint("[NAK] :: [+] Finish scanning");
}
