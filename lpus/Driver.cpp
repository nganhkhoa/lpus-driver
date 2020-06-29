#include <ntddk.h>
#include <wdf.h>
#include <ntdef.h>
#include <ntstrsafe.h>

#include "Driver.h"
#include "sioctl.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD UnloadRoutine;
extern "C" DRIVER_DISPATCH DriverCreateClose;
extern "C" DRIVER_DISPATCH DriverControl;
// extern "C" PDBGKD_GET_VERSION64 FindKdVersionBlock(void);

#define NT_DEVICE_NAME      L"\\Device\\poolscanner"
#define DOS_DEVICE_NAME     L"\\DosDevices\\poolscanner"

// #define POOL_HEADER_SIZE 0x10 // windows 10
#define CHUNK_SIZE 16         // 64 bit
// #define PAGE_SIZE 4096        // 4KB

// some globals
PVOID ntosbase;
PVOID systemEprocess;
PVOID processHead;

// offset to get from PDB file
ULONG64 eprocessNameOffset = 0;
ULONG64 eprocessLinkOffset = 0;
ULONG64 listBLinkOffset = 0;
ULONG64 processHeadOffset = 0;
ULONG64 miStateOffset = 0;
ULONG64 hardwareOffset = 0;
ULONG64 systemNodeOffset = 0;
ULONG64 firstVaOffset = 0;
ULONG64 lastVaOffset = 0;
ULONG64 largePageTableOffset = 0;
ULONG64 largePageSizeOffset = 0;
ULONG64 poolChunkSize = 0;

NTSTATUS
DriverCreateClose(PDEVICE_OBJECT /* DriverObject */, PIRP Irp) {
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DriverControl(PDEVICE_OBJECT /* DriverObject */, PIRP Irp) {
    PIO_STACK_LOCATION irpSp;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    // ULONG inBufLength;
    // ULONG outBufLength;
    ULONG controlCode;
    // PCHAR inBuf;
    // PCHAR outBuf;
    PINPUT_DATA inputData = nullptr;
    POUTPUT_DATA outputData = nullptr;
    POFFSET_VALUE offsetValues = nullptr;
    PDEREF_ADDR derefAddr = nullptr;
    PSCAN_RANGE scanRange = nullptr;
    PHIDE_PROCESS processHide = nullptr;

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    /*
     *  struct {
     *    ULONG                   OutputBufferLength;
     *    ULONG POINTER_ALIGNMENT InputBufferLength;
     *    ULONG POINTER_ALIGNMENT IoControlCode;
     *    PVOID                   Type3InputBuffer;
     *  } DeviceIoControl;
     **/
    controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
        case IOCTL_SETUP_OFFSETS:
            DbgPrint("[NAK] :: [ ] Setup offsets\n");
            inputData = (PINPUT_DATA)(Irp->AssociatedIrp.SystemBuffer);
            offsetValues = &(inputData->offsetValues);
            eprocessNameOffset   = offsetValues->eprocessNameOffset;
            eprocessLinkOffset   = offsetValues->eprocessLinkOffset;
            listBLinkOffset      = offsetValues->listBLinkOffset;
            processHeadOffset    = offsetValues->processHeadOffset;
            miStateOffset        = offsetValues->miStateOffset;
            hardwareOffset       = offsetValues->hardwareOffset;
            systemNodeOffset     = offsetValues->systemNodeOffset;
            firstVaOffset        = offsetValues->firstVaOffset;
            lastVaOffset         = offsetValues->lastVaOffset;
            largePageTableOffset = offsetValues->largePageTableOffset;
            largePageSizeOffset  = offsetValues->largePageSizeOffset;
            poolChunkSize        = offsetValues->poolChunkSize;
            setup();
            break;
        case GET_KERNEL_BASE:
            DbgPrint("[NAK] :: [ ] Get kernel base\n");
            outputData = (POUTPUT_DATA)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
            // TODO: check for safety outputData address null
            outputData->ulong64Value = (ULONG64)ntosbase;
            Irp->IoStatus.Information = sizeof(ULONG64);
            break;
        case SCAN_PS_ACTIVE_HEAD:
            DbgPrint("[NAK] :: [ ] Scan ps active head\n");
            scan_ps_active_head();
            break;
        // case SCAN_POOL:
        //     DbgPrint("[NAK] :: [ ] Scan pool\n");
        //     inputData = (PINPUT_DATA)(Irp->AssociatedIrp.SystemBuffer);
        //     scanRange = &(inputData->scanRange);
        //     DbgPrint("[NAK] :: Range: %llx - %llx", scanRange->start, scanRange->end);
        //     scanNormalPool(scanRange->start, scanRange->end);
        //     break;
        case SCAN_POOL_REMOTE:
            inputData = (PINPUT_DATA)(Irp->AssociatedIrp.SystemBuffer);
            outputData = (POUTPUT_DATA)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
            scanRange = &(inputData->scanRange);
            DbgPrint("[NAK] :: Range: %llx - %llx", scanRange->start, scanRange->end);
            (outputData->poolChunk).addr = (ULONG64)scanRemote(scanRange->start, scanRange->end, scanRange->tag);
            DbgPrint("[NAK] :: Found: %llx", (outputData->poolChunk).addr);
            break;
        case DEREFERENCE_ADDRESS:
            // DbgPrint("[NAK] :: [ ] Deref address\n");
            inputData = (PINPUT_DATA)(Irp->AssociatedIrp.SystemBuffer);
            derefAddr = &(inputData->derefAddr);
            outputData = (POUTPUT_DATA)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
            // DbgPrint("[NAK] :: [ ] Deref %llu bytes from %llx\n", derefAddr->size, derefAddr->addr);
            RtlCopyBytes((PVOID)outputData, (PVOID)derefAddr->addr, (SIZE_T)derefAddr->size);
            break;
        case HIDE_PROCESS_BY_NAME:
            DbgPrint("[NAK] :: [ ] Hide process\n");
            inputData = (PINPUT_DATA)(Irp->AssociatedIrp.SystemBuffer);
            processHide = &(inputData->processHide);
            DbgPrint("[NAK] :: [ ] Hide process name: [%15s]; size: %llu\n", processHide->name, processHide->size);
            hideProcess(processHide->name, processHide->size);
            break;
        default:
            break;
    }

    Irp->IoStatus.Status = ntStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return ntStatus;
}

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

    PAGED_CODE();

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
        DbgPrint(("[NAK] :: [-] Could not create the device object\n"));
        return returnStatus;
    }

    DriverObject->DriverUnload = UnloadRoutine;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;

    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
    returnStatus = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
    if (!NT_SUCCESS(returnStatus)) {
        DbgPrint("[NAK] :: [-] Could not create symbolic link for driver\n");
        IoDeleteDevice(deviceObject);
    }

    systemEprocess = IoGetCurrentProcess();

    DbgPrint("[NAK] :: [+] Setup completed, waiting for command on DeviceIo\n");

    return returnStatus;
}

VOID
setup() {
    PAGED_CODE();
    // TODO: Exception?????
    PVOID eprocess = systemEprocess;
    DbgPrint("[NAK] :: [ ] System eprocess        : 0x%p, [%15s]\n",
             eprocess, (char*)((ULONG64)eprocess + eprocessNameOffset));
    processHead = (PVOID)(*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset + listBLinkOffset));
    DbgPrint("[NAK] :: [ ] PsActiveProcessHead    : 0x%p\n", processHead);
    ntosbase = (PVOID)((ULONG64)processHead - processHeadOffset);
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
}

VOID
scan_ps_active_head() {
    PVOID eprocess = (PVOID)((ULONG64)processHead - eprocessLinkOffset);
    DbgPrint("[NAK] :: [ ] Scan the PsActiveProcessHead linked-list\n");
    while (*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset) != (ULONG64)processHead) {
        eprocess = (PVOID)(*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset) - eprocessLinkOffset);
        DbgPrint("[NAK] :: [ ] eprocess               : 0x%p, [%15s]\n",
                 eprocess, (char*)((ULONG64)eprocess + eprocessNameOffset));
    }
}

VOID
hideProcess(CHAR* name, ULONG64 size) {
    PVOID eprocess = (PVOID)((ULONG64)processHead - eprocessLinkOffset);
    while (*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset) != (ULONG64)processHead) {
        PVOID next_eprocess = (PVOID)(*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset) - eprocessLinkOffset);
        char* processName = (char*)((ULONG64)eprocess + eprocessNameOffset);
        int i = 0;
        for (; i < size; i++) {
            if (processName[i] != name[i]) break;
        }
        if (i != size) {
            eprocess = next_eprocess;
            continue;
        }
        // found process with name
        PVOID next_eprocess_link = (PVOID)(*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset));
        PVOID prev_eprocess_link = (PVOID)(*(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset + listBLinkOffset));

        // set current to 0
        // *(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset) = 0;
        // *(ULONG64*)((ULONG64)eprocess + eprocessLinkOffset + listBLinkOffset) = 0;

        *(ULONG64*)((ULONG64)next_eprocess_link + listBLinkOffset) = (ULONG64)prev_eprocess_link;
        *(ULONG64*)prev_eprocess_link = (ULONG64)next_eprocess_link;

        eprocess = next_eprocess;
    }
}

VOID
UnloadRoutine(_In_ PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;
    PAGED_CODE();

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

VOID
printChunkInfo(PPOOL_HEADER p) {
    DbgPrint("[NAK] :: [+] ==== PoolStart 0x%p ====\n", p->addr);
    DbgPrint("[NAK] :: [|] \tPreviousSize  : 0x%x\n", p->prevBlockSize);
    DbgPrint("[NAK] :: [|] \tPoolIndex     : 0x%x\n", p->poolIndex);
    DbgPrint("[NAK] :: [|] \tBlockSize     : 0x%x\n", p->blockSize * CHUNK_SIZE);
    DbgPrint("[NAK] :: [|] \tPoolType      : 0x%x\n", p->poolType);
    DbgPrint("[NAK] :: [|] \tPoolTag       : 0x%x\n", p->tag);
    DbgPrint("[NAK] :: [|] \tPoolTag       : 0x%lx [%4s]\n", p->tag, p->tag);
    DbgPrint("[NAK] :: [+] ==== PoolEnd   0x%p ====\n", p->addr);
}

VOID
scanLargePool(PVOID /* largePageTableArray */, ULONG64 /* largePageTableSize */) {
    DbgPrint("[NAK] :: [-] Scan large pool not supported yet");
}

PVOID
scanRemote(ULONG64 startAddress, ULONG64 endAddress, ULONG tag) {
    POOL_HEADER p;
    PVOID currentAddr = (PVOID)startAddress;
    while (true) {
        if ((ULONG64)currentAddr >= endAddress)
            break;

        if (!MmIsAddressValid(currentAddr)) {
            currentAddr = (PVOID)((ULONG64)currentAddr + PAGE_SIZE);
            continue;
        }
        if (!MmIsAddressValid((PVOID)((ULONG64)currentAddr + 0x10))) {
            // to be correct, this should be next page,
            // but I put this to make it works first
            // >> currentAddr is at the end of a page,
            //    currentAddr+0x10 will be some section bad page
            //    which if we parse the header, will be blue screen
            currentAddr = (PVOID)((ULONG64)currentAddr + 0x4);
            continue;
        }
        currentAddr = (PVOID)((ULONG64)currentAddr + 0x4);

        toPoolHeader(&p, (PVOID)currentAddr);
        if (p.poolType != 2) continue;
        if (!validTag(&p)) continue;
        if (p.tag != tag)
            continue;

        return p.addr;
    }
    return (PVOID)endAddress;
}
