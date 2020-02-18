#include <wdm.h>

__declspec(dllexport)
__declspec(noinline)
void*
GetNtoskrnlBaseAddress()
{
  //
  // From Windows Internals part 1, chapter 2:
  //
  //   "The kernel uses a data structure called the processor control region, or KPCR, to store
  //   processor-specific data. The KPCR contains basic information such as the processor's interrupt
  //   dispatch table(IDT), task - state segment(TSS), and global descriptor table(GDT). It also includes the
  //   interrupt controller state, which it shares with other modules, such as the ACPI driver and the HAL. To
  //   provide easy access to the KPCR, the kernel stores a pointer to it in the fs register on 32-bit Windows
  //   and in the gs register on an x64 Windows system."
  //
  //
  //  Let's view the address of KPCR of the current processor:
  //
  //     1: kd> dg gs
  //       P Si Gr Pr Lo
  //       Sel        Base              Limit          Type    l ze an es ng Flags
  //       ---- ---------------- - ---------------- - ---------- - -- -- -- -- --------
  //       002B ffffd001`1972e000 00000000`ffffffff Data RW Ac 3 Bg Pg P  Nl 00000cf3
  //
  // We only care about one field in KPCR which is IdtBase (it has been always at the offset 0x38):
  //
  //     1: kd> dt nt!_KPCR 0xffffd001`1972e000
  //       + 0x000 NtTib            : _NT_TIB
  //       + 0x000 GdtBase : 0xffffd001`1973b8c0 _KGDTENTRY64
  //       + 0x008 TssBase          : 0xffffd001`19734b40 _KTSS64
  //       + 0x010 UserRsp          : 0x000000c0`87cffc18
  //       + 0x018 Self             : 0xffffd001`1972e000 _KPCR
  //       + 0x020 CurrentPrcb      : 0xffffd001`1972e180 _KPRCB
  //       + 0x028 LockArray        : 0xffffd001`1972e7f0 _KSPIN_LOCK_QUEUE
  //       + 0x030 Used_Self        : 0x000000c0`86875000 Void
  //       + 0x038 IdtBase          : 0xffffd001`1973b930 _KIDTENTRY64      <- pointer to the IDT array
  //       ...
  //
  // The field is a pointer to an array of interrupt service routines in the following format:
  //
  //     1: kd> dt nt!_KIDTENTRY64
  //       +0x000 OffsetLow        : Uint2B
  //       +0x002 Selector         : Uint2B
  //       +0x004 IstIndex         : Pos 0, 3 Bits   --+
  //       +0x004 Reserved0        : Pos 3, 5 Bits     |
  //       +0x004 Type             : Pos 8, 5 Bits     |
  //       +0x004 Dpl              : Pos 13, 2 Bits    |-> the interrupt service routine as a bitfield
  //       +0x004 Present          : Pos 15, 1 Bit     |
  //       +0x006 OffsetMiddle     : Uint2B            |
  //       +0x008 OffsetHigh       : Uint4B          --+
  //       +0x00c Reserved1        : Uint4B
  //       +0x000 Alignment        : Uint8B
  //
  //
  // These interrupt service routines are functions defined within the address space of ntoskrnl.exe. We will
  // use this fact for searching for the base address of ntoskrnl.exe.
  //

  // Ensure that the structure is aligned on 1 byte boundary.
#pragma pack(push, 1)
  typedef struct
  {
    UCHAR Padding[4];
    PVOID InterruptServiceRoutine;
  } IDT_ENTRY;
#pragma pack(pop)

  // Find the address of IdtBase using gs register.
  const auto idt_base = reinterpret_cast<IDT_ENTRY *>(__readgsqword(0x38));

  // Find the address of the first (or any) interrupt service routine.
  const auto first_isr_address = idt_base[0].InterruptServiceRoutine;

  // Align the address on page boundary.
  auto page_within_ntoskrnl = reinterpret_cast<uintptr_t>(first_isr_address) & ~static_cast<uintptr_t>(0xfff);

  // Traverse pages backward until we find the PE signature (MZ) of ntoskrnl.exe in the beginning of some page.
  while (*reinterpret_cast<const USHORT *>(page_within_ntoskrnl) != 0x5a4d)
  {
    page_within_ntoskrnl -= 0x1000;
  }

  // Now we have the base address of ntoskrnl.exe
  return reinterpret_cast<void*>(page_within_ntoskrnl);
}

VOID
DriverUnload(PDRIVER_OBJECT driver_object)
{
  UNREFERENCED_PARAMETER(driver_object);
}

EXTERN_C
NTSTATUS
DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
  UNREFERENCED_PARAMETER(registry_path);

  driver_object->DriverUnload = DriverUnload;

  // 0 : 65 48 8b 04 25 38 00    mov    rax, QWORD PTR gs : 0x38
  // 7 : 00 00
  // 9 : b9 4d 5a 00 00          mov    ecx, 0x5a4d
  // e : 48 8b 40 04             mov    rax, QWORD PTR[rax + 0x4]
  // 12: 48 25 00 f0 ff ff       and    rax, 0xfffffffffffff000
  // 18: eb 06                   jmp    0x20
  // 1a: 48 2d 00 10 00 00       sub    rax, 0x1000
  // 20: 66 39 08                cmp    WORD PTR[rax], cx
  // 23: 75 f5                   jne    0x1a
  // 25: c3                      ret

  static const UCHAR shellcode[] = {
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x38, 0x00, 0x00, 0x00, 0xB9, 0x4D, 0x5A, 0x00, 0x00, 0x48, 0x8B,
    0x40, 0x04, 0x48, 0x25, 0x00, 0xF0, 0xFF, 0xFF, 0xEB, 0x06, 0x48, 0x2D, 0x00, 0x10, 0x00, 0x00,
    0x66, 0x39, 0x08, 0x75, 0xF5, 0xC3
  };

  const auto ntoskrnl_base_address = GetNtoskrnlBaseAddress();

  const auto pool = ExAllocatePoolWithTag(NonPagedPoolExecute, sizeof(shellcode), 'KMSL');
  if (pool != nullptr)
  {
    RtlCopyMemory(pool, shellcode, sizeof(shellcode));
    const auto get_ntoskrnl_base_address = reinterpret_cast<void *(*)()>(pool);
    ASSERT(get_ntoskrnl_base_address() == ntoskrnl_base_address);
    ExFreePoolWithTag(pool, 'KMSL');
  }

  return STATUS_SUCCESS;
}

