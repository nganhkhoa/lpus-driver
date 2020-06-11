Scanning the memory is not working well, we go with Pool tag quick scanning

[address in kernel space](https://www.codemachine.com/article_x64kvas.html)

find `MmNonPagedPoolStart` and `MmNonPagedPoolEnd` values in kernel variable.

These two variables located inside `KdDebuggerDataBlock` of type `_KDDEBUGGER_DATA64`. `KdDebuggerDataBlock` can be found somewhere in `KdVersionBlock`. `KdVersionBlock` is a member of `KPCR`. `KPCR` pointer can be get through `gs:[0x0]`

> Unfortunately this method stopped working in recent versions of Windows. Recently the KdVersionBlock member is always 0 and does not link to the kernel debugger block.

[kdbg.c](https://raw.githubusercontent.com/libvmi/libvmi/master/libvmi/os/windows/kdbg.c)

[KPCR at gs:[0x0]](https://sizzop.github.io/2016/07/07/kernel-hacking-with-hevd-part-3.html)

[finding kdbg](http://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)

[finding kernel variables](http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html)

[get kernel shellcode](https://github.com/FuzzySecurity/PSKernel-Primitives/blob/master/Get-KernelShellCode.ps1)

[www.rootkit.com artifacts](https://github.com/fdiskyou/www.rootkit.com)
 - GetVarXP.pdf

[ghidra on fs/gs and kdbg](https://github.com/NationalSecurityAgency/ghidra/issues/1339)

[big ram kdbg](https://laserkittens.com/big-ram-kernel-debugger-data-block/)

[](blackstormsecurity.com/docs/NO_HAT_2019.pdf)

> KPCR -> KdVersionBlock -> `_DBGKD_GET_VERSION64` -> `LIST_ENTRY _KDDEBUGGER_DATA64` (`GetDebuggerData()`) -> `_KDDEBUGGER_DATA64 KdDebuggerDataBlock` -> kernel variables



> `_KPCR gs:[0]` -> `_DBGKD_GET_VERSION64 KdVersionBlock` -> `PLIST_ENTRY DebuggerDataList` -> `PLIST_ENTRY Flink` -> `Debugger block`

This only works with windows x86, x64 Windows KdVersionBlock is always null.

[KdVersionBlock](https://web.archive.org/web/20061110120809/http://www.rootkit.com/newsread.php?newsid=153)

```
_DBGKD_GET_VERSION64* KdVersionBlock;
__asm {
  mov eax, gs:[0x108]
  mov KdVersionBlock, eax
}
PLIST_ENTRY dbglist = KdVersionBlock->DebuggerDataList;
DebuggerBlock dbgBlock = (DebuggerBlock)*(dbglist->Flink);
```



`AuxKlibQueryModuleInformation` to get all `PsActiveProcessModules`
[Sample](https://correy.webs.com/articles/computer/c/AuxKlibQueryModuleInformation.C.txt)
