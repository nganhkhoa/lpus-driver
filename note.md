
Try to find `MmNonPagedPoolStart` and `MmNonPagedPoolEnd`

https://web.archive.org/web/20061110120809/http://www.rootkit.com/newsread.php?newsid=153

`KPCR->KdVersionBlock->Debugger Data List Entry->Flink`

This technique is old and cannot be used in Windows 10, Windows 7/8 may fail
too, After research, the result is summary into this
(file)[https://github.com/nganhkhoa/lpus/blob/master/nonpaged-pool-range.md]

Basically, find ntoskrnl.exe module address (kernel base) in memory and use
offsets parsed from PDB file. Finding the kernel base by shellcode is not
usable in Windows 2020 Insider Preview, I use IoGetCurrentProcess and traverse
the ActiveProcessLinks linked list, Luckily, the process returned by
IoGetCurrentProcess (if called in DriverEntry) is System (the first process),
so the BLink is `nt!PsActiveProcessHead`. With the offset of
`nt!PsActiveProcessHead` parsed from PDB file, we can get the kernel base by
subtracting.

Then traverse the `(_MI_SYSTEM_INFORMATION*)nt!MiState` to find
NonPagedPool{First,Last}Va.

Try the following steps:

1. `x nt!MiState` to get address of MiState

2. `dt _MI_SYSTEM_INFORMATION` to get offset to Hardware

3. `dt _MI_HARDWARE_STATE` to get offset to SystemNodeNonPagedPool with those
offset, use the following command to list the NonPagedPool{First,Last}Va

4. `dt (_MI_SYSTEM_NODE_NONPAGED_POOL*) (<nt!MiState> + <HARDWARE_OFFSET> +
<NODE_INFO_OFFSET>)` Sample output

Sample results:
```
+0x000 DynamicBitMapNonPagedPool : _MI_DYNAMIC_BITMAP
+0x048 CachedNonPagedPoolCount : 0
+0x050 NonPagedPoolSpinLock : 0
+0x058 CachedNonPagedPool : (null)
+0x060 NonPagedPoolFirstVa : 0xffffe580`00000000 Void
+0x068 NonPagedPoolLastVa : 0xfffff580`00000000 Void
+0x070 SystemNodeInformation : 0xffffe58f`9283b050 _MI_SYSTEM_NODE_INFORMATION
```

The big page pool is denoted by two variables `PoolBigPageTable.Va` and
`PoolBigPageTableSize` It seems that this big page is inside NonPagedPool range

PoolBigPageTable is an array with PoolBigPageTableSize elements, where each
elements has:

- Va -> Address of the allocation
- Key -> Pool tag
- NumberOfBytes -> Size

By scanning the non-paged pool, we noticed that the scan hit on a few pages,
then no more results is found. The big table seems to be pointing to the
location of these allocation. So scanning through big table is faster?
