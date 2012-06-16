#include <stdio.h>
#include <string.h>
#include "pin.h"

// all our windows stuff.. needs its own namespace..
namespace W {
    #include <windows.h>
}

#define USHORT W::USHORT
#define ULONG W::ULONG
typedef wchar_t *PWCH;
typedef char *PCHAR;
#define HANDLE W::HANDLE
typedef void *PVOID;
#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define MAX_SYSCALL (64 * 1024)
static const char *g_syscall_names[MAX_SYSCALL];

// stole this lovely source code from the rreat library.
static void enum_syscalls()
{
    // no boundary checking at all, I assume ntdll is not malicious..
    // besides that, we are in our own process, _should_ be fine..
    unsigned char *image = (unsigned char *) W::GetModuleHandle("ntdll");
    W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;
    W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image +
        dos_header->e_lfanew);
    W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    W::IMAGE_EXPORT_DIRECTORY *export_directory =
        (W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);
    unsigned long *address_of_names = (unsigned long *)(image +
        export_directory->AddressOfNames);
    unsigned long *address_of_functions = (unsigned long *)(image +
        export_directory->AddressOfFunctions);
    unsigned short *address_of_name_ordinals = (unsigned short *)(image +
        export_directory->AddressOfNameOrdinals);
    unsigned long number_of_names = MIN(export_directory->NumberOfFunctions,
        export_directory->NumberOfNames);
    for (unsigned long i = 0; i < number_of_names; i++) {
        const char *name = (const char *)(image + address_of_names[i]);
        unsigned char *addr = image + address_of_functions[
            address_of_name_ordinals[i]];
        if(!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
            // does the signature match?
            // either:   mov eax, syscall_number ; mov ecx, some_value
            // or:       mov eax, syscall_number ; xor ecx, ecx
            if(*addr == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33)) {
                unsigned long syscall_number = *(unsigned long *)(addr + 1);
                if(syscall_number < MAX_SYSCALL) {
                    g_syscall_names[syscall_number] = name;
                }
            }
        }
    }
}

unsigned long syscall_name_to_number(const char *name)
{
    for (unsigned long i = 0; i < MAX_SYSCALL; i++) {
        if(g_syscall_names[i] != NULL &&
                !strcmp(g_syscall_names[i] + 2, name + 2)) {
            return i;
        }
    }
    fprintf(stderr, "System Call %s not found!\n", name);
    exit(0);
}

ADDRINT SYS_NtCreateUserProcess, SYS_NtWriteVirtualMemory, SYS_NtResumeThread;
ADDRINT SYS_NtDuplicateObject, SYS_NtOpenThread, SYS_NtDelayExecution;

void init_common_syscalls()
{
    SYS_NtCreateUserProcess = syscall_name_to_number("NtCreateUserProcess");
    SYS_NtWriteVirtualMemory = syscall_name_to_number("NtWriteVirtualMemory");
    SYS_NtResumeThread = syscall_name_to_number("NtResumeThread");
    SYS_NtDuplicateObject = syscall_name_to_number("NtDuplicateObject");
    SYS_NtOpenThread = syscall_name_to_number("NtOpenThread");
    SYS_NtDelayExecution = syscall_name_to_number("NtDelayExecution");
}

typedef struct _syscall_t {
    ADDRINT syscall_number;
    union {
        ADDRINT args[16];
        struct {
            ADDRINT arg0, arg1, arg2, arg3;
            ADDRINT arg4, arg5, arg6, arg7;
        };
    };
} syscall_t;

int g_process_handle_count = 0;
HANDLE g_process_handle[256] = {0};

int g_thread_handle_count = 0;
HANDLE g_thread_handle[256] = {0};

// extract arguments to a system call in a syscall_entry_callback
void syscall_get_arguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...)
{
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        int index = va_arg(args, int);
        ADDRINT *ptr = va_arg(args, ADDRINT *);
        *ptr = PIN_GetSyscallArgument(ctx, std, index);
    }
    va_end(args);
}

void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std,
    void *v)
{
    unsigned long syscall_number = PIN_GetSyscallNumber(ctx, std);
    if(syscall_number < MAX_SYSCALL) {
        const char *name = g_syscall_names[syscall_number];
        printf("%d %d %s\n", thread_id, syscall_number, name);

        syscall_t *sc = &((syscall_t *) v)[thread_id];
        sc->syscall_number = syscall_number;
        if(syscall_number == SYS_NtCreateUserProcess) {
            RTL_USER_PROCESS_PARAMETERS *process_parameters;
            ULONG create_thread_flags;

            syscall_get_arguments(ctx, std, 4, 0, &sc->arg0, 1, &sc->arg1,
                8, &process_parameters, 7, &create_thread_flags);

            printf("image_name: %S\ncommand_line: %S\n",
                process_parameters->ImagePathName.Buffer,
                process_parameters->CommandLine.Buffer);

            printf("process_flags: 0x%08x\nthread_flags: 0x%08x\n",
                PIN_GetSyscallArgument(ctx, std, 6),
                PIN_GetSyscallArgument(ctx, std, 7));

            if((create_thread_flags & 1) == 0) {
                printf("When creating a new process, please do suspend the "
                    "thread initially!\n");
                exit(0);
            }
        }
        else if(syscall_number == SYS_NtWriteVirtualMemory) {
            HANDLE process_handle; char *base_address, *buffer;

            syscall_get_arguments(ctx, std, 5, 0, &process_handle,
                1, &base_address, 2, &buffer, 3, &sc->arg3, 4, &sc->arg4);

            // base address, size, buffer
            fwrite(&base_address, 1, sizeof(base_address), stderr);
            fwrite(&sc->arg3, 1, sizeof(sc->arg3), stderr);
            fwrite(buffer, 1, sc->arg3, stderr);
        }
        else if(syscall_number == SYS_NtResumeThread) {
            W::TerminateThread(g_thread_handle[0], 0);
            W::TerminateProcess(g_process_handle[0], 0);
            printf("We've finished dumping the remote process.\n");
            exit(0);
        }
        else if(syscall_number == SYS_NtDuplicateObject) {
            printf("DuplicateHandle() not implemented yet!\n");
            exit(0);
        }
        else if(syscall_number == SYS_NtOpenThread) {
            printf("OpenThread() not implemented yet!\n");
            exit(0);
        }
        else if(syscall_number == SYS_NtDelayExecution) {
            // we can ignore Sleep() calls like this
            W::LARGE_INTEGER *delay_interval;
            syscall_get_arguments(ctx, std, 1, 1, &delay_interval);
            delay_interval->QuadPart = 0;
        }
    }
    else {
        printf("dafuq?\n");
    }
}

void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std,
    void *v)
{
    syscall_t *sc = &((syscall_t *) v)[thread_id];
    if(sc->syscall_number == SYS_NtCreateUserProcess) {
        g_process_handle[g_process_handle_count++] = (HANDLE) sc->arg0;
        g_thread_handle[g_thread_handle_count++] = (HANDLE) sc->arg1;
    }
    else if(sc->syscall_number == SYS_NtWriteVirtualMemory) {
    }
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)) {
        printf("Usage: %s <binary> [arguments]\n");
        return 0;
    }

    enum_syscalls();
    init_common_syscalls();

    static syscall_t sc[256] = {0};
    PIN_AddSyscallEntryFunction(&syscall_entry, &sc);
    PIN_AddSyscallExitFunction(&syscall_exit, &sc);

    PIN_StartProgram();
    return 0;
}
