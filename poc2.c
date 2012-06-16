#include <stdio.h>
#include <windows.h>

typedef LONG (WINAPI *LP_NtUnmapViewOfSection)(HANDLE ProcessHandle,
    DWORD BaseAddress);

char *FileToMem(const char *pszFileName)
{
    char *lpBuffer = NULL;
    HANDLE hFile = CreateFile(pszFileName, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE) goto cleanup;

    DWORD dwSize = GetFileSize(hFile, NULL);
    if(dwSize == (DWORD) -1) goto cleanup;

    lpBuffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if(lpBuffer == NULL) goto cleanup;

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD dwRead;
    if(ReadFile(hFile, lpBuffer, dwSize, &dwRead, NULL) == FALSE ||
            dwSize != dwRead) {
        goto cleanup;
    }

    CloseHandle(hFile);
    return lpBuffer;

cleanup:
    if(lpBuffer != NULL) {
        VirtualFree(lpBuffer, 0, MEM_RELEASE);
    }
    if(hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    return NULL;
}

int ExecFile(const char *pszFilePath, char *lpFile)
{
    DWORD dwBytes; void *lpImageBase = NULL;

    // check the image dos header
    IMAGE_DOS_HEADER *pImageDosHeader = (IMAGE_DOS_HEADER *) lpFile;
    if(pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // check the image nt headers
    IMAGE_NT_HEADERS *pImageNtHeaders = (IMAGE_NT_HEADERS *)(lpFile +
        pImageDosHeader->e_lfanew);
    if(pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // start the new process which we will overwrite later
    STARTUPINFOA StartupInfo = {sizeof(STARTUPINFOA)};
    PROCESS_INFORMATION ProcessInformation = {0};
    if(CreateProcess(pszFilePath, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &StartupInfo,
            &ProcessInformation) == FALSE) {
        return FALSE;
    }

    // read the base address of the executable loaded in the
    // process which we will inject
    CONTEXT ctx = {CONTEXT_FULL}; DWORD dwImageBase;
    if(GetThreadContext(ProcessInformation.hThread, &ctx) == FALSE ||
            ReadProcessMemory(ProcessInformation.hProcess,
                (void *)(ctx.Ebx + 8), &dwImageBase, 4, &dwBytes) == FALSE ||
            dwBytes != 4) {
        goto cleanup;
    }

    // unmap the loaded binary if the base address conflicts
    // with the binary which we want to load
    if(dwImageBase == pImageNtHeaders->OptionalHeader.ImageBase) {
        LP_NtUnmapViewOfSection pNtUnmapViewOfSection =
            (LP_NtUnmapViewOfSection) GetProcAddress(
                GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        pNtUnmapViewOfSection(ProcessInformation.hProcess, dwImageBase);
    }

    // allocate memory in the remote process for our binary
    lpImageBase = VirtualAllocEx(ProcessInformation.hProcess,
        (void *) pImageNtHeaders->OptionalHeader.ImageBase,
        pImageNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if(lpImageBase == NULL) {
        goto cleanup;
    }

    // write the headers of our binary to the process
    if(WriteProcessMemory(ProcessInformation.hProcess, lpImageBase, lpFile,
            pImageNtHeaders->OptionalHeader.SizeOfHeaders, &dwBytes)
                == FALSE ||
            dwBytes != pImageNtHeaders->OptionalHeader.SizeOfHeaders) {
        goto cleanup;
    }

    // enumerate all the sections in this binary
    IMAGE_SECTION_HEADER *pImageSectionHeader = (IMAGE_SECTION_HEADER *)(
        lpFile + pImageDosHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER) +
        sizeof(DWORD) + pImageNtHeaders->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections;
            i++, pImageSectionHeader++) {

        // if this section has no size_of_raw_data, then we skip it because
        // there is nothing to write
        if(pImageSectionHeader->SizeOfRawData == 0) continue;

        // and write each section to the correct address in the process
        if(WriteProcessMemory(ProcessInformation.hProcess,
                (char *) lpImageBase + pImageSectionHeader->VirtualAddress,
                lpFile + pImageSectionHeader->PointerToRawData,
                pImageSectionHeader->SizeOfRawData, &dwBytes) == FALSE ||
                pImageSectionHeader->SizeOfRawData != dwBytes) {
            goto cleanup;
        }
    }

    // write the new image base address
    if(WriteProcessMemory(ProcessInformation.hProcess, (void *)(ctx.Ebx + 8),
            &lpImageBase, 4, &dwBytes) == FALSE || dwBytes != 4) {
        goto cleanup;
    }

    // store the new entry point
    ctx.Eax = (DWORD) lpImageBase +
        pImageNtHeaders->OptionalHeader.AddressOfEntryPoint;

    // write the new context containing the updated entry point to the process
    SetThreadContext(ProcessInformation.hThread, &ctx);

    // resume the main thread, start the application
    ResumeThread(ProcessInformation.hThread);

    // clean up our resources
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    return TRUE;

cleanup:
    // clean up our resources
    if(lpImageBase != NULL) {
        VirtualFreeEx(ProcessInformation.hProcess, lpImageBase, 0,
            MEM_RELEASE);
    }
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    return FALSE;
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 0;
    }

    char szFileName[MAX_PATH]; char *lpFile;

    lpFile = FileToMem(argv[1]);
    if(lpFile != NULL) {
        GetModuleFileName(NULL, szFileName, sizeof(szFileName));
        ExecFile(szFileName, lpFile);
        VirtualFree(lpFile, 0, MEM_RELEASE);
    }
    return 0;
}
