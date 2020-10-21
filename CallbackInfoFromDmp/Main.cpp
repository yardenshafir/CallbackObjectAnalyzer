#include <Windows.h>
#include <DbgEng.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>
#include <list>

typedef
NTSTATUS
(__stdcall*
    NtSystemDebugControl) (
        ULONG ControlCode,
        PVOID InputBuffer,
        ULONG InputBufferLength,
        PVOID OutputBuffer,
        ULONG OutputBufferLength,
        PULONG ReturnLength
        );

typedef union _SYSDBG_LIVEDUMP_CONTROL_FLAGS
{
    struct
    {
        ULONG UseDumpStorageStack : 1;
        ULONG CompressMemoryPagesData : 1;
        ULONG IncludeUserSpaceMemoryPages : 1;
        ULONG Reserved : 29;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_FLAGS;

typedef union _SYSDBG_LIVEDUMP_CONTROL_ADDPAGES
{
    struct
    {
        ULONG HypervisorPages : 1;
        ULONG Reserved : 31;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_ADDPAGES;

typedef struct _SYSDBG_LIVEDUMP_CONTROL
{
    ULONG Version;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    PVOID DumpFileHandle;
    PVOID CancelEventHandle;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES AddPagesControl;
} SYSDBG_LIVEDUMP_CONTROL, * PSYSDBG_LIVEDUMP_CONTROL;

#define CONTROL_KERNEL_DUMP 37
static NtSystemDebugControl g_NtSystemDebugControl = NULL;

typedef enum CONNECT_TYPE
{
    DumpFile = 0x0,
    LiveDump = 0x1,
    KernelDebug = 0x2,
    MaxConnectionType = 0x3
};

typedef struct _CALLBACK_OBJECT
{
    ULONG Signature;
    KSPIN_LOCK Lock;
    LIST_ENTRY RegisteredCallbacks;
    BOOLEAN AllowMultipleCallbacks;
    UCHAR reserved[3];
    LIST_ENTRY CallbackList;
} CALLBACK_OBJECT, * PCALLBACK_OBJECT;

typedef struct _CALLBACK_REGISTRATION
{
    LIST_ENTRY Link;
    PCALLBACK_OBJECT CallbackObject;
    PVOID CallbackFunction;
    PVOID CallbackContext;
    ULONG Busy;
    BOOLEAN UnregisterWaiting;
} CALLBACK_REGISTRATION, * PCALLBACK_REGISTRATION;

/*
    Enables or disables the chosen privilege for the current process.
    Taken from here: https://github.com/lilhoser/livedump
*/
BOOL
EnablePrivilege(
    _In_ PCWSTR PrivilegeName,
    _In_ BOOLEAN Acquire
)
{
    HANDLE tokenHandle;
    BOOL ret;
    ULONG tokenPrivilegesSize = FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[1]);
    PTOKEN_PRIVILEGES tokenPrivileges = static_cast<PTOKEN_PRIVILEGES>(calloc(1, tokenPrivilegesSize));

    if (tokenPrivileges == NULL)
    {
        return FALSE;
    }

    tokenHandle = NULL;
    tokenPrivileges->PrivilegeCount = 1;
    ret = LookupPrivilegeValue(NULL,
        PrivilegeName,
        &tokenPrivileges->Privileges[0].Luid);
    if (ret == FALSE)
    {
        goto Exit;
    }

    tokenPrivileges->Privileges[0].Attributes = Acquire ? SE_PRIVILEGE_ENABLED
        : SE_PRIVILEGE_REMOVED;

    ret = OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &tokenHandle);
    if (ret == FALSE)
    {
        goto Exit;
    }

    ret = AdjustTokenPrivileges(tokenHandle,
        FALSE,
        tokenPrivileges,
        tokenPrivilegesSize,
        NULL,
        NULL);
    if (ret == FALSE)
    {
        goto Exit;
    }

Exit:
    if (tokenHandle != NULL)
    {
        CloseHandle(tokenHandle);
    }
    free(tokenPrivileges);
    return ret;
}


/*
    Creates a live dump of the current machine.
    Taken from here: https://github.com/lilhoser/livedump
*/
HRESULT
CreateDump(
    _In_ PCSTR FilePath
)
{
    HRESULT result;
    HANDLE handle;
    HMODULE module;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES pages;
    SYSDBG_LIVEDUMP_CONTROL liveDumpControl;
    NTSTATUS status;
    ULONG returnLength;

    handle = INVALID_HANDLE_VALUE;
    result = S_OK;
    flags.AsUlong = 0;
    pages.AsUlong = 0;

    //
    // Get function addresses
    //
    module = LoadLibrary(L"ntdll.dll");
    if (module == NULL)
    {
        result = S_FALSE;
        goto Exit;
    }

    g_NtSystemDebugControl = (NtSystemDebugControl)
        GetProcAddress(module, "NtSystemDebugControl");

    FreeLibrary(module);

    if (g_NtSystemDebugControl == NULL)
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Get SeDebugPrivilege
    //
    if (!EnablePrivilege(SE_DEBUG_NAME, TRUE))
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Create the target file (must specify synchronous I/O)
    //
    handle = CreateFileA(FilePath,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
        NULL);

    if (handle == INVALID_HANDLE_VALUE)
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Try to create the requested dump
    //
    memset(&liveDumpControl, 0, sizeof(liveDumpControl));

    //
    // The only thing the kernel looks at in the struct we pass is the handle,
    // the flags and the pages to dump.
    //
    liveDumpControl.DumpFileHandle = (PVOID)(handle);
    liveDumpControl.AddPagesControl = pages;
    liveDumpControl.Flags = flags;

    status = g_NtSystemDebugControl(CONTROL_KERNEL_DUMP,
        (PVOID)(&liveDumpControl),
        sizeof(liveDumpControl),
        NULL,
        0,
        &returnLength);

    if (NT_SUCCESS(status))
    {
        result = S_OK;
    }
    else
    {
        result = S_FALSE;
        goto Exit;
    }

Exit:
    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);
    }
    return result;
}

HRESULT ParseArgs (
    _In_ int argc,
    _In_ char* argv[],
    _Out_ CONNECT_TYPE *ConnectionType,
    _Out_ PCSTR *Path
)
{
    *ConnectionType = MaxConnectionType;

    if (argc > 1)
    {
        for (int i = 0; i < argc; i++)
        {
            if (strcmp(argv[i], "-l") == 0)
            {
                if (*ConnectionType != MaxConnectionType)
                {
                    printf("Requested more than one connection type. Conflicting Flags.");
                    return S_FALSE;
                }
                *ConnectionType = LiveDump;
                *Path = "c:\\temp\\live.dmp";
                printf("Creating a  dump of current machine at path %s\n", *Path);
                CreateDump(*Path);
                continue;
            }
            if (strcmp(argv[i], "-d") == 0)
            {
                if (i + 1 == argc)
                {
                    printf("Flag -d must receive a dump file path.");
                    return S_FALSE;
                }
                if (*ConnectionType != MaxConnectionType)
                {
                    printf("Requested more than one connection type. Conflicting Flags.");
                    return S_FALSE;
                }
                *ConnectionType = DumpFile;
                *Path = argv[i + 1];
                i++;
                continue;
            }
            if (strcmp(argv[i], "-k") == 0)
            {
                if (i + 1 == argc)
                {
                    printf("Flag -k must receive connection parameters.");
                    return S_FALSE;
                }
                if (*ConnectionType != MaxConnectionType)
                {
                    printf("Requested more than one connection type. Conflicting Flags.");
                    return S_FALSE;
                }
                *ConnectionType = KernelDebug;
                *Path = argv[i + 1];
                i++;
                continue;
            }
        }
    }
    return S_OK;
}

int main(int argc, char* argv[])
{
    IDebugClient* debugClient;
    IDebugSymbols* debugSymbols;
    IDebugDataSpaces* dataSpaces;
    IDebugControl* debugControl;

    HRESULT result;
    ULONG64 kernBase;

    ULONG OBJECT_HEADER;
    ULONG objHeaderSize;
    PVOID objHeader;
    ULONG infoMaskOffset;
    BYTE infoMask;
    ULONG offsetToNameInfoHeader;

    ULONG OBJECT_HEADER_NAME_INFO;
    ULONG OBJECT_HEADER_HANDLE_INFO;
    ULONG OBJECT_HEADER_QUOTA_INFO;
    ULONG OBJECT_HEADER_PROCESS_INFO;
    ULONG OBJECT_HEADER_AUDIT_INFO;
    ULONG OBJECT_HEADER_HANDLE_REVOCATION_INFO;
    ULONG objHeaderNameInfoSize;
    ULONG objHeaderHandleInfoSize;
    ULONG objHeaderQuotaInfoSize;
    ULONG objHeaderProcessInfoSize;
    ULONG objHeaderAuditInfoSize;
    ULONG objHeaderHandleRevocationInfoSize;
    PVOID objHeaderNameInfo;
    ULONG nameInfoNameOffset;
    PWSTR buffer;
    PUNICODE_STRING callbackName;

    ULONG64 callbackListHeadAddress;
    ULONG64 callbackListHead;
    ULONG64 callbackAddress;
    CALLBACK_OBJECT callback;
    LIST_ENTRY registeredCallbacksList;
    PLIST_ENTRY nextRegisteredCallback;
    CALLBACK_REGISTRATION callbackRegistration;
    PLIST_ENTRY registeredCallbacksAddr;

    CHAR symbolBuffer[100];
    ULONG64 displacement;

    CONNECT_TYPE connectionType;
    PCSTR dumpPath;

    objHeader = nullptr;
    callbackName == nullptr;
    buffer = nullptr;

    //
    // Parse the arguments to receive the connection information
    //
    ParseArgs(argc, argv, &connectionType, &dumpPath);

    //
    // Initialize interfaces
    //
    debugClient = nullptr;
    debugSymbols = nullptr;
    dataSpaces = nullptr;
    debugControl = nullptr;
    result = DebugCreate(__uuidof(IDebugClient), (PVOID*)&debugClient);
    if (!SUCCEEDED(result))
    {
        printf("DebugCreate failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*)&debugSymbols);
    if (!SUCCEEDED(result))
    {
        printf("QueryInterface for debug symbols failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*)&dataSpaces);
    if (!SUCCEEDED(result))
    {
        printf("QueryInterface for debug data spaces failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugClient->QueryInterface(__uuidof(IDebugControl), (PVOID*)&debugControl);
    if (!SUCCEEDED(result))
    {
        printf("QueryInterface for debug control failed with error 0x%x\n", result);
        goto Exit;
    }

    if (connectionType == KernelDebug)
    {
        //
        // Attach to kernel
        //
        result = debugControl->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
        if (!SUCCEEDED(result))
        {
            printf("OpenDumpFile failed with error 0x%x\n", result);
            goto Exit;
        }

        result = debugClient->AttachKernel(DEBUG_ATTACH_KERNEL_CONNECTION, dumpPath);
        if (!SUCCEEDED(result))
        {
            printf("OpenDumpFile failed with error 0x%x\n", result);
            goto Exit;
        }
    }
    else
    {
        //
        // Open the dmp file
        //
        result = debugClient->OpenDumpFile(dumpPath);
    }

    //
    // Wait for the file to be loaded with all of its symbols
    //
    result = debugControl->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
    if (!SUCCEEDED(result))
    {
        printf("WaitForEvent failed with error 0x%x\n", result);
        return result;
    }

    //
    // Get the base of the nt module, we will need it to get other symbols
    //
    result = dataSpaces->ReadDebuggerData(DEBUG_DATA_KernBase,
                                          &kernBase,
                                          sizeof(kernBase),
                                          nullptr);
    if (!SUCCEEDED(result))
    {
        printf("ReadDebuggerData failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // Get infomation about the object header structure so we can 
    // get the name information for callbacks
    //
    result = debugSymbols->GetTypeId(kernBase, "_OBJECT_HEADER", &OBJECT_HEADER);
    if (!SUCCEEDED(result))
    {
        printf("GetTypeId failed with error 0x%x\n", result);
        goto Exit;
    }
    result = debugSymbols->GetTypeSize(kernBase, OBJECT_HEADER, &objHeaderSize);
    if (!SUCCEEDED(result))
    {
        printf("GetTypeSize failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugSymbols->GetFieldOffset(kernBase,
                                          OBJECT_HEADER,
                                          "InfoMask",
                                          &infoMaskOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }

    if (!SUCCEEDED(debugSymbols->GetTypeId(kernBase, "_OBJECT_HEADER_NAME_INFO", &OBJECT_HEADER_NAME_INFO)) ||
        !SUCCEEDED(debugSymbols->GetTypeId(kernBase, "_OBJECT_HEADER_HANDLE_INFO", &OBJECT_HEADER_HANDLE_INFO)) ||
        !SUCCEEDED(debugSymbols->GetTypeId(kernBase, "_OBJECT_HEADER_QUOTA_INFO", &OBJECT_HEADER_QUOTA_INFO)) ||
        !SUCCEEDED(debugSymbols->GetTypeId(kernBase, "_OBJECT_HEADER_PROCESS_INFO", &OBJECT_HEADER_PROCESS_INFO)) ||
        !SUCCEEDED(debugSymbols->GetTypeId(kernBase, "_OBJECT_HEADER_AUDIT_INFO", &OBJECT_HEADER_AUDIT_INFO)) ||
        !SUCCEEDED(debugSymbols->GetTypeSize(kernBase, OBJECT_HEADER_NAME_INFO, &objHeaderNameInfoSize) ) ||
        !SUCCEEDED(debugSymbols->GetTypeSize(kernBase, OBJECT_HEADER_HANDLE_INFO, &objHeaderHandleInfoSize)) ||
        !SUCCEEDED(debugSymbols->GetTypeSize(kernBase, OBJECT_HEADER_QUOTA_INFO, &objHeaderQuotaInfoSize)) ||
        !SUCCEEDED(debugSymbols->GetTypeSize(kernBase, OBJECT_HEADER_PROCESS_INFO, &objHeaderProcessInfoSize)) ||
        !SUCCEEDED(debugSymbols->GetTypeSize(kernBase, OBJECT_HEADER_AUDIT_INFO, &objHeaderAuditInfoSize)))
    {
        printf("Failed getting types or sizes\n");
        goto Exit;
    }

    result = debugSymbols->GetFieldOffset(kernBase,
                                          OBJECT_HEADER_NAME_INFO,
                                          "Name",
                                          &nameInfoNameOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // CALLBACK_OBJECT and CALLBACK_REGISTRATION are not exported types
    // so we need to use our own definitions.
    // We will start iteration from the known symbol ExpCallbackListHead
    // and then read the lists of callback objects and registered callbacks
    //
    result = debugSymbols->GetOffsetByName("nt!ExpCallbackListHead",
                                           &callbackListHeadAddress);
    if (!SUCCEEDED(result))
    {
        printf("GetOffsetByName failed with error 0x%x\n", result);
        goto Exit;
    }

    result = dataSpaces->ReadVirtual(callbackListHeadAddress,
                                     &callbackListHead,
                                     sizeof(callbackListHead),
                                     nullptr);
    if (!SUCCEEDED(result))
    {
        printf("ReadVirtual failed with error 0x%x\n", result);
        goto Exit;
    }

    callbackAddress = (ULONG64)(CONTAINING_RECORD(callbackListHead, CALLBACK_OBJECT, CallbackList));

    //
    // Allocate memory for an object header
    //
    objHeader = VirtualAlloc(NULL, objHeaderSize, MEM_COMMIT, PAGE_READWRITE);
    if (objHeader == nullptr)
    {
        goto Exit;
    }

    //
    // Read the callback object
    //
    do
    {
        result = dataSpaces->ReadVirtual(callbackAddress,
                                         &callback,
                                         sizeof(callback),
                                         nullptr);
        if (!SUCCEEDED(result))
        {
            printf("ReadVirtual failed with error 0x%x\n", result);
            goto Exit;
        }
        printf("Callback at address 0x%p:\n\tAllow multiple callbacks: %d\n",
               callbackAddress,
               callback.AllowMultipleCallbacks);

        //
        // Read object header to learn the callback's name
        // OBJECT_HEADER contains the "body" field too, so we need to decrease it by 8 bytes
        //
        result = dataSpaces->ReadVirtual(callbackAddress - (objHeaderSize - sizeof(PVOID)),
                                         objHeader,
                                         objHeaderSize - sizeof(PVOID),
                                         nullptr);

        //
        // The infoMask tells us which object headers this object has.
        // Use those to calculate the offset of the name info header
        // from the object header (all the special headers are before
        // the OBJECT_HEADER) and read the callback name from it.
        //
        infoMask = *(PBYTE)((ULONG64)objHeader + infoMaskOffset);

        if ((infoMask & 2) == 2)
        {
            offsetToNameInfoHeader = 0;
            if ((infoMask & 2) == 2)
            {
                offsetToNameInfoHeader += objHeaderNameInfoSize;
            }
            if ((infoMask & 4) == 4)
            {
                offsetToNameInfoHeader += objHeaderHandleInfoSize;
            }
            if ((infoMask & 8) == 8)
            {
                offsetToNameInfoHeader += objHeaderQuotaInfoSize;
            }
            if ((infoMask & 0x10) == 0x10)
            {
                offsetToNameInfoHeader += objHeaderProcessInfoSize;
            }
            if ((infoMask & 0x20) == 0x20)
            {
                offsetToNameInfoHeader += objHeaderAuditInfoSize;
            }
            if ((infoMask & 0x40) == 0x40)
            {
                //
                // This should be OBJECT_HEADER_HANDLE_REVOCATION_INFO but since
                // this structure is not in the symbol file we'll hard-code
                // the size. I don't think I've ever seen this used so it probably
                // won't matter much anyway.
                //
                offsetToNameInfoHeader += 0x20;
            }
            objHeaderNameInfo = VirtualAlloc(NULL, objHeaderNameInfoSize, MEM_COMMIT, PAGE_READWRITE);
            if (objHeaderNameInfo != nullptr)
            {
                result = dataSpaces->ReadVirtual(callbackAddress - (objHeaderSize - sizeof(PVOID)) - offsetToNameInfoHeader,
                    objHeaderNameInfo,
                    objHeaderNameInfoSize,
                    nullptr);

                callbackName = (UNICODE_STRING*)((ULONG64)objHeaderNameInfo + nameInfoNameOffset);
                buffer = (PWSTR)VirtualAlloc(NULL, callbackName->Length, MEM_COMMIT, PAGE_READWRITE);
                if (buffer != nullptr)
                {
                    result = dataSpaces->ReadVirtual((ULONG64)callbackName->Buffer,
                                                     buffer,
                                                     callbackName->Length,
                                                     nullptr);
                    if (!SUCCEEDED(result))
                    {
                        printf("ReadVirtual failed with error 0x%x\n", result);
                        callbackName->Length = 0;
                    }
                    callbackName->Buffer = buffer;
                }
                else
                {
                    callbackName->Length = 0;
                }
                printf("\tCallback name: %wZ\n", callbackName);
            }
            if (buffer != nullptr)
            {
                VirtualFree(buffer, NULL, MEM_RELEASE);
            }
            if (objHeaderNameInfo != nullptr)
            {
                VirtualFree(objHeaderNameInfo, NULL, MEM_RELEASE);
            }
        }
        else
        {
            //
            // This is an unnamed callback
            //
            printf("\tCallback is unnamed\n");
        }

        //
        // Iterate over registeredCallbacks and print information about them
        //
        registeredCallbacksList = callback.RegisteredCallbacks;
        registeredCallbacksAddr = (PLIST_ENTRY)(callbackAddress + offsetof(CALLBACK_OBJECT,
                                                                           RegisteredCallbacks));
        nextRegisteredCallback = (PLIST_ENTRY)(CONTAINING_RECORD(registeredCallbacksList.Flink,
                                                                 CALLBACK_REGISTRATION,
                                                                 Link));
        while (nextRegisteredCallback != registeredCallbacksAddr)
        {
            result = dataSpaces->ReadVirtual((ULONG64)(nextRegisteredCallback),
                                             &callbackRegistration,
                                             sizeof(callbackRegistration),
                                             nullptr);
            if (!SUCCEEDED(result))
            {
                printf("ReadVirtual failed with error 0x%x\n", result);
                goto Exit;
            }
            //
            // Get the symbol name for the registered callback function
            //
            result = debugSymbols->GetNameByOffset((ULONG64)callbackRegistration.CallbackFunction,
                                                   symbolBuffer,
                                                   sizeof(symbolBuffer),
                                                   NULL,
                                                   &displacement);
            if (displacement == 0)
            {
                printf("\t\tFunction at address 0x%p, symbol: %s\n\t\t\tCallback Context: 0x%p\n",
                       callbackRegistration.CallbackFunction,
                       symbolBuffer,
                       callbackRegistration.CallbackContext);
            }
            else
            {
                printf("\t\tFunction at address 0x%p, symbol: %s+0x%x\n\t\t\tCallback Context: 0x%p\n",
                       callbackRegistration.CallbackFunction,
                       symbolBuffer,
                       displacement,
                       callbackRegistration.CallbackContext);
            }
            nextRegisteredCallback = (PLIST_ENTRY)(CONTAINING_RECORD(callbackRegistration.Link.Flink,
                                                                     CALLBACK_REGISTRATION,
                                                                     Link));
        }

        //
        // Get the linked list from the callback object and set callbackAddress
        // to the next callback
        //
        callbackAddress = (ULONG64)(CONTAINING_RECORD((ULONG64)callback.CallbackList.Flink, CALLBACK_OBJECT, CallbackList));

    } while ((ULONG64)callback.CallbackList.Flink != callbackListHeadAddress);

Exit:
    if (objHeader != nullptr)
    {
        VirtualFree(objHeader, NULL, MEM_RELEASE);
    }
    if (debugClient != nullptr)
    {
        //
        // End the current session
        //
        debugClient->EndSession(DEBUG_END_ACTIVE_DETACH);
        debugClient->Release();
    }
    if (debugSymbols != nullptr)
    {
        debugSymbols->Release();
    }
    if (dataSpaces != nullptr)
    {
        dataSpaces->Release();
    }
    if (debugControl != nullptr)
    {
        debugControl->Release();
    }
    return 0;
}
