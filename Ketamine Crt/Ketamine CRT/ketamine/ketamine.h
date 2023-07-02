#pragma once

namespace Ketamine
{

    typedef struct _LIST_ENTRY {
        struct _LIST_ENTRY* Flink;
        struct _LIST_ENTRY* Blink;
    } LIST_ENTRY, * PLIST_ENTRY, * __restrict PRLIST_ENTRY;

    struct UNICODE_STRING
    {
        unsigned short Length;
        unsigned short MaxLength;
        wchar_t* Buffer;
    };

    typedef struct _PEB_LDR_DATA {
        unsigned long Length;
        unsigned char Initialized;
        void* SsHandle;
        LIST_ENTRY ModuleListLoadOrder;
        LIST_ENTRY ModuleListMemoryOrder;
        LIST_ENTRY ModuleListInitOrder;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        unsigned char Reserved1[16];
        void* Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

    typedef struct _PEB {
        unsigned char Reserved1[2];
        unsigned char BeingDebugged;
        unsigned char Reserved2[1];
        void* Reserved3[2];
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        void* Reserved4[3];
        void* AtlThunkSListPtr;
        void* Reserved5;
        unsigned long Reserved6;
        void* Reserved7;
        unsigned long Reserved8;
        unsigned long AtlThunkSListPtr32;
        void* Reserved9[45];
        unsigned char Reserved10[96];
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
        unsigned char Reserved11[128];
        void* Reserved12[1];
        unsigned long SessionId;
    } PEB, * PPEB;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        void* DllBase;
        void* EntryPoint;
        unsigned long SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        unsigned long Flags;
        unsigned short LoadCount;
        unsigned short TlsIndex;
        LIST_ENTRY HashLinks;
        void* SectionPointer;
        unsigned long CheckSum;
        unsigned long TimeDateStamp;
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef struct _IMAGE_DATA_DIRECTORY {
        unsigned long   VirtualAddress;
        unsigned long   Size;
    } IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

    typedef struct _IMAGE_OPTIONAL_HEADER {
        unsigned short    Magic;
        unsigned char    MajorLinkerVersion;
        unsigned char    MinorLinkerVersion;
        unsigned long   SizeOfCode;
        unsigned long   SizeOfInitializedData;
        unsigned long   SizeOfUninitializedData;
        unsigned long   AddressOfEntryPoint;
        unsigned long   BaseOfCode;
        unsigned long   BaseOfData;

        unsigned long   ImageBase;
        unsigned long   SectionAlignment;
        unsigned long   FileAlignment;
        unsigned short    MajorOperatingSystemVersion;
        unsigned short    MinorOperatingSystemVersion;
        unsigned short    MajorImageVersion;
        unsigned short    MinorImageVersion;
        unsigned short    MajorSubsystemVersion;
        unsigned short    MinorSubsystemVersion;
        unsigned long   Win32VersionValue;
        unsigned long   SizeOfImage;
        unsigned long   SizeOfHeaders;
        unsigned long   CheckSum;
        unsigned short    Subsystem;
        unsigned short    DllCharacteristics;
        unsigned long   SizeOfStackReserve;
        unsigned long   SizeOfStackCommit;
        unsigned long   SizeOfHeapReserve;
        unsigned long   SizeOfHeapCommit;
        unsigned long   LoaderFlags;
        unsigned long   NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    } IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

    typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
        unsigned short   Magic;
        unsigned char   MajorLinkerVersion;
        unsigned char   MinorLinkerVersion;
        unsigned long  SizeOfCode;
        unsigned long  SizeOfInitializedData;
        unsigned long  SizeOfUninitializedData;
        unsigned long  AddressOfEntryPoint;
        unsigned long  BaseOfCode;
        unsigned long  BaseOfData;
        unsigned long  BaseOfBss;
        unsigned long  GprMask;
        unsigned long  CprMask[4];
        unsigned long  GpValue;
    } IMAGE_ROM_OPTIONAL_HEADER, * PIMAGE_ROM_OPTIONAL_HEADER;

    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        unsigned short        Magic;
        unsigned char        MajorLinkerVersion;
        unsigned char        MinorLinkerVersion;
        unsigned long       SizeOfCode;
        unsigned long       SizeOfInitializedData;
        unsigned long       SizeOfUninitializedData;
        unsigned long       AddressOfEntryPoint;
        unsigned long       BaseOfCode;
        unsigned __int64 unsigned   ImageBase;
        unsigned long       SectionAlignment;
        unsigned long       FileAlignment;
        unsigned short        MajorOperatingSystemVersion;
        unsigned short        MinorOperatingSystemVersion;
        unsigned short        MajorImageVersion;
        unsigned short        MinorImageVersion;
        unsigned short        MajorSubsystemVersion;
        unsigned short        MinorSubsystemVersion;
        unsigned long       Win32VersionValue;
        unsigned long       SizeOfImage;
        unsigned long       SizeOfHeaders;
        unsigned long       CheckSum;
        unsigned short        Subsystem;
        unsigned short        DllCharacteristics;
        unsigned __int64 unsigned   SizeOfStackReserve;
        unsigned __int64 unsigned   SizeOfStackCommit;
        unsigned __int64 unsigned   SizeOfHeapReserve;
        unsigned __int64 unsigned   SizeOfHeapCommit;
        unsigned long       LoaderFlags;
        unsigned long       NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    } IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

    typedef struct _IMAGE_FILE_HEADER {
        unsigned short    Machine;
        unsigned short    NumberOfSections;
        unsigned long   TimeDateStamp;
        unsigned long   PointerToSymbolTable;
        unsigned long   NumberOfSymbols;
        unsigned short    SizeOfOptionalHeader;
        unsigned short    Characteristics;
    } IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

    typedef struct _IMAGE_NT_HEADERS64 {
        unsigned long Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

    typedef struct _IMAGE_NT_HEADERS {
        unsigned long Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

    typedef struct _IMAGE_ROM_HEADERS {
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
    } IMAGE_ROM_HEADERS, * PIMAGE_ROM_HEADERS;

    typedef struct _IMAGE_EXPORT_DIRECTORY
    {
        unsigned long Characteristics;
        unsigned long TimeDateStamp;
        unsigned short MajorVersion;
        unsigned short MinorVersion;
        unsigned long Name;
        unsigned long Base;
        unsigned long NumberOfFunctions;
        unsigned long NumberOfNames;
        unsigned long AddressOfFunctions;
        unsigned long AddressOfNames;
        unsigned long AddressOfNameOrdinals;
    }IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

    typedef struct _IMAGE_DOS_HEADER {
        unsigned short   e_magic;
        unsigned short   e_cblp;
        unsigned short   e_cp;
        unsigned short   e_crlc;
        unsigned short   e_cparhdr;
        unsigned short   e_minalloc;
        unsigned short   e_maxalloc;
        unsigned short   e_ss;
        unsigned short   e_sp;
        unsigned short   e_csum;
        unsigned short   e_ip;
        unsigned short   e_cs;
        unsigned short   e_lfarlc;
        unsigned short   e_ovno;
        unsigned short   e_res[4];
        unsigned short   e_oemid;
        unsigned short   e_oeminfo;
        unsigned short   e_res2[10];
        unsigned short   e_lfanew;
    } IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

    typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;

    #define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (unsigned __int64)(&((type *)0)->field)))

    template<typename T = char>
    inline bool strcmp(const T* a, const T* b)
    {
        if (!a || !b)
            return !a && !b;

        int ret = 0;
        T* p1 = (T*)a;
        T* p2 = (T*)b;
        while (!(ret = *p1 - *p2) && *p2)
            ++p1, ++p2;

        return ret == 0;
    }

    template<typename T = char>
    inline unsigned short strlen(const T* str)
    {
        auto counter{ 0 };
        if (!str)
            return 0;
        for (; *str != '\0'; ++str)
            ++counter;

        return counter;
    }

}

using namespace Ketamine;