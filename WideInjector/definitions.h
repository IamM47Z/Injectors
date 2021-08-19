#ifndef _DEFINITIONS_
#define _DEFINITIONS_

#define cs                  const_cast
#define sc					static_cast
#define rc					reinterpret_cast

#define PAUSE_EXIT( )		std::cout << xorstr( "\nPress Enter to Exit" ).c_str( ); \
							system( "pause>nul" );

#define PAUSE_CONTINUE( )	std::cout << xorstr( "\nPress Enter to Continue" ).c_str( ); \
							system( "pause>nul" );

union IMAGE_BASE_RELOCATION_INFO
{
	struct
	{
		WORD type : 4;
		WORD virtual_address : 12;
	};
	WORD value;
};

typedef IMAGE_BASE_RELOCATION_INFO* PIMAGE_BASE_RELOCATION_INFO;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,
	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

typedef struct _MM_COPY_ADDRESS
{
	union
	{
		PVOID            VirtualAddress;
		PHYSICAL_ADDRESS PhysicalAddress;
	};
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
	USHORT NextOffset;
	RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _EPROCESS EPROCESS, * PEPROCESS;

typedef enum _KPROCESSOR_MODE
{
	KernelMode,
	UserMode,
	MaximumMode
} KPROCESSOR_MODE, * PKPROCESSOR_MODE;

typedef struct _KAPC_STATE
{
	LIST_ENTRY ApcListHead[ 2 ];
	PEPROCESS Process;
	UCHAR KernelApcInProgress;
	UCHAR KernelApcPending;
	UCHAR UserApcPending;
} KAPC_STATE, * PKAPC_STATE;

struct LOADER_DATA
{
	wchar_t* driver_name;
	uintptr_t memory_pool;
	size_t    memory_size;
};

struct MAPPER_DATA
{
	void( *_ExFreePoolWithTag ) ( PVOID, ULONG );
	PVOID( *_ExAllocatePoolWithTag ) ( POOL_TYPE, SIZE_T, ULONG );
	NTSTATUS( *_MmCopyVirtualMemory ) ( PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T );
	PEPROCESS( *_IoGetCurrentProcess )( );
	NTSTATUS( *_PsLookupProcessByProcessId )( HANDLE, PEPROCESS* );

	size_t data_size;
	char*  data_address;
	HANDLE process_id;

	LOADER_DATA loader_data;

	uintptr_t return_address;
};

typedef MAPPER_DATA* PMAPPER_DATA;

extern "C" NTSTATUS NTAPI ZwLoadDriver( PUNICODE_STRING str );
extern "C" NTSTATUS NTAPI ZwUnloadDriver( PUNICODE_STRING str );

extern "C" __declspec( noinline ) char* get_rip( );

#endif