#include "includes.h"

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

struct MAPPER_DATA
{
	HMODULE	( WINAPI*	_LoadLibraryA )			( LPCSTR );
	FARPROC	( WINAPI*	_GetProcAddress )		( HMODULE, LPCSTR );
	BOOLEAN	( WINAPI*	_RtlAddFunctionTable )	( PRUNTIME_FUNCTION, DWORD, DWORD64 );

	uintptr_t base_address;
	uintptr_t return_address;
};

typedef MAPPER_DATA* PMAPPER_DATA;

void WINAPI injected_shellcode( PMAPPER_DATA ptr_mapper_data )
{
	if ( !ptr_mapper_data )
		return;

	if ( ptr_mapper_data->return_address )
	{
		char* ptr_base					= rc<char*>( ptr_mapper_data->base_address );
		
		const auto ptr_optional_header	= &( rc<PIMAGE_NT_HEADERS>( ptr_base + rc<PIMAGE_DOS_HEADER>( ptr_base )->e_lfanew )->OptionalHeader );
		
		
		const auto _LoadLibraryA		= ptr_mapper_data->_LoadLibraryA;
		const auto _GetProcAddress		= ptr_mapper_data->_GetProcAddress;
		const auto _RtlAddFunctionTable = ptr_mapper_data->_RtlAddFunctionTable;
		const auto _DllMain				= rc<BOOL( WINAPI* ) ( void*, DWORD, LPVOID )>( ptr_base + ptr_optional_header->AddressOfEntryPoint );

		if ( ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size )
		{
			const auto location_delta = rc<uintptr_t>( ptr_base - ptr_optional_header->ImageBase );

			for ( auto ptr_reloc_block = rc<PIMAGE_BASE_RELOCATION>( ptr_base + ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );
				  location_delta && ptr_reloc_block->VirtualAddress;
				  ptr_reloc_block = rc<PIMAGE_BASE_RELOCATION>( rc<char*>( ptr_reloc_block ) + ptr_reloc_block->SizeOfBlock ) )
			{
				const auto entries_num				= ( ptr_reloc_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( IMAGE_BASE_RELOCATION_INFO );
				const auto ptr_relock_info_array	= reinterpret_cast<PIMAGE_BASE_RELOCATION_INFO>( ptr_reloc_block + 1 );

				for ( auto i = 0; i < entries_num; i++ )
				{
					if ( ptr_relock_info_array[ i ].type != IMAGE_REL_BASED_DIR64 )
						continue;

					ptr_relock_info_array[ i ].virtual_address += location_delta;
				}
			}
		}

		if ( ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
		{
			for ( auto ptr_import_descriptor = rc<PIMAGE_IMPORT_DESCRIPTOR>( ptr_base + ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );
				  ptr_import_descriptor->Name;
				  ptr_import_descriptor++ )
			{
				const auto import_module_handle = _LoadLibraryA( rc<char*>( ptr_base + ptr_import_descriptor->Name ) );

				auto ptr_original_thunk = rc<PIMAGE_THUNK_DATA>( ptr_base + ptr_import_descriptor->OriginalFirstThunk );
				auto ptr_first_thunk	= rc<PIMAGE_THUNK_DATA>( ptr_base + ptr_import_descriptor->FirstThunk );

				if ( !ptr_original_thunk )
					ptr_original_thunk = ptr_first_thunk;

				for ( ; ptr_original_thunk->u1.AddressOfData; ptr_original_thunk++, ptr_first_thunk++ )
				{
					if ( IMAGE_SNAP_BY_ORDINAL( ptr_original_thunk->u1.Ordinal ) )
					{
						ptr_first_thunk->u1.Function = rc<uintptr_t>( _GetProcAddress( import_module_handle, rc<char*>( ptr_original_thunk->u1.Ordinal & 0xFFFF ) ) );
						continue;
					}
					
					ptr_first_thunk->u1.Function = rc<uintptr_t>( _GetProcAddress( import_module_handle, rc<PIMAGE_IMPORT_BY_NAME>( ptr_base + ptr_original_thunk->u1.ForwarderString )->Name ) );
				}
			}
		}

		if ( ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].Size )
		{
			const auto ptr_tls_directory = rc<PIMAGE_TLS_DIRECTORY>( ptr_base + ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].VirtualAddress );
			const auto ptr_tls_callbacks = rc<PIMAGE_TLS_CALLBACK*>( ptr_tls_directory->AddressOfCallBacks );
			
			for ( auto i = 0; ptr_tls_callbacks[ i ]; i++ )
				ptr_tls_callbacks[ i ]( ptr_base, DLL_PROCESS_ATTACH, nullptr );
		}

		if ( ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ].Size )
		{
			const auto ptr_exception	= rc<PRUNTIME_FUNCTION>( ptr_base + ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ].VirtualAddress );
			const auto entry_count		= ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ].Size / sizeof( RUNTIME_FUNCTION );
			
			_RtlAddFunctionTable( ptr_exception, entry_count, rc<uintptr_t>( ptr_base ) );
		}

		_DllMain( ptr_base, DLL_PROCESS_ATTACH, nullptr );

		return;
	}

	const auto return_address = get_rip( );

	ptr_mapper_data->return_address = rc<uintptr_t>( return_address );
}
	
bool injection_methods::manual_map( File* ptr_file, PEParser* ptr_peparser, DWORD process_id )
{
	const auto h_proc = OpenProcess( PROCESS_ALL_ACCESS, false, process_id );
	if ( !h_proc )
		return false;

	if ( !utils::is_process_x64( h_proc ) )
	{
		CloseHandle( h_proc );

		return false;
	}

	printf( xorstr( "\nThe process is a valid x64 Process\nAllocating Dll at the target Process" ).c_str( ) );

	auto ptr_ex_image_base = rc<char*>( VirtualAllocEx( h_proc, rc<void*>( ptr_peparser->get_image_base( ) ),
											ptr_peparser->get_image_size( ), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE ) );
	if ( !ptr_ex_image_base )
	{
		ptr_ex_image_base = rc<char*>( VirtualAllocEx( h_proc, nullptr, ptr_peparser->get_image_size( ),
									   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE ) );
		if ( !ptr_ex_image_base )
		{
			CloseHandle( h_proc );

			return false;
		}
	}

	auto ptr_section_header = ptr_peparser->get_first_section_header( );
	for ( auto i = 0; i < ptr_peparser->get_number_of_sections( ); i++, ptr_section_header++ )
	{
		if ( !ptr_section_header || !ptr_section_header->SizeOfRawData )
			continue;

		if ( !WriteProcessMemory( h_proc, ptr_ex_image_base + ptr_section_header->VirtualAddress,
			 ptr_file->get_file_base_address( ) + ptr_section_header->PointerToRawData,
			 ptr_section_header->SizeOfRawData, nullptr ) )
		{
			VirtualFreeEx( h_proc, ptr_ex_image_base, NULL, MEM_RELEASE );

			CloseHandle( h_proc );

			return false;
		}
	}

	if ( !WriteProcessMemory( h_proc, ptr_ex_image_base, ptr_file->get_file_base_address( ), ptr_peparser->get_file_headers_size( ), nullptr ) )
	{
		VirtualFreeEx( h_proc, ptr_ex_image_base, NULL, MEM_RELEASE );

		CloseHandle( h_proc );

		return false;
	}

	printf( xorstr( "\nDll allocated at %p\nAllocating mapper shellcode at the target Process" ).c_str( ), ptr_ex_image_base );

	MAPPER_DATA mapper_data;
	ZeroMemory( &mapper_data, sizeof( MAPPER_DATA ) );

	injected_shellcode( &mapper_data );

	const auto shellcode_size = mapper_data.return_address - rc<uintptr_t>( injected_shellcode );

	auto ptr_ex_shellcode = rc<char*>( VirtualAllocEx( h_proc, nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
	if ( !ptr_ex_shellcode )
	{
		VirtualFreeEx( h_proc, ptr_ex_image_base, NULL, MEM_RELEASE );

		CloseHandle( h_proc );

		return false;
	}

	if ( !WriteProcessMemory( h_proc, ptr_ex_shellcode, injected_shellcode, shellcode_size, nullptr ) )
	{
		VirtualFreeEx( h_proc, ptr_ex_shellcode, NULL, MEM_RELEASE );

		VirtualFreeEx( h_proc, ptr_ex_image_base, NULL, MEM_RELEASE );

		CloseHandle( h_proc );

		return false;
	}

	printf( xorstr( "\nShellcode allocated at %p\nPassing data to target process" ).c_str( ), ptr_ex_shellcode );

	mapper_data.base_address			= rc<uintptr_t>( ptr_ex_image_base );

	mapper_data._LoadLibraryA			= LoadLibraryA;
	mapper_data._GetProcAddress			= GetProcAddress;
	mapper_data._RtlAddFunctionTable	= RtlAddFunctionTable;

	auto ptr_ex_mapper_data = rc<char*>( VirtualAllocEx( h_proc, nullptr, sizeof( MAPPER_DATA ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
	if ( !ptr_ex_mapper_data )
	{
		VirtualFreeEx( h_proc, ptr_ex_shellcode, NULL, MEM_RELEASE );

		VirtualFreeEx( h_proc, ptr_ex_image_base, NULL, MEM_RELEASE );

		CloseHandle( h_proc );

		return false;
	}

	if ( !WriteProcessMemory( h_proc, ptr_ex_mapper_data, &mapper_data, sizeof( MAPPER_DATA ), nullptr ) )
	{
		VirtualFreeEx( h_proc, ptr_ex_mapper_data, NULL, MEM_RELEASE );

		VirtualFreeEx( h_proc, ptr_ex_shellcode, NULL, MEM_RELEASE );

		VirtualFreeEx( h_proc, ptr_ex_image_base, NULL, MEM_RELEASE );

		CloseHandle( h_proc );

		return false;
	}

	printf( xorstr( "\nData allocated at 0x%p\nCreating remote thread" ).c_str( ), ptr_ex_mapper_data );

	auto h_thread = CreateRemoteThread( h_proc, nullptr, NULL, rc<PTHREAD_START_ROUTINE>( ptr_ex_shellcode ), ptr_ex_mapper_data, NULL, nullptr );
	if ( !h_thread )
	{
		VirtualFreeEx( h_proc, ptr_ex_shellcode, NULL, MEM_RELEASE );

		VirtualFreeEx( h_proc, ptr_ex_image_base, NULL, MEM_RELEASE );

		CloseHandle( h_proc );

		return false;
	}

	printf( xorstr( "\nWaiting for thread to end" ).c_str( ) );

	WaitForSingleObject( h_thread, INFINITE );

	printf( xorstr( "\nThread just finished!\nCleaning up" ).c_str( ) );

	CloseHandle( h_thread );
	
	VirtualFreeEx( h_proc, ptr_ex_mapper_data, NULL, MEM_RELEASE );

	VirtualFreeEx( h_proc, ptr_ex_shellcode, NULL, MEM_RELEASE );

	CloseHandle( h_proc );

	return true;
}