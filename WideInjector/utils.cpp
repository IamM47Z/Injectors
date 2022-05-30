#include "includes.h"

char* utils::generate_string( size_t length )
{
    if ( length < 1 )
        length = 1;

    auto destination = new char[ length + 1 ];

    const char alfabeto [ ] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    for ( auto i = 0; i < length; i++ )
        destination[ i ] = alfabeto[ rand( ) % 63 ];

    destination[ length + 1 ] = '\0';

    return destination;
}

void utils::create_random_console_title( size_t length )
{
    const auto title = generate_string( length );

    auto title_cmd = new char[ length + 8 ];

    sprintf_s( title_cmd, length + 8, "title %s", title );

    system( title_cmd );

    delete [ ] title_cmd;

    delete [ ] title;
}

RTL_PROCESS_MODULE_INFORMATION utils::get_kernel_module_info( const char* module_name )
{
    ULONG required_size;
    NtQuerySystemInformation( sc<SYSTEM_INFORMATION_CLASS>( 0x0B ), nullptr, NULL, &required_size ); // 0xB -> SystemModuleInformation
    if ( !required_size )
        return { };
    
    auto ptr_buffer = rc<PRTL_PROCESS_MODULES>( VirtualAlloc( nullptr, required_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
    if ( !ptr_buffer )
        return { };

    auto ret_status = NtQuerySystemInformation( sc<SYSTEM_INFORMATION_CLASS>( 0x0B ), ptr_buffer, required_size, &required_size ); // 0xB -> SystemModuleInformation
    if ( ret_status == 0xC0000004 ) // 0xC0000004 -> STATUS_INFO_LENGTH_MISMATCH
    {
        VirtualFree( ptr_buffer, NULL, MEM_RELEASE );

        return utils::get_kernel_module_info( module_name );
    }

    if ( !NT_SUCCESS( ret_status ) )
    {
        VirtualFree( ptr_buffer, NULL, MEM_RELEASE );

        return { };
    }

    RTL_PROCESS_MODULE_INFORMATION module_info;

    for ( auto i = 0; i < ptr_buffer->NumberOfModules; i++ )
    {
        auto module = ptr_buffer->Modules[ i ];

        if ( _stricmp( rc<char*>( module.FullPathName + module.OffsetToFileName ), module_name ) )
            continue;
        
        module_info = module;
        break;
    }

    VirtualFree( ptr_buffer, NULL, MEM_RELEASE );

    return module_info;
}

std::string utils::convert_nt_path_to_dos_path( std::string nt_path )
{
    std::wstring ustr_nt_path( nt_path.begin(), nt_path.end() );

    UNICODE_STRING unicode_nt_path;
    RtlInitUnicodeString( &unicode_nt_path, ustr_nt_path.c_str( ) );

    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes( &object_attributes, &unicode_nt_path, OBJ_CASE_INSENSITIVE, NULL, NULL );

    HANDLE file_handle;
    IO_STATUS_BLOCK io_status;
    auto status = NtCreateFile( &file_handle, FILE_GENERIC_READ, &object_attributes, &io_status, nullptr, FILE_ATTRIBUTE_NORMAL, 
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, NULL, nullptr, NULL );
    if ( !NT_SUCCESS( status ) || io_status.Information != FILE_OPENED )
        return "";
    
    char dos_path[ MAX_PATH + 1 ];
    status = GetFinalPathNameByHandleA( file_handle, dos_path, MAX_PATH + 1, NULL );

    CloseHandle( file_handle );

    return status ? dos_path : "";
}

uintptr_t utils::get_kernel_module_function( const char* module_name, uint16_t function_ordinal, const char* function_name )
{
    if ( !module_name || ( !function_ordinal && !function_name ) )
        return NULL;

    const auto module = utils::get_kernel_module_info( module_name );
    if ( !module.ImageSize )
        return NULL;

    auto ptr_file = new File( utils::convert_nt_path_to_dos_path( rc<const char*>( module.FullPathName ) ).c_str( ) );
    if ( !ptr_file->read_file( ) )
    {
        delete ptr_file;

        return NULL;
    }

    auto ptr_peparser = new PEParser( ptr_file->get_file_base_address( ) );
    if ( !ptr_peparser->parse( ) )
    {
        delete ptr_peparser;

        delete ptr_file;

        return NULL;
    }

    auto ptr_export_directory = rc<PIMAGE_EXPORT_DIRECTORY>( 
        ptr_file->get_file_base_address( ) + ptr_peparser->get_rva_from_va( 
            ptr_peparser->get_data_directory( IMAGE_DIRECTORY_ENTRY_EXPORT )->VirtualAddress ) );
    if ( !ptr_export_directory )
    {
        delete ptr_peparser;

        delete ptr_file;

        return NULL;
    }

    const auto ptr_export_table = rc<uint32_t*>( ptr_file->get_file_base_address( ) + ptr_peparser->get_rva_from_va( ptr_export_directory->AddressOfFunctions ) );
    const auto ptr_name_offset = rc<uint32_t*>( ptr_file->get_file_base_address( ) + ptr_peparser->get_rva_from_va( ptr_export_directory->AddressOfNames ) );
    const auto ptr_ordinals = rc<uint16_t*>( ptr_file->get_file_base_address( ) + ptr_peparser->get_rva_from_va( ptr_export_directory->AddressOfNameOrdinals ) );

    if ( !function_ordinal )
        for ( auto i = 0; i < ptr_export_directory->NumberOfNames; i++ )
        {
            if ( _stricmp( rc<char*>( ptr_file->get_file_base_address( ) + ptr_peparser->get_rva_from_va( ptr_name_offset[ i ] ) ),
                           function_name ) )
                continue;

            function_ordinal = ptr_ordinals[ i ];
            break;
        }
    else
        function_ordinal -= 1; // turn ordinal into index in case it is aleardy specified

    auto function_address = rc<uintptr_t>( module.ImageBase ) + ptr_export_table[ function_ordinal ];

    delete ptr_peparser;

    delete ptr_file;

    return function_address;
}