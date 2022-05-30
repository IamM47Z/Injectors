#include "includes.h"

bool loader::load_driver( uint8_t* driver, int size, const std::wstring path, const std::wstring service )
{
    std::ofstream file( ( path + service + L".sys" ).c_str( ), std::ios_base::out | std::ios_base::binary );
    file.write( rc< char* >( driver ), size );
    file.close( );

    auto service_error = 0, service_type = 1, service_startup_type = 1;

    auto service_group = std::wstring( L"Base" );
    auto service_image_path = L"\\??\\" + path + service + L".sys";

    HKEY services_key, service_key;
    auto status = RegOpenKeyW( HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", &services_key );
    if ( status )
        return false;

    status = RegCreateKeyW( services_key, service.c_str( ), &service_key );
    if ( status )
    {
        status = RegOpenKeyW( services_key, service.c_str( ), &service_key );
        if ( status )
        {
            RegCloseKey( services_key );
            return false;
        }

        RegCloseKey( service_key );

        status = RegDeleteKeyW( services_key, service.c_str( ) );
        if ( status )
        {
            RegCloseKey( services_key );
            return false;
        }

        status = RegCreateKeyW( services_key, service.c_str( ), &service_key );
        if ( status )
        {
            RegCloseKey( services_key );
            return false;
        }
    }

    status |= RegSetValueExW( service_key, L"DisplayName", 0, REG_SZ,
                              rc< const BYTE* >( service.c_str( ) ), ( service.length( ) + 1 ) * sizeof( WCHAR ) );
    status |= RegSetValueExW( service_key, L"ErrorControl", 0, REG_DWORD,
                              rc< const BYTE* >( &service_error ), sizeof( service_error ) );
    status |= RegSetValueExW( service_key, L"Group", 0, REG_SZ,
                              rc< const BYTE* >( service_group.c_str( ) ), ( service_group.length( ) + 1 ) * sizeof( WCHAR ) );
    status |= RegSetValueExW( service_key, L"ImagePath", 0, REG_SZ,
                              rc< const BYTE* >( service_image_path.c_str( ) ), ( service_image_path.length( ) + 1 ) * sizeof( WCHAR ) );
    status |= RegSetValueExW( service_key, L"Start", 0, REG_DWORD,
                              rc< const BYTE* >( &service_startup_type ), sizeof( service_startup_type ) );
    status |= RegSetValueExW( service_key, L"Type", 0, REG_DWORD,
                              rc< const BYTE* >( &service_type ), sizeof( service_type ) );

    RegCloseKey( service_key );
    RegCloseKey( services_key );

    if ( status )
        return false;

    auto reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service;

    UNICODE_STRING driver_path;
    RtlInitUnicodeString( &driver_path, reg_path.c_str( ) );

    status = ZwLoadDriver( &driver_path );

    return NT_SUCCESS( status );
}

bool loader::unload_driver( const std::wstring path, const std::wstring service )
{
    auto reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service;

    UNICODE_STRING driver_path;
    RtlInitUnicodeString( &driver_path, reg_path.c_str( ) );

    auto ret_status = ZwUnloadDriver( &driver_path );

    HKEY services_key;
    auto status = RegOpenKeyW( HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", &services_key );
    if ( status )
        return false;

    status = RegDeleteKeyW( services_key, service.c_str( ) );

    RegCloseKey( services_key );

    return DeleteFileW( ( path + service + L".sys" ).c_str( ) ) && !status && NT_SUCCESS( ret_status );
}