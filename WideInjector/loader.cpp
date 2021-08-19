#include "includes.h"

bool loader::load_driver( uint8_t* driver, int size, const std::wstring path, const std::wstring service )
{
    std::ofstream file( ( path + service + xorstr( L".sys" ).c_str( ) ).c_str( ), std::ios_base::out | std::ios_base::binary );
    file.write( rc< char* >( driver ), size );
    file.close( );

    auto service_error = 0, service_type = 1, service_startup_type = 1;

    auto service_group = std::wstring( xorstr( L"Base" ).c_str( ) );
    auto service_image_path = xorstr( L"\\??\\" ).c_str( ) + path + service + xorstr( L".sys" ).c_str( );

    HKEY services_key, service_key;
    auto status = RegOpenKeyW( HKEY_LOCAL_MACHINE, xorstr( L"System\\CurrentControlSet\\Services" ).c_str( ), &services_key );
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

    status |= RegSetValueExW( service_key, xorstr( L"DisplayName" ).c_str( ), 0, REG_SZ,
                              rc< const BYTE* >( service.c_str( ) ), ( service.length( ) + 1 ) * sizeof( WCHAR ) );
    status |= RegSetValueExW( service_key, xorstr( L"ErrorControl" ).c_str( ), 0, REG_DWORD,
                              rc< const BYTE* >( &service_error ), sizeof( service_error ) );
    status |= RegSetValueExW( service_key, xorstr( L"Group" ).c_str( ), 0, REG_SZ,
                              rc< const BYTE* >( service_group.c_str( ) ), ( service_group.length( ) + 1 ) * sizeof( WCHAR ) );
    status |= RegSetValueExW( service_key, xorstr( L"ImagePath" ).c_str( ), 0, REG_SZ,
                              rc< const BYTE* >( service_image_path.c_str( ) ), ( service_image_path.length( ) + 1 ) * sizeof( WCHAR ) );
    status |= RegSetValueExW( service_key, xorstr( L"Start" ).c_str( ), 0, REG_DWORD,
                              rc< const BYTE* >( &service_startup_type ), sizeof( service_startup_type ) );
    status |= RegSetValueExW( service_key, xorstr( L"Type" ).c_str( ), 0, REG_DWORD,
                              rc< const BYTE* >( &service_type ), sizeof( service_type ) );

    RegCloseKey( service_key );
    RegCloseKey( services_key );

    if ( status )
        return false;

    auto reg_path = xorstr( L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ).c_str( ) + service;

    UNICODE_STRING driver_path;
    RtlInitUnicodeString( &driver_path, reg_path.c_str( ) );

    status = ZwLoadDriver( &driver_path );

    return NT_SUCCESS( status );
}

bool loader::unload_driver( const std::wstring path, const std::wstring service )
{
    auto reg_path = xorstr( L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ).c_str( ) + service;

    UNICODE_STRING driver_path;
    RtlInitUnicodeString( &driver_path, reg_path.c_str( ) );

    auto ret_status = ZwUnloadDriver( &driver_path );

    HKEY services_key;
    auto status = RegOpenKeyW( HKEY_LOCAL_MACHINE, xorstr( L"System\\CurrentControlSet\\Services" ).c_str( ), &services_key );
    if ( status )
        return false;

    status = RegDeleteKeyW( services_key, service.c_str( ) );

    RegCloseKey( services_key );

    return DeleteFileW( ( path + service + xorstr( L".sys" ).c_str( ) ).c_str( ) ) && !status && NT_SUCCESS( ret_status );
}