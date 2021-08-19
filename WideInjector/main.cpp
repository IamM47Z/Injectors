#include "includes.h"

int main( int argc, char* argv[] )
{
    HANDLE token;
    if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &token ) )
    {
        printf( xorstr( "\nError Opening Process Token" ).c_str( ) );

        PAUSE_EXIT( );

        return 1;
    }

    LUID luid;
    if ( !LookupPrivilegeValueW( nullptr, L"SeLoadDriverPrivilege", &luid ) )
    {
        printf( xorstr( "\nError Looking up For Privilege Value" ).c_str( ) );

        PAUSE_EXIT( );

        return 1;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[ 0 ].Luid = luid;
    tp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

    if ( !AdjustTokenPrivileges( token, FALSE, &tp, sizeof( TOKEN_PRIVILEGES ),
                                 ( PTOKEN_PRIVILEGES ) NULL, ( PDWORD ) NULL ) )
    {
        printf( xorstr( "\nError Adjusting Privileges" ).c_str( ) );

        PAUSE_EXIT( );

        return 1;
    }

    CloseHandle( token );

    auto info_in_commandline = false;
    if ( argc > 1 )
        info_in_commandline = true;

    srand( sc<unsigned int>( time( nullptr ) ) );

    utils::create_random_console_title( sc<size_t>( rand( ) % 50 ) + 1 );

    printf( xorstr( "WideInjector by M47Z\n\nUsage: wi.exe \"Path_to_Sys\"\n\tyou can also insert the values manually by opening wi.exe\n" ).c_str( ) );

    if ( !info_in_commandline )
        printf( xorstr( "\nInsert the path to the Sys: " ).c_str( ) );

    const auto file_path = info_in_commandline ? argv[ 1 ] : new char[ MAX_PATH ];

    if ( !info_in_commandline )
        scanf_s( "%[^\n]", file_path, MAX_PATH );

    const auto ptr_file = new File( file_path );

    if( !info_in_commandline )
        delete [ ] file_path;

    if ( !ptr_file->read_file( ) )
    {
        printf( xorstr( "\nError Checking and Reading Sys" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_file;

        return 1;
    }

    printf( xorstr( "\nChecking if the file is a valid x64 Sys" ).c_str( ) );

    const auto ptr_peparser = new PEParser( ptr_file->get_file_base_address( ) );

    if ( !ptr_peparser->parse( ) )
    {
        printf( xorstr( "\nError parsing the File" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    if ( !ptr_peparser->get_subsystem( ) ||
         ptr_peparser->get_machine( ) != IMAGE_FILE_MACHINE_AMD64 )
    {
        printf( xorstr( "\nThe file is Not a valid x64 Sys" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( xorstr( "\nThe file is a valid x64 Sys" ).c_str( ) );

    if ( !manual_map( ptr_file, ptr_peparser ) )
    {
        printf( xorstr( "\nError Mapping the Sys" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( xorstr( "\n\nFile successfully loaded!" ).c_str( ) );

    PAUSE_EXIT( );

    delete ptr_peparser;

    delete ptr_file;

    return 0;
}