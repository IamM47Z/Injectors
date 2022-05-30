#include "includes.h"

int main( int argc, char* argv[] )
{
    HANDLE token;
    if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &token ) )
    {
        printf( "\nError Opening Process Token" );

        PAUSE_EXIT( );

        return 1;
    }

    LUID luid;
    if ( !LookupPrivilegeValueW( nullptr, L"SeLoadDriverPrivilege", &luid ) )
    {
        printf( "\nError Looking up For Privilege Value" );

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
        printf( "\nError Adjusting Privileges" );

        PAUSE_EXIT( );

        return 1;
    }

    CloseHandle( token );

    auto info_in_commandline = false;
    if ( argc > 1 )
        info_in_commandline = true;

    srand( sc<unsigned int>( time( nullptr ) ) );

    utils::create_random_console_title( sc<size_t>( rand( ) % 50 ) + 1 );

    printf( "WideInjector by M47Z\n\nUsage: wi.exe \"Path_to_Sys\"\n\tyou can also insert the values manually by opening wi.exe\n" );

    if ( !info_in_commandline )
        printf( "\nInsert the path to the Sys: " );

    const auto file_path = info_in_commandline ? argv[ 1 ] : new char[ MAX_PATH ];

    if ( !info_in_commandline )
        scanf_s( "%[^\n]", file_path, MAX_PATH );

    const auto ptr_file = new File( file_path );

    if( !info_in_commandline )
        delete [ ] file_path;

    if ( !ptr_file->read_file( ) )
    {
        printf( "\nError Checking and Reading Sys" );

        PAUSE_EXIT( );

        delete ptr_file;

        return 1;
    }

    printf( "\nChecking if the file is a valid x64 Sys" );

    const auto ptr_peparser = new PEParser( ptr_file->get_file_base_address( ) );

    if ( !ptr_peparser->parse( ) )
    {
        printf( "\nError parsing the File" );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    if ( !ptr_peparser->get_subsystem( ) ||
         ptr_peparser->get_machine( ) != IMAGE_FILE_MACHINE_AMD64 )
    {
        printf( "\nThe file is Not a valid x64 Sys" );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( "\nThe file is a valid x64 Sys" );

    if ( !manual_map( ptr_file, ptr_peparser ) )
    {
        printf( "\nError Mapping the Sys" );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( "\n\nFile successfully loaded!" );

    PAUSE_EXIT( );

    delete ptr_peparser;

    delete ptr_file;

    return 0;
}