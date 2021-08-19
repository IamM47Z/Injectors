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

DWORD utils::get_process_id_by_name( const char* process_name )
{
    auto h_snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
    if ( h_snapshot == INVALID_HANDLE_VALUE )
        return NULL;

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof( process_entry );

    if ( !Process32First( h_snapshot, &process_entry ) )
        return NULL;

    do 
    {
        if ( _stricmp( process_entry.szExeFile, process_name ) )
            continue;

        CloseHandle( h_snapshot );

        return process_entry.th32ProcessID;
    } while ( Process32Next( h_snapshot, &process_entry ) );

    CloseHandle( h_snapshot );

    return NULL;
}

bool utils::is_process_x64( HANDLE h_proc )
{
    bool is_wow64;
    return IsWow64Process( h_proc, rc<BOOL*>( &is_wow64 ) ) && !is_wow64;
}