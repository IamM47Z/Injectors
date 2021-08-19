#pragma once

namespace utils
{
    char*   generate_string             ( size_t length );
    void    create_random_console_title ( size_t length );
    DWORD   get_process_id_by_name      ( const char* process_name );
    bool    is_process_x64              ( HANDLE h_proc );
}