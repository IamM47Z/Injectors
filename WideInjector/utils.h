#pragma once

namespace utils
{
    char*                          generate_string             ( size_t length );
    void                           create_random_console_title ( size_t length );
    RTL_PROCESS_MODULE_INFORMATION get_kernel_module_info      ( const char* module_name );
    std::string                    convert_nt_path_to_dos_path ( std::string nt_path );
    uintptr_t                      get_kernel_module_function  ( const char* module_name, uint16_t function_ordinal = NULL, const char* function_name = nullptr );
}