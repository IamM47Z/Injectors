#include "includes.h"

int main( int argc, char* argv[] )
{
    auto info_in_commandline = false;
    if ( argc > 2 )
        info_in_commandline = true;

    srand( sc<unsigned int>( time( nullptr ) ) );

    utils::create_random_console_title( sc<size_t>( rand( ) % 50 ) + 1 );

    printf( xorstr( "LazyInjector by M47Z\n\nUsage: li.exe \"Path_to_Dll\" \"Process_name\"\n\tyou can also insert the values manually by opening li.exe\n" ).c_str( ) );

    if ( !info_in_commandline )
        printf( xorstr( "\nInsert the path to the Dll: " ).c_str( ) );

    const auto dll_path = info_in_commandline ? argv[ 1 ] : new char[ MAX_PATH ];

    if ( !info_in_commandline )
        scanf_s( "%[^\n]", dll_path, MAX_PATH );

    const auto ptr_file = new File( dll_path );

    if( !info_in_commandline )
        delete [ ] dll_path;

    if ( !ptr_file->read_file( ) )
    {
        printf( xorstr( "\nError Checking and Reading Dll" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_file;

        return 1;
    }

    printf( xorstr( "\nChecking if the file is a valid x64 Dll" ).c_str( ) );

    const auto ptr_peparser = new PEParser( ptr_file->get_file_base_address( ) );

    if ( !ptr_peparser->parse( ) )
    {
        printf( xorstr( "\nError parsing the Dll" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    if ( !( ptr_peparser->get_file_characteristics( ) & IMAGE_FILE_DLL ) ||
         ptr_peparser->get_machine( ) != IMAGE_FILE_MACHINE_AMD64 )
    {
        printf( xorstr( "\nThe file is Not a valid Dll" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( xorstr( "\nThe file is a valid x64 Dll" ).c_str( ) );

    if ( !info_in_commandline )
        printf( xorstr( "\n\nInsert the name of the process: " ).c_str( ) );

    const auto process_name = info_in_commandline ? argv[ 2 ] : new char[ MAX_PATH ];

    if ( !info_in_commandline )
        scanf_s( "%s", process_name, MAX_PATH );

    auto process_id = utils::get_process_id_by_name( process_name );
    if ( !process_id )
    {
        printf( xorstr( "\nThe process is not running\n\nDo you want to wait for the process to Start? ( 0 - No ): " ).c_str( ) );

        auto wait_for_process = NULL;

        scanf_s( "%d", &wait_for_process );

        if ( !wait_for_process )
        {
            PAUSE_EXIT( );

            if ( !info_in_commandline )
                delete [ ] process_name;

            delete ptr_peparser;

            delete ptr_file;

            return 0;
        }

        printf( xorstr( "\nWaiting for %s to start..." ).c_str( ), process_name );

        while ( !process_id )
        {
            process_id = utils::get_process_id_by_name( process_name );
            Sleep( 100 );
        }
    }

    printf( xorstr( "\nProcess %s Started!\nPID: %d" ).c_str( ), process_name, process_id );

    if ( !info_in_commandline )
        delete [ ] process_name;

    if ( !injection_methods::manual_map( ptr_file, ptr_peparser, process_id ) )
    {
        printf( xorstr( "\nError Mapping the Dll" ).c_str( ) );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( xorstr( "\n\nDll successfully injected!" ).c_str( ) );

    PAUSE_EXIT( );

    delete ptr_peparser;

    delete ptr_file;

    return 0;
}