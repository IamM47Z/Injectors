#include "includes.h"

int main( int argc, char* argv[] )
{
    auto info_in_commandline = false;
    if ( argc > 2 )
        info_in_commandline = true;

    srand( sc<unsigned int>( time( nullptr ) ) );

    utils::create_random_console_title( sc<size_t>( rand( ) % 50 ) + 1 );

    printf( "LazyInjector by M47Z\n\nUsage: li.exe \"Path_to_Dll\" \"Process_name\"\n\tyou can also insert the values manually by opening li.exe\n" );

    if ( !info_in_commandline )
        printf( "\nInsert the path to the Dll: " );

    const auto dll_path = info_in_commandline ? argv[ 1 ] : new char[ MAX_PATH ];

    if ( !info_in_commandline )
        scanf_s( "%[^\n]", dll_path, MAX_PATH );

    const auto ptr_file = new File( dll_path );

    if( !info_in_commandline )
        delete [ ] dll_path;

    if ( !ptr_file->read_file( ) )
    {
        printf( "\nError Checking and Reading Dll" );

        PAUSE_EXIT( );

        delete ptr_file;

        return 1;
    }

    printf( "\nChecking if the file is a valid x64 Dll" );

    const auto ptr_peparser = new PEParser( ptr_file->get_file_base_address( ) );

    if ( !ptr_peparser->parse( ) )
    {
        printf( "\nError parsing the Dll" );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    if ( !( ptr_peparser->get_file_characteristics( ) & IMAGE_FILE_DLL ) ||
         ptr_peparser->get_machine( ) != IMAGE_FILE_MACHINE_AMD64 )
    {
        printf( "\nThe file is Not a valid Dll" );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( "\nThe file is a valid x64 Dll" );

    if ( !info_in_commandline )
        printf( "\n\nInsert the name of the process: " );

    const auto process_name = info_in_commandline ? argv[ 2 ] : new char[ MAX_PATH ];

    if ( !info_in_commandline )
        scanf_s( "%s", process_name, MAX_PATH );

    auto process_id = utils::get_process_id_by_name( process_name );
    if ( !process_id )
    {
        printf( "\nThe process is not running\n\nDo you want to wait for the process to Start? ( 0 - No ): " );

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

        printf( "\nWaiting for %s to start...", process_name );

        while ( !process_id )
        {
            process_id = utils::get_process_id_by_name( process_name );
            Sleep( 100 );
        }
    }

    printf( "\nProcess %s Started!\nPID: %d", process_name, process_id );

    if ( !info_in_commandline )
        delete [ ] process_name;

    if ( !injection_methods::manual_map( ptr_file, ptr_peparser, process_id ) )
    {
        printf( "\nError Mapping the Dll" );

        PAUSE_EXIT( );

        delete ptr_peparser;

        delete ptr_file;

        return 1;
    }

    printf( "\n\nDll successfully injected!" );

    PAUSE_EXIT( );

    delete ptr_peparser;

    delete ptr_file;

    return 0;
}