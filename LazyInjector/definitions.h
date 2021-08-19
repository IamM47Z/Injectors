#ifndef _DEFINITIONS_
#define _DEFINITIONS_

#define sc					static_cast
#define rc					reinterpret_cast

#define PAUSE_EXIT( )		std::cout << xorstr( "\nPress Enter to Exit" ).c_str( ); \
							system( "pause>nul" );

#define PAUSE_CONTINUE( )	std::cout << xorstr( "\nPress Enter to Continue" ).c_str( ); \
							system( "pause>nul" );

extern "C" __declspec( noinline ) char* get_rip( );

#endif