#ifndef _DEFINITIONS_
#define _DEFINITIONS_

#define sc					static_cast
#define rc					reinterpret_cast

#define PAUSE_EXIT( )		std::cout << "\nPress Enter to Exit"; \
							system( "pause>nul" );

#define PAUSE_CONTINUE( )	std::cout << "\nPress Enter to Continue"; \
							system( "pause>nul" );

extern "C" __declspec( noinline ) char* get_rip( );

#endif