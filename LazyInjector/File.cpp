#include "includes.h"

bool File::open( std::ios_base::openmode open_mode )
{
	if ( !m_DllPath || m_bIsOpen )
		return false;

	m_DllStream.open( m_DllPath, open_mode | std::ifstream::ate ); // add std::ifstream::ate so we can get file size

	m_bIsOpen = m_DllStream.is_open( );
	
	if ( !m_bIsOpen )
		return false;

	m_Size = m_DllStream.tellg( );
	
	if ( !( open_mode & std::ifstream::ate ) )						// if std::ifstream::ate on open_mode than dont reset the pointer
		m_DllStream.seekg( 0 );

	return true;
}

void File::close( )
{
	if ( !m_bIsOpen )
		return;
	
	m_DllStream.close( );

	m_bIsOpen = false;
	m_Size = NULL;
}

bool File::read_file( )
{
	if ( !this->open( std::ifstream::binary ) )
		return false;

	m_pBaseAddress = new char[ m_Size ];

	m_DllStream.read( m_pBaseAddress, m_Size );

	if ( !m_DllStream )
	{
		delete m_pBaseAddress;

		this->close( );

		return false;
	}

	return true;
}