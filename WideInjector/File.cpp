#include "includes.h"

bool File::open( std::ios_base::openmode open_mode )
{
	if ( !m_FilePath || m_bIsOpen )
		return false;

	m_FileStream.open( m_FilePath, open_mode | std::ifstream::ate ); // add std::ifstream::ate so we can get file size

	m_bIsOpen = m_FileStream.is_open( );
	
	if ( !m_bIsOpen )
		return false;

	m_Size = m_FileStream.tellg( );
	
	if ( !( open_mode & std::ifstream::ate ) )						// if std::ifstream::ate on open_mode than dont reset the pointer
		m_FileStream.seekg( 0 );

	return true;
}

void File::close( )
{
	if ( !m_bIsOpen )
		return;
	
	m_FileStream.close( );

	m_bIsOpen = false;
	m_Size = NULL;
}

bool File::read_file( )
{
	if ( !this->open( std::ifstream::binary ) )
		return false;

	m_pBaseAddress = new char[ m_Size ];

	m_FileStream.read( m_pBaseAddress, m_Size );

	if ( !m_FileStream )
	{
		delete m_pBaseAddress;

		this->close( );

		return false;
	}

	return true;
}