#pragma once

class File
{
	std::ifstream	m_FileStream;
	bool			m_bIsOpen;
	char			m_FilePath[ MAX_PATH + 1 ];
	char*			m_pBaseAddress;
	size_t			m_Size;

	bool open	( std::ios_base::openmode open_mode );
	void close	( );

	public:
	File( const char* file_path )
	{
		strcpy_s( m_FilePath, file_path );

		m_pBaseAddress	= nullptr;
		m_Size			= NULL;
		m_bIsOpen		= false;
	}

	~File( )
	{
		if ( m_pBaseAddress )
			delete[] m_pBaseAddress;

		this->close( );
	}
	
	bool	read_file				( );
	bool	get_file_open_state		( ) { return m_bIsOpen; };
	char*	get_file_base_address	( ) { return m_pBaseAddress; };
	size_t	get_file_size			( )	{ return m_Size; };
};