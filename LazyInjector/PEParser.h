#pragma once

class PEParser
{
	bool				m_bInitialized;
	char* m_pBaseAddress;
	PIMAGE_DOS_HEADER	m_pDosHeader;
	PIMAGE_NT_HEADERS	m_pNtHeaders;

	public:
	PEParser( char* ptr_base_address )
	{
		m_pBaseAddress = ptr_base_address;
		m_pDosHeader = rc<PIMAGE_DOS_HEADER>( ptr_base_address );
		m_pNtHeaders = nullptr;
		m_bInitialized = false;
	}

	bool parse( );

	PIMAGE_DOS_HEADER       get_dos_header( )
	{
		return m_bInitialized ? m_pDosHeader : nullptr;
	};
	PIMAGE_NT_HEADERS       get_nt_headers( )
	{
		return m_bInitialized ? m_pNtHeaders : nullptr;
	};
	bool                    get_subsystem( )
	{
		return m_bInitialized ? m_pNtHeaders->OptionalHeader.Subsystem : NULL;
	};
	WORD					get_file_characteristics( )
	{
		return m_bInitialized ? m_pNtHeaders->FileHeader.Characteristics : NULL;
	};
	WORD					get_machine( )
	{
		return m_bInitialized ? m_pNtHeaders->FileHeader.Machine : NULL;
	};
	uintptr_t				get_image_base( )
	{
		return m_bInitialized ? m_pNtHeaders->OptionalHeader.ImageBase : NULL;
	};
	size_t					get_image_size( )
	{
		return m_bInitialized ? m_pNtHeaders->OptionalHeader.SizeOfImage : NULL;
	};
	size_t					get_number_of_sections( )
	{
		return m_bInitialized ? m_pNtHeaders->FileHeader.NumberOfSections : NULL;
	};
	PIMAGE_SECTION_HEADER	get_first_section_header( )
	{
		return m_bInitialized ? rc<PIMAGE_SECTION_HEADER>( rc<uintptr_t>( m_pNtHeaders ) + sizeof( IMAGE_NT_HEADERS ) ) : NULL;
	};
	DWORD					get_file_headers_size( )
	{
		return m_bInitialized ? m_pNtHeaders->OptionalHeader.SizeOfHeaders : NULL;
	};

	uintptr_t             get_rva_from_va( uintptr_t virtual_address, uintptr_t base = NULL );
	uintptr_t             get_va_from_rva( uintptr_t relative_virtual_address, uintptr_t base = NULL );
	PIMAGE_DATA_DIRECTORY get_data_directory( uint8_t directory_id );
};