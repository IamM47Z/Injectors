#include "includes.h"

bool PEParser::parse( )
{
	if ( m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return false;

	m_pNtHeaders = rc<PIMAGE_NT_HEADERS>( rc<uintptr_t>( m_pDosHeader ) + m_pDosHeader->e_lfanew );

	if ( m_pNtHeaders->Signature != IMAGE_NT_SIGNATURE )
		return false;

	m_bInitialized = true;

	return true;
}

uintptr_t PEParser::get_rva_from_va( uintptr_t virtual_address, uintptr_t base )
{
	if ( !m_bInitialized )
		return NULL;

	auto ptr_section_header = this->get_first_section_header( );
	for ( auto i = 0; i < this->get_number_of_sections( ); i++, ptr_section_header++ )
	{
		if ( !ptr_section_header || !ptr_section_header->SizeOfRawData ||
			 ptr_section_header->VirtualAddress > virtual_address ||
			 virtual_address > sc<uintptr_t>( ptr_section_header->VirtualAddress ) + ptr_section_header->SizeOfRawData )
			continue;

		return base + ( virtual_address - ptr_section_header->VirtualAddress ) + ptr_section_header->PointerToRawData;
	}

	return NULL;
}

uintptr_t PEParser::get_va_from_rva( uintptr_t relative_virtual_address, uintptr_t base )
{
	if ( !m_bInitialized )
		return NULL;

	auto ptr_section_header = this->get_first_section_header( );
	for ( auto i = 0; i < this->get_number_of_sections( ); i++, ptr_section_header++ )
	{
		if ( !ptr_section_header || !ptr_section_header->SizeOfRawData ||
			 ptr_section_header->PointerToRawData > relative_virtual_address ||
			 relative_virtual_address > sc<uintptr_t>( ptr_section_header->PointerToRawData ) + ptr_section_header->SizeOfRawData )
			continue;

		return base + ( relative_virtual_address - ptr_section_header->PointerToRawData ) + ptr_section_header->VirtualAddress;
	}

	return NULL;
}

PIMAGE_DATA_DIRECTORY PEParser::get_data_directory( uint8_t directory_id )
{
	if ( !m_bInitialized )
		return nullptr;

	return &( m_pNtHeaders->OptionalHeader.DataDirectory[ directory_id ] );
}