#pragma once

struct SUP_HEADER
{
	uint32_t cookie;
	uint32_t session_cookie;	// 0x4
	uint32_t input_size;		// 0x8
	uint32_t output_size;		// 0xC
	uint32_t flags;			    // 0x10
	int32_t  status_code;		// 0x14
}; // sizeof 0x18

struct SUP_COOKIE
{
	SUP_HEADER header;

	union
	{
		struct
		{
			char 	 magic_word[ 0x10 ];// 0x18
			uint32_t requested_version; // 0x28
			uint32_t min_version;	    // 0x2C
		} in;
		struct
		{
			uint32_t cookie;	      // 0x18
			uint32_t session_cookie;  // 0x1C
			uint32_t session_version; // 0x20
			uint32_t driver_version;  // 0x24
			uint32_t num_functions;   // 0x28
			uint64_t ptr_session;     // 0x30
		} out;
	};
};

struct SUP_LDR_OPEN
{
	SUP_HEADER header;

	union
	{
		struct
		{
			uint32_t image_size; 	     // 0x18
			char     image_name[ 0x20 ]; // 0x1C
			char     padding[ 0x4 ];     // 0x3C
		} in;
		struct
		{
			uint64_t image_base;	   // 0x18
			bool     requires_loading; // 0x20
		} out;
	};
};

struct SUP_LDR_FREE
{
	SUP_HEADER header;

	union
	{
		struct
		{
			uint64_t cpl0_image_base;
		} in;
	};
};

enum ENUM_SUP_LDR_LOAD_EP_TYPE
{
	SUP_LDR_LOAD_EP_NOTHING = 0,
	SUP_LDR_LOAD_EP_VMMR0,
	SUP_LDR_LOAD_EP_SERVICE,
	SUP_LDR_LOAD_EP_32BIT_HACK = 0x7FFFFFFF
};

struct SUP_SET_VM_FOR_FAST
{
	SUP_HEADER header;

	union
	{
		struct
		{
			uint64_t vm_handle_cpl0;
		} in;
	};
};

struct SUP_LDR_LOAD
{
	SUP_HEADER header;

	union
	{
		struct
		{
			uint64_t module_init;
			uint64_t module_term;

			union
			{
				struct
				{
					uint64_t module_handle_cpl0;
					uint64_t module_entry_cpl0;
					uint64_t module_entry_fast_cpl0;
					uint64_t module_entry_ex_cpl0;
				} cpl0;
			} entry;

			uint64_t 		          image_base;
			ENUM_SUP_LDR_LOAD_EP_TYPE entrypoint_type;
			uint32_t        	      offset_symbol_table;
			uint32_t                  size_symbols;
			uint32_t                  offset_string_table;
			uint32_t                  size_string_table;
			uint32_t        	      image_size;
			char*                     image_data;
		} in;
	};
};

// Default Values
//
#define SUP_INITIAL_COOKIE 0x69726F74
#define SUP_DEFAULT_FLAGS  0x42000042

// IOCTLS
//
#define SUP_IOCTL_COOKIE          0x228204
#define SUP_IOCTL_LDR_OPEN        0x228214
#define SUP_IOCTL_LDR_LOAD        0x228218
#define SUP_IOCTL_SET_VM_FOR_FAST 0x22824C
#define SUP_IOCTL_LDR_FREE        0x22821C
#define SUP_IOCTL_FAST_DO_NOP     0x22830B

class IVBox
{
	HANDLE m_hDriver = INVALID_HANDLE_VALUE;

	SUP_HEADER m_header;

	public:
	bool open( );
	bool close( );

	bool      begin_session( );
	uintptr_t allocate_ldr( size_t ldr_size );
	bool      load_ldr( uintptr_t ldr_base, uintptr_t* ptr_data, size_t data_size );
	bool      set_vm_for_fast( );
	NTSTATUS  run_entry( );
	bool      free_ldr( uintptr_t ldr_base );
};