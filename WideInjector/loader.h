#pragma once

namespace loader
{
    bool load_driver( uint8_t* driver, int size, const std::wstring path, const std::wstring service );

    bool unload_driver( const std::wstring path, const std::wstring service );
}