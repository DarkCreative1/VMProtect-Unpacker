#include "module/decompression.hxx"
#include "module/decompression2.hxx"
#include "module/lifter.hxx"

#include "module/static_iat.hxx"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

auto read_file( const char* path ) -> std::vector< std::uint8_t >
{
    std::ifstream in( path, std::ios::binary );
    if ( !in )
        throw std::runtime_error( std::string( "failed to open " ) + path );

    in.seekg( 0, std::ios::end );
    const auto size = static_cast< std::size_t >( in.tellg( ) );
    in.seekg( 0, std::ios::beg );

    std::vector< std::uint8_t > buf( size );
    if ( size && !in.read( reinterpret_cast< char* >( buf.data( ) ), static_cast< std::streamsize >( size ) ) )
        throw std::runtime_error( std::string( "failed to read " ) + path );

    return buf;
}

auto write_file( const char* path, const std::vector< std::uint8_t >& buf ) -> void
{
    std::ofstream out( path, std::ios::binary );
    if ( !out )
        throw std::runtime_error( std::string( "failed to create " ) + path );

    if ( !buf.empty( ) && !out.write( reinterpret_cast< const char* >( buf.data( ) ), static_cast< std::streamsize >( buf.size( ) ) ) )
        throw std::runtime_error( std::string( "failed to write " ) + path );
}

auto parse_u32_opt( int argc, char** argv, const char* name, std::uint32_t fallback ) -> std::uint32_t
{
    for ( int i = 1; i + 1 < argc; ++i )
    {
        if ( !std::strcmp( argv[ i ], name ) )
            return static_cast< std::uint32_t >( std::strtoul( argv[ i + 1 ], nullptr, 10 ) );
    }
    return fallback;
}

auto main( int argc, char** argv ) -> int
{
    auto runtime = false;
    auto decompress_only = false;
    auto lift = false;
    auto strip_vmp = false;
    auto pid = 0u;
    auto vmenter = 0ull;
    auto max_ops = 256ull;
    const char* module_name = nullptr;
    std::vector< const char* > pos;
    for ( int i = 1; i < argc; ++i )
    {
        if ( !std::strcmp( argv[ i ], "--runtime" ) )
        {
            runtime = true;
            continue;
        }
        if ( !std::strcmp( argv[ i ], "--decompress-only" ) )
        {
            decompress_only = true;
            continue;
        }
        if ( !std::strcmp( argv[ i ], "--lift" ) )
        {
            lift = true;
            continue;
        }
        if ( !std::strcmp( argv[ i ], "--strip-vmp" ) )
        {
            strip_vmp = true;
            continue;
        }
        if ( !std::strcmp( argv[ i ], "--wait" ) || !std::strcmp( argv[ i ], "--pid" ) ||
            !std::strcmp( argv[ i ], "--module" ) || !std::strcmp( argv[ i ], "--vmenter" ) ||
            !std::strcmp( argv[ i ], "--max-ops" ) )
        {
            if ( i + 1 < argc )
            {
                if ( !std::strcmp( argv[ i ], "--pid" ) )
                    pid = static_cast< std::uint32_t >( std::strtoul( argv[ i + 1 ], nullptr, 10 ) );
                else if ( !std::strcmp( argv[ i ], "--module" ) )
                    module_name = argv[ i + 1 ];
                else if ( !std::strcmp( argv[ i ], "--vmenter" ) )
                    vmenter = std::strtoull( argv[ i + 1 ], nullptr, 0 );
                else if ( !std::strcmp( argv[ i ], "--max-ops" ) )
                    max_ops = std::strtoull( argv[ i + 1 ], nullptr, 0 );
                ++i;
            }
            continue;
        }
        pos.push_back( argv[ i ] );
    }

    if ( ( pid && pos.size( ) < 1 ) || ( lift && pos.size( ) < 1 ) || ( !pid && !lift && pos.size( ) < 2 ) )
    {
        std::printf( "usage: %s [--decompress-only] [--strip-vmp] <in> <out>\n", argv[ 0 ] );
        std::printf( "       %s --runtime [--wait ms] [--strip-vmp] <in> <out>\n", argv[ 0 ] );
        std::printf( "       %s --pid <pid> [--module name] [--strip-vmp] <out>\n", argv[ 0 ] );
        std::printf( "       %s --lift [--vmenter va] [--max-ops n] <in> [outdir]\n", argv[ 0 ] );
        return 1;
    }

    try
    {
        if ( pid )
        {
            const auto dumped = dump_pid_and_fix( pid, module_name, strip_vmp );
            write_file( pos[ 0 ], dumped );
            std::printf( "dumped %zu bytes\n", dumped.size( ) );
            return 0;
        }

        if ( runtime )
        {
            const auto wait_ms = parse_u32_opt( argc, argv, "--wait", 15000 );
            const auto dumped = dump_and_fix( pos[ 0 ], wait_ms, strip_vmp );
            write_file( pos[ 1 ], dumped );
            std::printf( "dumped %zu bytes\n", dumped.size( ) );
            return 0;
        }

        if ( lift )
        {
            const auto file = read_file( pos[ 0 ] );
            const auto report = lift_vm( file, vmenter, static_cast< std::size_t >( max_ops ) );
            const auto dir = pos.size( ) >= 2 ? std::string( pos[ 1 ] ) : ( std::string( pos[ 0 ] ) + ".lift" );
            write_lift_report( dir, report );
            std::printf( "%s\n", report.summary.c_str( ) );
            std::printf( "wrote lift report to %s\n", dir.c_str( ) );
            const auto n = report.vmenters.size( ) < 16 ? report.vmenters.size( ) : 16;
            for ( std::size_t i = 0; i < n; ++i )
            {
                const auto& s = report.vmenters[ i ];
                const char* kind = "pushfq";
                if ( s.kind == vmenter_kind::push_imm )
                    kind = "push_imm";
                else if ( s.kind == vmenter_kind::push_call )
                    kind = "push_call";
                else if ( s.kind == vmenter_kind::pdata )
                    kind = "pdata";
                std::printf( "  %-8s va=0x%llx rva=0x%x score=%d %s\n",
                    kind,
                    static_cast< unsigned long long >( s.va ),
                    s.rva,
                    s.score,
                    s.note.c_str( ) );
            }
            return 0;
        }

        const auto packed = read_file( pos[ 0 ] );
        const auto unpacked = unpack_pe( packed );
        if ( unpacked.empty( ) )
        {
            std::printf( "failed\n" );
            return 1;
        }

        if ( decompress_only )
        {
            write_file( pos[ 1 ], unpacked );
            std::printf( "decompressed %zu bytes (IAT recovery skipped)\n", unpacked.size( ) );
            return 0;
        }

        try
        {
            const auto wait_ms = parse_u32_opt( argc, argv, "--wait", 180000 );
            auto image = initialize_static_imports( packed, unpacked, wait_ms );
            auto fixed = rebuild_iat( image, strip_vmp );
            write_file( pos[ 1 ], fixed );
            std::printf( "unpacked and rebuilt IAT, %zu bytes\n", fixed.size( ) );
        }
        catch ( const std::exception& ex )
        {
            throw std::runtime_error( std::string( "offline IAT recovery failed: " ) + ex.what( ) +
                "; use --decompress-only to save the decompressed image or --runtime for live recovery" );
        }
        return 0;
    }
    catch ( const std::exception& ex )
    {
        std::printf( "failed: %s\n", ex.what( ) );
        return 1;
    }
}
