#include "lifter.hxx"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    constexpr auto k_page = 0x1000ull;
    constexpr auto k_stack_va = 0x00007fff00000000ull;
    constexpr auto k_stack_size = 0x200000ull;
    constexpr auto k_max_insns = 16384u;
    constexpr auto k_gpr_n = 16;

    const char* k_gpr[ k_gpr_n ] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };

    const int k_uc_gpr[ k_gpr_n ] = {
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
    };

    auto fail( const char* op, uc_err err ) -> std::runtime_error
    {
        return std::runtime_error( std::string( op ) + ": " + uc_strerror( err ) );
    }

    auto hex64( std::uint64_t v ) -> std::string
    {
        char b[ 32 ];
        std::snprintf( b, sizeof( b ), "0x%llx", static_cast< unsigned long long >( v ) );
        return b;
    }

    auto read_u16( const std::uint8_t* p ) -> std::uint16_t
    {
        std::uint16_t v;
        std::memcpy( &v, p, 2 );
        return v;
    }

    auto read_u32( const std::uint8_t* p ) -> std::uint32_t
    {
        std::uint32_t v;
        std::memcpy( &v, p, 4 );
        return v;
    }

    auto read_u64( const std::uint8_t* p ) -> std::uint64_t
    {
        std::uint64_t v;
        std::memcpy( &v, p, 8 );
        return v;
    }

    auto lower8( const char* s ) -> std::string
    {
        char n[ 9 ]{};
        if ( !s )
            return {};
        for ( auto i = 0; i < 8 && s[ i ]; ++i )
            n[ i ] = static_cast< char >( ::tolower( static_cast< unsigned char >( s[ i ] ) ) );
        return n;
    }

    auto is_std_sec( const std::string& n ) -> bool
    {
        return n == ".text" || n == ".rdata" || n == ".data" || n == ".pdata" || n == ".rsrc" ||
            n == ".reloc" || n == ".idata" || n == ".edata" || n == ".bss" || n == ".tls" ||
            n == ".debug" || n == ".gfids" || n == ".retplne" || n == ".00cfg";
    }

    auto is_vm_name( const char* name ) -> bool
    {
        const auto s = lower8( name );
        if ( s.rfind( ".vmp", 0 ) == 0 || s == ".be0" || s == ".be1" || s == ".byted" )
            return true;
        return s.size( ) >= 2 && s[ 0 ] == '.' && !is_std_sec( s );
    }

    struct sec
    {
        char name[ 9 ];
        std::uint32_t va;
        std::uint32_t vsz;
        std::uint32_t raw;
        std::uint32_t rsz;
        std::uint32_t ch;
        bool vm;
        bool exec;
    };

    struct pe_view
    {
        const std::uint8_t* file;
        std::size_t file_n;
        std::uint64_t base;
        std::uint32_t entry;
        std::uint32_t image_size;
        std::vector< sec > secs;
        std::vector< std::uint8_t > image;
        bool is64;
    };
    auto parse_pe( const std::vector< std::uint8_t >& file ) -> pe_view
    {
        pe_view p{};
        p.file = file.data( );
        p.file_n = file.size( );
        if ( file.size( ) < 0x40 )
            throw std::runtime_error( "file is too small to be a PE" );
        const auto nt = read_u32( file.data( ) + 0x3c );
        if ( nt + 24 >= file.size( ) || read_u32( file.data( ) + nt ) != 0x4550 )
            throw std::runtime_error( "invalid PE signature" );
        const auto magic = read_u16( file.data( ) + nt + 24 );
        p.is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        if ( !p.is64 )
            throw std::runtime_error( "VM lifter currently supports AMD64 only" );
        const auto opt = nt + 24;
        p.entry = read_u32( file.data( ) + opt + 16 );
        p.base = read_u64( file.data( ) + opt + 24 );
        p.image_size = read_u32( file.data( ) + opt + 56 );
        const auto nsec = read_u16( file.data( ) + nt + 6 );
        const auto optsz = read_u16( file.data( ) + nt + 20 );
        const auto secoff = nt + 24 + optsz;
        if ( !nsec || nsec > 96 )
            throw std::runtime_error( "invalid section count" );
        for ( std::uint16_t i = 0; i < nsec; ++i )
        {
            const auto off = secoff + i * 40u;
            if ( off + 40 > file.size( ) )
                break;
            sec s{};
            std::memcpy( s.name, file.data( ) + off, 8 );
            s.vsz = read_u32( file.data( ) + off + 8 );
            s.va = read_u32( file.data( ) + off + 12 );
            s.rsz = read_u32( file.data( ) + off + 16 );
            s.raw = read_u32( file.data( ) + off + 20 );
            s.ch = read_u32( file.data( ) + off + 36 );
            s.exec = ( s.ch & IMAGE_SCN_MEM_EXECUTE ) != 0;
            s.vm = is_vm_name( s.name );
            p.secs.push_back( s );
        }
        auto named_vm = false;
        for ( const auto& s : p.secs )
            named_vm = named_vm || ( s.vm && s.exec );
        if ( !named_vm )
        {
            for ( auto& s : p.secs )
            {
                if ( s.exec && lower8( s.name ) != ".text" )
                    s.vm = true;
            }
        }
        auto span = static_cast< std::size_t >( p.image_size );
        if ( span < 0x1000 )
            span = 0x1000;
        p.image.assign( span, 0 );
        const auto hdr = ( std::min )( static_cast< std::size_t >( read_u32( file.data( ) + opt + 60 ) ), file.size( ) );
        std::memcpy( p.image.data( ), file.data( ), ( std::min )( hdr, p.image.size( ) ) );
        for ( const auto& s : p.secs )
        {
            if ( !s.rsz || s.raw >= file.size( ) )
                continue;
            const auto room = p.image.size( ) > s.va ? p.image.size( ) - s.va : 0;
            const auto n = ( std::min )( { static_cast< std::size_t >( s.rsz ), file.size( ) - s.raw, room } );
            if ( n )
                std::memcpy( p.image.data( ) + s.va, file.data( ) + s.raw, n );
        }
        return p;
    }

    auto in_vm( const pe_view& p, std::uint64_t va ) -> bool
    {
        if ( va < p.base )
            return false;
        const auto rva = static_cast< std::uint32_t >( va - p.base );
        for ( const auto& s : p.secs )
        {
            const auto sp = s.vsz > s.rsz ? s.vsz : s.rsz;
            if ( s.vm && rva >= s.va && rva < s.va + sp )
                return true;
        }
        return false;
    }

    auto in_code( const pe_view& p, std::uint64_t va ) -> bool
    {
        if ( va < p.base )
            return false;
        const auto rva = static_cast< std::uint32_t >( va - p.base );
        for ( const auto& s : p.secs )
        {
            const auto sp = s.vsz > s.rsz ? s.vsz : s.rsz;
            if ( s.exec && rva >= s.va && rva < s.va + sp )
                return true;
        }
        return false;
    }

    auto gpr_from_zy( ZydisRegister r ) -> int
    {
        switch ( r )
        {
        case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH: case ZYDIS_REGISTER_AX:
        case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_RAX: return 0;
        case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH: case ZYDIS_REGISTER_CX:
        case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_RCX: return 1;
        case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH: case ZYDIS_REGISTER_DX:
        case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_RDX: return 2;
        case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH: case ZYDIS_REGISTER_BX:
        case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_RBX: return 3;
        case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_SP:
        case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_RSP: return 4;
        case ZYDIS_REGISTER_BPL: case ZYDIS_REGISTER_BP:
        case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_RBP: return 5;
        case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_SI:
        case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_RSI: return 6;
        case ZYDIS_REGISTER_DIL: case ZYDIS_REGISTER_DI:
        case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_RDI: return 7;
        case ZYDIS_REGISTER_R8B: case ZYDIS_REGISTER_R8W:
        case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8: return 8;
        case ZYDIS_REGISTER_R9B: case ZYDIS_REGISTER_R9W:
        case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9: return 9;
        case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R10W:
        case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10: return 10;
        case ZYDIS_REGISTER_R11B: case ZYDIS_REGISTER_R11W:
        case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11: return 11;
        case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R12W:
        case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12: return 12;
        case ZYDIS_REGISTER_R13B: case ZYDIS_REGISTER_R13W:
        case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13: return 13;
        case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R14W:
        case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14: return 14;
        case ZYDIS_REGISTER_R15B: case ZYDIS_REGISTER_R15W:
        case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15: return 15;
        default: return -1;
        }
    }


    struct decoded
    {
        bool ok;
        std::uint8_t len;
        ZydisMnemonic mnemonic;
        ZydisDecodedOperand ops[ ZYDIS_MAX_OPERAND_COUNT ];
        ZyanU8 op_count;
        std::uint64_t abs0;
        bool has_abs0;
        ZydisDecodedInstruction insn;
    };

    auto decode_va( const pe_view& p, std::uint64_t va ) -> decoded
    {
        decoded d{};
        if ( va < p.base )
            return d;
        const auto rva = static_cast< std::uint32_t >( va - p.base );
        if ( rva >= p.image.size( ) )
            return d;
        ZydisDecoder dec;
        if ( !ZYAN_SUCCESS( ZydisDecoderInit( &dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64 ) ) )
            return d;
        if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( &dec, p.image.data( ) + rva, p.image.size( ) - rva, &d.insn, d.ops ) ) )
            return d;
        d.ok = true;
        d.len = d.insn.length;
        d.mnemonic = d.insn.mnemonic;
        d.op_count = d.insn.operand_count_visible;
        if ( d.op_count && ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &d.insn, &d.ops[ 0 ], va, &d.abs0 ) ) )
            d.has_abs0 = true;
        return d;
    }

    auto score_prologue( const pe_view& p, std::uint64_t va ) -> int
    {
        auto score = 0;
        auto pushes = 0;
        auto fq = false;
        auto extra_fq = 0;
        auto xfer = false;
        auto vm_xfer = false;
        auto movabs = false;
        auto junk = false;
        auto cur = va;
        for ( auto i = 0; i < 16; ++i )
        {
            const auto d = decode_va( p, cur );
            if ( !d.ok )
                break;
            if ( d.mnemonic == ZYDIS_MNEMONIC_PUSH )
            {
                ++pushes;
                score += 4;
            }
            else if ( d.mnemonic == ZYDIS_MNEMONIC_PUSHFQ )
            {
                if ( fq )
                    ++extra_fq;
                fq = true;
                score += 12;
            }
            else if ( d.mnemonic == ZYDIS_MNEMONIC_MOV || d.mnemonic == ZYDIS_MNEMONIC_LEA )
            {
                score += 2;
                if ( d.op_count > 1 && d.ops[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    d.ops[ 1 ].imm.value.u > 0xffffffffull )
                    movabs = true;
            }
            else if ( d.mnemonic == ZYDIS_MNEMONIC_CALL || d.mnemonic == ZYDIS_MNEMONIC_JMP )
            {
                xfer = true;
                if ( d.has_abs0 && in_vm( p, d.abs0 ) )
                {
                    const auto dist = d.abs0 > cur ? d.abs0 - cur : cur - d.abs0;
                    if ( dist >= 0x40 )
                    {
                        vm_xfer = true;
                        score += 30;
                    }
                }
                else if ( d.op_count && d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER )
                    score += 8;
                break;
            }
            else if ( d.mnemonic == ZYDIS_MNEMONIC_RET || d.mnemonic == ZYDIS_MNEMONIC_INT3 )
            {
                score -= 20;
                break;
            }
            else if ( fq && ( d.mnemonic == ZYDIS_MNEMONIC_ADC || d.mnemonic == ZYDIS_MNEMONIC_SBB ||
                d.mnemonic == ZYDIS_MNEMONIC_OR ) )
            {
                junk = true;
            }
            cur += d.len;
        }
        if ( pushes >= 1 && fq )
            score += 12;
        if ( movabs && vm_xfer )
            score += 20;
        if ( extra_fq )
            score -= extra_fq * 25;
        if ( junk )
            score -= 40;
        if ( !vm_xfer )
            score /= 4;
        if ( !xfer && pushes < 1 )
            score /= 2;
        if ( score < 0 )
            score = 0;
        if ( score > 100 )
            score = 100;
        return score;
    }


    auto add_site( std::vector< vmenter_site >& out, const pe_view& p, std::uint64_t va, vmenter_kind kind, int score, const char* note ) -> void
    {
        if ( !in_code( p, va ) )
            return;
        for ( const auto& s : out )
        {
            if ( ( s.va & ~0xfull ) == ( va & ~0xfull ) )
                return;
        }
        vmenter_site st{};
        st.va = va;
        st.rva = static_cast< std::uint32_t >( va - p.base );
        st.kind = kind;
        st.score = score;
        st.note = note;
        out.push_back( st );
    }

    auto scan_sites( const pe_view& p ) -> std::vector< vmenter_site >
    {
        std::vector< vmenter_site > out;
        add_site( out, p, p.base + p.entry, vmenter_kind::pdata, score_prologue( p, p.base + p.entry ), "entry" );

        const auto nt = read_u32( p.file + 0x3c );
        const auto opt = nt + 24;
        const auto ex_rva = read_u32( p.file + opt + 112 + 24 );
        const auto ex_sz = read_u32( p.file + opt + 112 + 28 );
        if ( ex_rva && ex_sz && ( ex_sz % 12 ) == 0 && ex_rva < p.image.size( ) )
        {
            const auto n = ex_sz / 12;
            for ( std::uint32_t i = 0; i < n; ++i )
            {
                const auto off = ex_rva + i * 12;
                if ( off + 4 > p.image.size( ) )
                    break;
                const auto va = p.base + read_u32( p.image.data( ) + off );
                const auto sc = score_prologue( p, va );
                if ( sc >= 30 )
                    add_site( out, p, va, vmenter_kind::pdata, sc, "pdata" );
            }
        }

        for ( const auto& s : p.secs )
        {
            if ( !s.exec )
                continue;
            const auto start = p.base + s.va;
            const auto span = s.rsz ? s.rsz : s.vsz;
            if ( !span )
                continue;
            const auto limit = s.vm ? ( std::min )( span, 0x400000u ) : ( std::min )( span, 0x20000u );
            for ( std::uint32_t i = 0; i + 8 < limit; ++i )
            {
                const auto rva = s.va + i;
                if ( rva >= p.image.size( ) )
                    break;
                const auto b0 = p.image[ rva ];
                const auto b1 = p.image[ rva + 1 ];
                auto kind = vmenter_kind::pushfq;
                auto base_score = 0;
                if ( b0 == 0x9c )
                    base_score = 50;
                else if ( b0 >= 0x50 && b0 <= 0x57 && b1 == 0x9c )
                    base_score = 55;
                else if ( b0 == 0x41 && b1 >= 0x50 && b1 <= 0x57 && rva + 2 < p.image.size( ) && p.image[ rva + 2 ] == 0x9c )
                    base_score = 58;
                else if ( b0 == 0x68 || b0 == 0x6a )
                {
                    kind = vmenter_kind::push_imm;
                    base_score = 40;
                }
                else
                    continue;
                const auto va = start + i;
                const auto sc = score_prologue( p, va );
                if ( sc < 40 )
                    continue;
                auto conf = base_score + sc / 2;
                if ( !s.vm )
                    conf += 8;
                if ( conf > 95 )
                    conf = 95;
                add_site( out, p, va, kind, conf, s.vm ? "vmsec" : "text" );
            }
        }

        std::sort( out.begin( ), out.end( ), [ ]( const vmenter_site& a, const vmenter_site& b )
        {
            if ( a.score != b.score )
                return a.score > b.score;
            return a.va < b.va;
        } );
        if ( out.size( ) > 64 )
            out.resize( 64 );
        return out;
    }


    auto read_reg( uc_engine* uc, int id ) -> std::uint64_t
    {
        std::uint64_t v = 0;
        uc_reg_read( uc, id, &v );
        return v;
    }

    auto write_reg( uc_engine* uc, int id, std::uint64_t v ) -> void
    {
        uc_reg_write( uc, id, &v );
    }

    auto mem_op_addr( uc_engine* uc, const ZydisDecodedOperand& op ) -> std::uint64_t
    {
        std::uint64_t addr = static_cast< std::uint64_t >( op.mem.disp.value );
        const auto base = gpr_from_zy( op.mem.base );
        if ( base >= 0 )
            addr += read_reg( uc, k_uc_gpr[ base ] );
        const auto idx = gpr_from_zy( op.mem.index );
        if ( idx >= 0 )
            addr += read_reg( uc, k_uc_gpr[ idx ] ) * ( op.mem.scale ? op.mem.scale : 1 );
        return addr;
    }

    auto looks_code( const pe_view& p, std::uint64_t va ) -> bool
    {
        if ( !in_code( p, va ) )
            return false;
        const auto rva = static_cast< std::uint32_t >( va - p.base );
        if ( rva + 2 >= p.image.size( ) )
            return false;
        auto nz = 0;
        for ( auto i = 0; i < 4 && rva + i < p.image.size( ); ++i )
        {
            const auto b = p.image[ rva + i ];
            if ( b && b != 0xcc )
                ++nz;
        }
        return nz >= 1;
    }

    struct effect
    {
        std::uint64_t handler;
        std::uint64_t vip_before;
        std::uint64_t vip_after;
        std::uint64_t key_before;
        std::uint64_t key_after;
        std::int64_t vsp_delta;
        std::optional< std::uint64_t > next;
        std::optional< std::uint64_t > pushed;
        std::vector< lift_fetch > fetches;
        int alu_add, alu_sub, alu_xor, alu_and, alu_or, alu_not, alu_neg, alu_shl, alu_shr;
        int mem_load, mem_store, pushes, pops;
        bool xfer;
        bool ret_exit;
        vm_op kind;
        int conf;
        std::string why;
    };

    auto peel( effect& e ) -> void
    {
        if ( e.ret_exit && !e.xfer )
        {
            e.kind = vm_op::vmexit;
            e.conf = 90;
            e.why = "ret/vmexit";
            return;
        }
        if ( e.vsp_delta == -8 && !e.fetches.empty( ) )
        {
            e.kind = vm_op::push;
            e.conf = 80;
            e.why = "vsp-8 + vip fetch";
            return;
        }
        if ( e.vsp_delta == 8 && e.mem_load == 0 && e.mem_store == 0 )
        {
            e.kind = vm_op::pop;
            e.conf = 70;
            e.why = "vsp+8";
            return;
        }
        if ( e.mem_load && e.vsp_delta == 0 )
        {
            e.kind = vm_op::load;
            e.conf = 65;
            e.why = "mem load";
            return;
        }
        if ( e.mem_store && e.vsp_delta <= -8 )
        {
            e.kind = vm_op::store;
            e.conf = 65;
            e.why = "mem store";
            return;
        }
        const auto alu = e.alu_add + e.alu_sub + e.alu_xor + e.alu_and + e.alu_or + e.alu_not + e.alu_neg + e.alu_shl + e.alu_shr;
        if ( alu && e.vsp_delta == 8 )
        {
            if ( e.alu_add ) e.kind = vm_op::add;
            else if ( e.alu_sub ) e.kind = vm_op::sub;
            else if ( e.alu_xor ) e.kind = vm_op::xor_;
            else if ( e.alu_and ) e.kind = vm_op::and_;
            else if ( e.alu_or ) e.kind = vm_op::or_;
            else if ( e.alu_not ) e.kind = vm_op::not_;
            else if ( e.alu_neg ) e.kind = vm_op::neg;
            else if ( e.alu_shl ) e.kind = vm_op::shl;
            else if ( e.alu_shr ) e.kind = vm_op::shr;
            e.conf = 75;
            e.why = "alu + vsp pop";
            return;
        }
        if ( !e.fetches.empty( ) && e.vsp_delta == 0 )
        {
            e.kind = vm_op::fetch;
            e.conf = 60;
            e.why = "vip fetch";
            return;
        }
        if ( e.xfer )
        {
            e.kind = vm_op::calc_jmp;
            e.conf = 55;
            e.why = "handler xfer";
            return;
        }
        e.kind = vm_op::unknown;
        e.conf = 0;
        e.why = "unclassified";
    }


    struct walk_st
    {
        const pe_view* pe;
        uc_engine* uc;
        std::uint64_t handler;
        std::uint64_t next;
        std::uint64_t vip;
        std::uint64_t key;
        std::uint64_t vsp;
        int vip_reg;
        int key_reg;
        int vsp_reg;
        int steps;
        int vip_reads;
        bool hit;
        bool saw_ret;
        bool stop;
        effect* cur;
    };

    auto hook_code( uc_engine* uc, std::uint64_t addr, std::uint32_t size, void* user ) -> void
    {
        auto* st = static_cast< walk_st* >( user );
        ++st->steps;
        if ( st->steps > static_cast< int >( k_max_insns ) )
        {
            st->stop = true;
            uc_emu_stop( uc );
            return;
        }
        if ( st->hit )
            return;
        decoded d{};
        if ( addr >= st->pe->base )
        {
            const auto rva = static_cast< std::uint32_t >( addr - st->pe->base );
            if ( rva < st->pe->image.size( ) )
            {
                ZydisDecoder dec;
                ZydisDecoderInit( &dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64 );
                if ( ZYAN_SUCCESS( ZydisDecoderDecodeFull( &dec, st->pe->image.data( ) + rva, st->pe->image.size( ) - rva, &d.insn, d.ops ) ) )
                {
                    d.ok = true;
                    d.len = d.insn.length;
                    d.mnemonic = d.insn.mnemonic;
                    d.op_count = d.insn.operand_count_visible;
                }
            }
        }
        if ( !d.ok )
            return;
        if ( st->cur )
        {
            switch ( d.mnemonic )
            {
            case ZYDIS_MNEMONIC_ADD: case ZYDIS_MNEMONIC_ADC: ++st->cur->alu_add; break;
            case ZYDIS_MNEMONIC_SUB: case ZYDIS_MNEMONIC_SBB: ++st->cur->alu_sub; break;
            case ZYDIS_MNEMONIC_XOR: ++st->cur->alu_xor; break;
            case ZYDIS_MNEMONIC_AND: ++st->cur->alu_and; break;
            case ZYDIS_MNEMONIC_OR: ++st->cur->alu_or; break;
            case ZYDIS_MNEMONIC_NOT: ++st->cur->alu_not; break;
            case ZYDIS_MNEMONIC_NEG: ++st->cur->alu_neg; break;
            case ZYDIS_MNEMONIC_SHL: ++st->cur->alu_shl; break;
            case ZYDIS_MNEMONIC_SHR: case ZYDIS_MNEMONIC_SAR: ++st->cur->alu_shr; break;
            case ZYDIS_MNEMONIC_PUSH: ++st->cur->pushes; break;
            case ZYDIS_MNEMONIC_POP: ++st->cur->pops; break;
            default: break;
            }
            if ( d.op_count )
            {
                if ( d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY )
                    ++st->cur->mem_store;
                if ( d.op_count > 1 && d.ops[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY )
                    ++st->cur->mem_load;
            }
        }
        if ( d.mnemonic == ZYDIS_MNEMONIC_RET )
        {
            st->saw_ret = true;
            const auto rsp = read_reg( uc, UC_X86_REG_RSP );
            std::uint64_t ret = 0;
            uc_mem_read( uc, rsp, &ret, 8 );
            if ( looks_code( *st->pe, ret ) && ret != st->handler && ( in_vm( *st->pe, ret ) || in_code( *st->pe, ret ) ) )
            {
                const auto dist = ret > addr ? ret - addr : addr - ret;
                if ( dist >= 0x80 )
                {
                    st->next = ret;
                    st->hit = true;
                    st->stop = true;
                    uc_emu_stop( uc );
                    return;
                }
            }
            if ( !in_vm( *st->pe, ret ) )
            {
                if ( st->cur )
                    st->cur->ret_exit = true;
                st->stop = true;
                uc_emu_stop( uc );
            }
            return;
        }
        if ( ( d.mnemonic == ZYDIS_MNEMONIC_JMP || d.mnemonic == ZYDIS_MNEMONIC_CALL ) && d.op_count )
        {
            std::uint64_t tgt = 0;
            auto indirect = false;
            if ( d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER )
            {
                const auto g = gpr_from_zy( d.ops[ 0 ].reg.value );
                if ( g >= 0 )
                    tgt = read_reg( uc, k_uc_gpr[ g ] );
                indirect = true;
            }
            else if ( d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY )
            {
                tgt = mem_op_addr( uc, d.ops[ 0 ] );
                if ( d.ops[ 0 ].mem.base != ZYDIS_REGISTER_RIP && d.ops[ 0 ].mem.base != ZYDIS_REGISTER_NONE )
                    indirect = true;
            }
            if ( !indirect || !tgt )
                return;
            if ( st->vip_reg >= 0 )
            {
                const auto vip = read_reg( uc, k_uc_gpr[ st->vip_reg ] );
                if ( tgt == vip || tgt == st->vip )
                    return;
            }
            if ( looks_code( *st->pe, tgt ) && tgt != st->handler && ( in_vm( *st->pe, tgt ) || in_code( *st->pe, tgt ) ) )
            {
                const auto dist = tgt > addr ? tgt - addr : addr - tgt;
                if ( dist < 0x80 )
                    return;
                if ( addr < st->handler || addr - st->handler > 8 )
                {
                    st->next = tgt;
                    st->hit = true;
                    st->stop = true;
                    uc_emu_stop( uc );
                }
            }
        }
    }


    auto hook_mem( uc_engine* uc, uc_mem_type type, std::uint64_t addr, int size, std::int64_t, void* user ) -> void
    {
        auto* st = static_cast< walk_st* >( user );
        if ( type != UC_MEM_READ || !st->cur )
            return;
        if ( size <= 0 || size > 8 )
            return;
        if ( in_vm( *st->pe, addr ) && addr != st->handler && ( addr < st->handler || addr - st->handler > 0x40 ) )
        {
            auto src = -1;
            for ( auto i = 0; i < k_gpr_n; ++i )
            {
                if ( i == 4 )
                    continue;
                if ( read_reg( uc, k_uc_gpr[ i ] ) == addr )
                {
                    src = i;
                    break;
                }
            }
            if ( src >= 0 && size <= 4 )
            {
                auto base_ptr = false;
                for ( auto i = 0; i < k_gpr_n; ++i )
                {
                    if ( i == 4 || i == src )
                        continue;
                    const auto v = read_reg( uc, k_uc_gpr[ i ] );
                    if ( v && addr >= v && addr < v + 0x20 )
                    {
                        base_ptr = true;
                        if ( st->vip_reg < 0 )
                            st->vip_reg = i;
                        break;
                    }
                }
                if ( !base_ptr && st->vip_reg < 0 )
                    st->vip_reg = src;
                if ( st->vip_reg >= 0 )
                {
                    const auto vip = read_reg( uc, k_uc_gpr[ st->vip_reg ] );
                    if ( addr < vip || addr >= vip + 0x40 )
                        return;
                }
                lift_fetch f{};
                f.addr = addr;
                f.size = static_cast< std::uint32_t >( size );
                std::uint64_t enc = 0;
                uc_mem_read( uc, addr, &enc, static_cast< std::size_t >( size ) );
                f.enc = enc;
                if ( st->key )
                {
                    f.dec = static_cast< std::uint32_t >( enc ) ^ static_cast< std::uint32_t >( st->key );
                    f.decrypted = true;
                    if ( !st->cur->pushed )
                        st->cur->pushed = f.dec;
                }
                st->cur->fetches.push_back( f );
                ++st->vip_reads;
                st->vip = addr;
                if ( st->vip_reg < 0 )
                    st->vip_reg = src;
            }
        }
        if ( st->vsp_reg < 0 )
        {
            for ( auto i = 0; i < k_gpr_n; ++i )
            {
                if ( i == 4 )
                    continue;
                const auto v = read_reg( uc, k_uc_gpr[ i ] );
                if ( v >= k_stack_va && v < k_stack_va + k_stack_size && addr >= v && addr < v + 0x80 )
                {
                    st->vsp_reg = i;
                    st->vsp = v;
                    break;
                }
            }
        }
    }

    auto hook_unmap( uc_engine* uc, uc_mem_type, std::uint64_t addr, int, std::int64_t, void* ) -> bool
    {
        const auto page = addr & ~( k_page - 1 );
        return uc_mem_map( uc, page, static_cast< std::size_t >( k_page ), UC_PROT_ALL ) == UC_ERR_OK;
    }

    auto guess_context( walk_st& st ) -> void
    {
        std::uint64_t g[ k_gpr_n ];
        for ( auto i = 0; i < k_gpr_n; ++i )
            g[ i ] = read_reg( st.uc, k_uc_gpr[ i ] );
        const auto rsp = g[ 4 ];

        if ( st.vsp_reg < 0 )
        {
            for ( auto i = 0; i < k_gpr_n; ++i )
            {
                if ( i == 4 )
                    continue;
                if ( g[ i ] >= k_stack_va && g[ i ] < k_stack_va + k_stack_size && g[ i ] != rsp )
                {
                    st.vsp_reg = i;
                    st.vsp = g[ i ];
                    break;
                }
            }
        }

        if ( st.vip_reg < 0 )
        {
            auto best = -1;
            auto best_hits = -1;
            for ( auto i = 0; i < k_gpr_n; ++i )
            {
                if ( i == 4 || i == st.vsp_reg || i == 9 )
                    continue;
                if ( !g[ i ] )
                    continue;
                if ( g[ i ] == st.handler || g[ i ] == st.next )
                    continue;
                if ( in_code( *st.pe, g[ i ] ) && !in_vm( *st.pe, g[ i ] ) )
                    continue;
                auto hits = 0;
                for ( const auto& f : st.cur ? st.cur->fetches : std::vector< lift_fetch >{ } )
                {
                    if ( f.addr >= g[ i ] && f.addr < g[ i ] + 0x20 )
                        ++hits;
                }
                const auto in_image = in_code( *st.pe, g[ i ] ) || in_vm( *st.pe, g[ i ] );
                if ( !in_image && hits == 0 )
                    continue;
                if ( hits > best_hits || ( hits == best_hits && in_image && best >= 0 && !in_code( *st.pe, g[ best ] ) ) )
                {
                    best = i;
                    best_hits = hits;
                }
            }
            if ( best >= 0 )
            {
                st.vip_reg = best;
                st.vip = g[ best ];
            }
        }

        if ( st.key_reg < 0 )
        {
            for ( auto i = 0; i < k_gpr_n; ++i )
            {
                if ( i == 4 || i == st.vip_reg || i == st.vsp_reg )
                    continue;
                if ( g[ i ] && g[ i ] <= 0xffffffffull && g[ i ] > 0xff && !in_vm( *st.pe, g[ i ] ) )
                {
                    st.key_reg = i;
                    st.key = g[ i ];
                    break;
                }
            }
        }
        if ( st.vip_reg >= 0 )
            st.vip = g[ st.vip_reg ];
        if ( st.vsp_reg >= 0 )
            st.vsp = g[ st.vsp_reg ];
        if ( st.key_reg >= 0 )
            st.key = g[ st.key_reg ];
    }


    auto map_image( uc_engine* uc, const pe_view& p ) -> void
    {
        const auto span = ( static_cast< std::uint64_t >( p.image.size( ) ) + k_page - 1 ) & ~( k_page - 1 );
        auto err = uc_mem_map( uc, p.base, static_cast< std::size_t >( span ), UC_PROT_ALL );
        if ( err != UC_ERR_OK )
            throw fail( "uc_mem_map image", err );
        err = uc_mem_write( uc, p.base, p.image.data( ), p.image.size( ) );
        if ( err != UC_ERR_OK )
            throw fail( "uc_mem_write image", err );
        err = uc_mem_map( uc, k_stack_va, static_cast< std::size_t >( k_stack_size ), UC_PROT_ALL );
        if ( err != UC_ERR_OK )
            throw fail( "uc_mem_map stack", err );
    }

    auto emit_vasm( const lift_report& r ) -> std::string
    {
        std::ostringstream o;
        o << "; vmenter " << hex64( r.vmenter_va ) << "\n";
        o << "; vip_reg=" << r.vip_reg << " vsp_reg=" << r.vsp_reg << " key_reg=" << r.key_reg << "\n";
        o << "; initial_vip=" << hex64( r.initial_vip ) << " key=" << hex64( r.rolling_key ) << "\n";
        o << "; ops=" << r.ops.size( ) << " classified=" << r.classified << " unknown=" << r.unknown << "\n\n";
        for ( const auto& op : r.ops )
        {
            o << "  " << op.mnemonic;
            if ( op.imm )
                o << "  imm=" << hex64( *op.imm );
            if ( op.vip )
                o << "  vip=" << hex64( op.vip );
            o << "  @" << hex64( op.handler_va ) << "  conf=" << op.confidence;
            if ( op.semantic )
                o << "  [sem]";
            if ( !op.comment.empty( ) )
                o << "  ; " << op.comment;
            o << "\n";
            if ( op.next )
                o << "       -> " << hex64( *op.next ) << "\n";
        }
        return o.str( );
    }

    auto emit_c( const lift_report& r ) -> std::string
    {
        std::ostringstream o;
        o << "/* lifted from " << hex64( r.vmenter_va ) << " */\n";
        o << "#include <stdint.h>\n\n";
        o << "void recovered(void) {\n";
        o << "  uint64_t vsp[512]; int top = 0;\n";
        for ( const auto& op : r.ops )
        {
            switch ( op.kind )
            {
            case vm_op::vmenter:
                break;
            case vm_op::vmexit:
                o << "  return;\n";
                break;
            case vm_op::push:
            case vm_op::fetch:
                if ( op.imm )
                    o << "  vsp[top++] = " << hex64( *op.imm ) << "ull;\n";
                else
                    o << "  vsp[top++] = 0;\n";
                break;
            case vm_op::pop:
                o << "  if (top) --top;\n";
                break;
            case vm_op::add:
                o << "  if (top >= 2) { vsp[top-2] += vsp[top-1]; --top; }\n";
                break;
            case vm_op::sub:
                o << "  if (top >= 2) { vsp[top-2] -= vsp[top-1]; --top; }\n";
                break;
            case vm_op::xor_:
                o << "  if (top >= 2) { vsp[top-2] ^= vsp[top-1]; --top; }\n";
                break;
            case vm_op::and_:
                o << "  if (top >= 2) { vsp[top-2] &= vsp[top-1]; --top; }\n";
                break;
            case vm_op::or_:
                o << "  if (top >= 2) { vsp[top-2] |= vsp[top-1]; --top; }\n";
                break;
            case vm_op::nor:
                o << "  if (top >= 2) { vsp[top-2] = ~(vsp[top-2] | vsp[top-1]); --top; }\n";
                break;
            case vm_op::shl:
                o << "  if (top >= 2) { vsp[top-2] <<= (vsp[top-1] & 63); --top; }\n";
                break;
            case vm_op::shr:
                o << "  if (top >= 2) { vsp[top-2] >>= (vsp[top-1] & 63); --top; }\n";
                break;
            case vm_op::not_:
                o << "  if (top) vsp[top-1] = ~vsp[top-1];\n";
                break;
            case vm_op::neg:
                o << "  if (top) vsp[top-1] = (uint64_t)-(int64_t)vsp[top-1];\n";
                break;
            case vm_op::load:
                o << "  /* load *(uint64_t*)vsp[top-1] */\n";
                break;
            case vm_op::store:
                o << "  /* store vsp[top-2] to *(uint64_t*)vsp[top-1] */\n";
                if ( op.vsp_delta )
                    o << "  /* vsp_delta=" << op.vsp_delta << " */\n";
                break;
            case vm_op::calc_jmp:
                o << "  /* calc_jmp */\n";
                break;
            default:
                o << "  /* " << op.mnemonic << " @" << hex64( op.handler_va ) << " */\n";
                break;
            }
        }
        o << "}\n";
        return o.str( );
    }


    auto run_lift( const pe_view& p, std::uint64_t start, std::size_t max_ops ) -> lift_report
    {
        lift_report r{};
        r.image_base = p.base;
        r.vmenter_va = start;
        r.vmenters = scan_sites( p );

        uc_engine* uc = nullptr;
        auto err = uc_open( UC_ARCH_X86, UC_MODE_64, &uc );
        if ( err != UC_ERR_OK )
            throw fail( "uc_open", err );
        struct closer { uc_engine* uc; ~closer( ) { if ( uc ) uc_close( uc ); } } guard{ uc };
        map_image( uc, p );

        auto rsp = k_stack_va + k_stack_size - 0x400;
        const auto sentinel = p.base + 0x1000;
        rsp -= 8;
        uc_mem_write( uc, rsp, &sentinel, 8 );
        write_reg( uc, UC_X86_REG_RSP, rsp );
        write_reg( uc, UC_X86_REG_RIP, start );
        const std::uint64_t junk = 0x1111111111111111ull;
        for ( auto i = 0; i < k_gpr_n; ++i )
        {
            if ( i == 4 )
                continue;
            write_reg( uc, k_uc_gpr[ i ], junk );
        }
        const std::uint64_t flags = 0x202;
        write_reg( uc, UC_X86_REG_EFLAGS, flags );

        walk_st st{};
        st.pe = &p;
        st.uc = uc;
        st.vip_reg = -1;
        st.key_reg = -1;
        st.vsp_reg = -1;

        uc_hook h_code{}, h_mem{}, h_unmap{};
        uc_hook_add( uc, &h_code, UC_HOOK_CODE, reinterpret_cast< void* >( hook_code ), &st, 1, 0 );
        uc_hook_add( uc, &h_mem, UC_HOOK_MEM_READ, reinterpret_cast< void* >( hook_mem ), &st, 1, 0 );
        uc_hook_add( uc, &h_unmap, UC_HOOK_MEM_UNMAPPED, reinterpret_cast< void* >( hook_unmap ), &st, 1, 0 );

        std::set< std::uint64_t > seen;
        auto cur = start;
        auto stalls = 0;
        if ( !max_ops )
            max_ops = 256;
        if ( max_ops > 4096 )
            max_ops = 4096;

        for ( std::size_t i = 0; i < max_ops; ++i )
        {
            if ( !looks_code( p, cur ) )
                break;
            const auto revisit = !seen.insert( cur ).second;
            if ( revisit && stalls > 2 )
                break;

            effect eff{};
            eff.handler = cur;
            st.handler = cur;
            st.next = 0;
            st.hit = false;
            st.saw_ret = false;
            st.stop = false;
            st.steps = 0;
            st.vip_reads = 0;
            st.cur = &eff;
            eff.vip_before = st.vip;
            eff.key_before = st.key;
            const auto vsp_before = st.vsp;

            uc_emu_start( uc, cur, 0, 0, k_max_insns );
            guess_context( st );
            if ( st.vip_reg >= 0 )
                st.vip = read_reg( uc, k_uc_gpr[ st.vip_reg ] );
            if ( st.key_reg >= 0 )
                st.key = read_reg( uc, k_uc_gpr[ st.key_reg ] );
            if ( st.vsp_reg >= 0 )
            {
                const auto now = read_reg( uc, k_uc_gpr[ st.vsp_reg ] );
                if ( vsp_before )
                    eff.vsp_delta = static_cast< std::int64_t >( now - vsp_before );
                st.vsp = now;
            }
            for ( auto& f : eff.fetches )
            {
                if ( !f.decrypted && st.key )
                {
                    f.dec = static_cast< std::uint32_t >( f.enc ) ^ static_cast< std::uint32_t >( st.key );
                    f.decrypted = true;
                    if ( !eff.pushed )
                        eff.pushed = f.dec;
                }
            }
            eff.vip_after = st.vip;
            eff.key_after = st.key;
            if ( st.hit )
            {
                eff.xfer = true;
                eff.next = st.next;
            }
            peel( eff );

            lifted_op op{};
            op.index = r.ops.size( );
            op.handler_va = cur;
            op.vip = st.vip;
            op.kind = i == 0 && eff.pushes >= 1 ? vm_op::vmenter : eff.kind;
            op.mnemonic = vm_op_name( op.kind );
            op.imm = eff.pushed;
            op.next = eff.next;
            op.vsp_delta = eff.vsp_delta;
            op.confidence = eff.conf;
            op.comment = eff.why;
            op.semantic = true;
            if ( op.kind == vm_op::unknown )
                ++r.unknown;
            else
                ++r.classified;
            r.ops.push_back( op );

            if ( i == 0 )
                r.initial_vip = st.vip;
            if ( st.key )
                r.rolling_key = st.key;

            st.cur = nullptr;
            if ( st.saw_ret && !st.hit )
                break;
            if ( !st.hit )
            {
                ++stalls;
                if ( stalls > 8 )
                    break;
                write_reg( uc, UC_X86_REG_RIP, cur );
                continue;
            }
            stalls = 0;
            cur = st.next;
            write_reg( uc, UC_X86_REG_RIP, cur );
        }

        if ( st.vip_reg >= 0 )
            r.vip_reg = k_gpr[ st.vip_reg ];
        if ( st.vsp_reg >= 0 )
            r.vsp_reg = k_gpr[ st.vsp_reg ];
        if ( st.key_reg >= 0 )
            r.key_reg = k_gpr[ st.key_reg ];
        r.vasm = emit_vasm( r );
        r.native_c = emit_c( r );
        std::ostringstream tr;
        tr << "; vip trace steps=" << r.ops.size( ) << "\n";
        for ( const auto& op : r.ops )
        {
            tr << hex64( op.handler_va ) << "  " << op.mnemonic;
            if ( op.vip )
                tr << "  vip=" << hex64( op.vip );
            if ( op.imm )
                tr << "  imm=" << hex64( *op.imm );
            tr << "\n";
        }
        r.vip_trace = tr.str( );
        std::ostringstream sm;
        sm << "vmenter " << hex64( r.vmenter_va ) << " ops=" << r.ops.size( )
           << " classified=" << r.classified << " unknown=" << r.unknown
           << " vip=" << r.vip_reg << " vsp=" << r.vsp_reg << " key=" << r.key_reg;
        r.summary = sm.str( );
        return r;
    }
}


auto vm_op_name( vm_op k ) -> const char*
{
    switch ( k )
    {
    case vm_op::vmenter: return "vmenter";
    case vm_op::vmexit: return "vmexit";
    case vm_op::calc_jmp: return "calc_jmp";
    case vm_op::fetch: return "fetch";
    case vm_op::push: return "push";
    case vm_op::pop: return "pop";
    case vm_op::add: return "add";
    case vm_op::sub: return "sub";
    case vm_op::xor_: return "xor";
    case vm_op::and_: return "and";
    case vm_op::or_: return "or";
    case vm_op::nor: return "nor";
    case vm_op::shl: return "shl";
    case vm_op::shr: return "shr";
    case vm_op::not_: return "not";
    case vm_op::neg: return "neg";
    case vm_op::load: return "load";
    case vm_op::store: return "store";
    case vm_op::mov: return "mov";
    case vm_op::flags: return "flags";
    default: return "unk";
    }
}

auto scan_vmenters( const std::vector< std::uint8_t >& file ) -> std::vector< vmenter_site >
{
    return scan_sites( parse_pe( file ) );
}

auto lift_vm( const std::vector< std::uint8_t >& file, std::uint64_t vmenter_va, std::size_t max_ops ) -> lift_report
{
    const auto p = parse_pe( file );
    auto start = vmenter_va;
    auto sites = scan_sites( p );
    if ( !start )
    {
        if ( sites.empty( ) )
            throw std::runtime_error( "no vmenter candidates found" );
        start = sites.front( ).va;
        for ( const auto& s : sites )
        {
            if ( s.kind == vmenter_kind::pushfq && s.score >= 70 && s.note == "text" )
            {
                start = s.va;
                break;
            }
        }
        if ( start == sites.front( ).va )
        {
            for ( const auto& s : sites )
            {
                if ( s.kind == vmenter_kind::pushfq && s.score >= 70 )
                {
                    start = s.va;
                    break;
                }
            }
        }
    }
    auto r = run_lift( p, start, max_ops );
    r.vmenters = std::move( sites );
    return r;
}

auto write_lift_report( const std::string& dir, const lift_report& report ) -> void
{
    std::filesystem::create_directories( dir );
    auto dump = [ & ]( const char* name, const std::string& text )
    {
        std::ofstream out( std::filesystem::path( dir ) / name, std::ios::binary );
        if ( !out )
            throw std::runtime_error( std::string( "cannot write " ) + name );
        out << text;
    };
    dump( "report.txt", report.summary + "\n\n" + report.vasm );
    dump( "devirt.vasm", report.vasm );
    dump( "devirt_native.c", report.native_c );
    dump( "vip_trace.txt", report.vip_trace );
    std::ostringstream json;
    json << "{\n  \"vmenter\": \"" << hex64( report.vmenter_va ) << "\",\n";
    json << "  \"ops\": " << report.ops.size( ) << ",\n";
    json << "  \"classified\": " << report.classified << ",\n";
    json << "  \"unknown\": " << report.unknown << ",\n";
    json << "  \"vip_reg\": \"" << report.vip_reg << "\",\n";
    json << "  \"vsp_reg\": \"" << report.vsp_reg << "\",\n";
    json << "  \"key_reg\": \"" << report.key_reg << "\"\n}\n";
    dump( "summary.json", json.str( ) );
}


