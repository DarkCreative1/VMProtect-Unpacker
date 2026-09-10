#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

enum class vm_op : std::uint8_t
{
    unknown,
    vmenter,
    vmexit,
    calc_jmp,
    fetch,
    push,
    pop,
    add,
    sub,
    xor_,
    and_,
    or_,
    nor,
    shl,
    shr,
    not_,
    neg,
    load,
    store,
    mov,
    flags
};

enum class vmenter_kind : std::uint8_t
{
    pushfq,
    push_imm,
    push_call,
    pdata
};

struct vmenter_site
{
    std::uint64_t va;
    std::uint32_t rva;
    vmenter_kind kind;
    int score;
    std::string note;
};

struct lift_fetch
{
    std::uint64_t addr;
    std::uint32_t size;
    std::uint64_t enc;
    std::uint64_t dec;
    bool decrypted;
};

struct lifted_op
{
    std::size_t index;
    std::uint64_t handler_va;
    std::uint64_t vip;
    vm_op kind;
    std::string mnemonic;
    std::optional< std::uint64_t > imm;
    std::optional< std::uint64_t > next;
    std::int64_t vsp_delta;
    int confidence;
    std::string comment;
    bool semantic;
};

struct lift_report
{
    std::uint64_t image_base;
    std::uint64_t vmenter_va;
    std::string vip_reg;
    std::string vsp_reg;
    std::string key_reg;
    std::uint64_t initial_vip;
    std::uint64_t rolling_key;
    std::vector< vmenter_site > vmenters;
    std::vector< lifted_op > ops;
    std::size_t classified;
    std::size_t unknown;
    std::string vasm;
    std::string native_c;
    std::string vip_trace;
    std::string summary;
};

auto vm_op_name( vm_op k ) -> const char*;
auto scan_vmenters( const std::vector< std::uint8_t >& file ) -> std::vector< vmenter_site >;
auto lift_vm( const std::vector< std::uint8_t >& file, std::uint64_t vmenter_va, std::size_t max_ops ) -> lift_report;
auto write_lift_report( const std::string& dir, const lift_report& report ) -> void;
