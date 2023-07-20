// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "crab/abstract_domain.hpp"
#include "crab/common.hpp"
#include "crab/type_ostream.hpp"
#include "crab/cfg.hpp"

#include "platform.hpp"

namespace crab {

class ctx_t {
    using ptr_types_t = std::unordered_map<uint64_t, ptr_no_off_t>;

    ptr_types_t m_packet_ptrs;
    size_t size = 0;

  public:
    ctx_t(const ebpf_context_descriptor_t* desc);
    constexpr size_t get_size() const { return size; }
    std::vector<uint64_t> get_keys() const;
    std::optional<ptr_no_off_t> find(uint64_t key) const;
};

using ptr_or_mapfd_cells_t = std::pair<ptr_or_mapfd_t, int>;
using ptr_or_mapfd_types_t = std::map<uint64_t, ptr_or_mapfd_cells_t>;

class stack_t {
    ptr_or_mapfd_types_t m_ptrs;
    bool m_is_bottom;

  public:
    stack_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
    stack_t(ptr_or_mapfd_types_t && ptrs, bool is_bottom)
    : m_ptrs(std::move(ptrs)) , m_is_bottom(is_bottom) {}
    
    stack_t operator|(const stack_t& other) const;
    void operator-=(uint64_t);
    void operator-=(const std::vector<uint64_t>&);
    void set_to_bottom();
    void set_to_top();
    static stack_t bottom();
    static stack_t top();
    bool is_bottom() const;
    bool is_top() const;
    const ptr_or_mapfd_types_t &get_ptrs() { return m_ptrs; }
    void store(uint64_t, ptr_or_mapfd_t, int);
    std::optional<ptr_or_mapfd_cells_t> find(uint64_t) const;
    std::vector<uint64_t> get_keys() const;
    std::vector<uint64_t> find_overlapping_cells(uint64_t, int) const;
    size_t size() const;
};

using live_registers_t = std::array<std::shared_ptr<reg_with_loc_t>, 11>;
using global_region_env_t = std::unordered_map<reg_with_loc_t, ptr_or_mapfd_t>;

class register_types_t {

    live_registers_t m_cur_def;
    std::shared_ptr<global_region_env_t> m_region_env;
    bool m_is_bottom = false;

  public:
    register_types_t(bool is_bottom = false) : m_region_env(nullptr), m_is_bottom(is_bottom) {}
    explicit register_types_t(live_registers_t&& vars,
            std::shared_ptr<global_region_env_t> reg_type_env, bool is_bottom = false)
        : m_cur_def(std::move(vars)), m_region_env(reg_type_env), m_is_bottom(is_bottom) {}

    explicit register_types_t(std::shared_ptr<global_region_env_t> reg_type_env,
            bool is_bottom = false)
        : m_region_env(reg_type_env), m_is_bottom(is_bottom) {}

    register_types_t operator|(const register_types_t& other) const;
    void operator-=(register_t var);
    void set_to_bottom();
    void set_to_top();
    bool is_bottom() const;
    bool is_top() const;
    void insert(register_t reg, const reg_with_loc_t& reg_with_loc, const ptr_or_mapfd_t& type);
    std::optional<ptr_or_mapfd_t> find(reg_with_loc_t reg) const;
    std::optional<ptr_or_mapfd_t> find(register_t key) const;
    [[nodiscard]] live_registers_t &get_vars() { return m_cur_def; }
    void forget_packet_ptrs();
    void adjust_bb_for_registers(location_t loc);
    void print_all_register_types() const;
};

class region_domain_t final {

    bool m_is_bottom = false;
    crab::stack_t m_stack;
    crab::register_types_t m_registers;
    std::shared_ptr<crab::ctx_t> m_ctx;
    std::vector<std::string> m_errors;

  public:

    region_domain_t() = default;
    region_domain_t(region_domain_t&& o) = default;
    region_domain_t(const region_domain_t& o) = default;
    region_domain_t& operator=(region_domain_t&& o) = default;
    region_domain_t& operator=(const region_domain_t& o) = default;
    region_domain_t(crab::register_types_t&& _types, crab::stack_t&& _st, std::shared_ptr<crab::ctx_t> _ctx)
            : m_stack(std::move(_st)), m_registers(std::move(_types)), m_ctx(_ctx) {}
    // eBPF initialization: R1 points to ctx, R10 to stack, etc.
    static region_domain_t&& setup_entry();
    // bottom/top
    static region_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    // inclusion
    bool operator<=(const region_domain_t& other) const;
    // join
    void operator|=(const region_domain_t& abs);
    void operator|=(region_domain_t&& abs);
    region_domain_t operator|(const region_domain_t& other) const;
    region_domain_t operator|(region_domain_t&& abs) const;
    // meet
    region_domain_t operator&(const region_domain_t& other) const;
    // widening
    region_domain_t widen(const region_domain_t& other) const;
    // narrowing
    region_domain_t narrow(const region_domain_t& other) const;
    //forget
    void operator-=(crab::variable_t var);
    void operator-=(register_t var) { m_registers -= var; }

    //// abstract transformers
    void operator()(const Undefined&, location_t loc = boost::none, int print = 0);
    void operator()(const Bin&, location_t loc = boost::none, int print = 0);
    void operator()(const Un&, location_t loc = boost::none, int print = 0);
    void operator()(const LoadMapFd&, location_t loc = boost::none, int print = 0);
    void operator()(const Call&, location_t loc = boost::none, int print = 0);
    void operator()(const Exit&, location_t loc = boost::none, int print = 0);
    void operator()(const Jmp&, location_t loc = boost::none, int print = 0);
    void operator()(const Mem&, location_t loc = boost::none, int print = 0);
    void operator()(const Packet&, location_t loc = boost::none, int print = 0);
    void operator()(const LockAdd&, location_t loc = boost::none, int print = 0);
    void operator()(const Assume&, location_t loc = boost::none, int print = 0);
    void operator()(const Assert&, location_t loc = boost::none, int print = 0);
    void operator()(const ValidAccess&, location_t loc = boost::none, int print = 0);
    void operator()(const Comparable&, location_t loc = boost::none, int print = 0);
    void operator()(const Addable&, location_t loc = boost::none, int print = 0);
    void operator()(const ValidStore&, location_t loc = boost::none, int print = 0);
    void operator()(const TypeConstraint&, location_t loc = boost::none, int print = 0);
    void operator()(const ValidSize&, location_t loc = boost::none, int print = 0);
    void operator()(const ValidMapKeyValue&, location_t loc = boost::none, int print = 0);
    void operator()(const ZeroCtxOffset&, location_t loc = boost::none, int print = 0);
    void operator()(const ValidDivisor&, location_t loc = boost::none, int print = 0);
    void operator()(const basic_block_t& bb, bool check_termination, int print = 0);
    void write(std::ostream& o) const {}
    friend std::ostream& operator<<(std::ostream&, const region_domain_t&);
    std::string domain_name() const;
    crab::bound_t get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f) {}

    interval_t get_map_value_size(const Reg&) const;
    bool get_map_fd_range(const Reg&, int32_t*, int32_t*) const;
    std::optional<uint32_t> get_map_type(const Reg&) const;
    std::optional<uint32_t> get_map_inner_map_fd(const Reg&) const;
    void do_load_mapfd(const register_t&, int, location_t);
    void do_load(const Mem&, const Reg&, bool, location_t);
    void do_mem_store(const Mem&, location_t);
    interval_t do_bin(const Bin&, const std::optional<interval_t>&,
            const std::optional<crab::ptr_or_mapfd_t>&,
            const std::optional<crab::ptr_or_mapfd_t>&, location_t);
    void update_ptr_or_mapfd(crab::ptr_or_mapfd_t&&, const interval_t&&,
            const crab::reg_with_loc_t&, uint8_t);

    std::optional<crab::ptr_or_mapfd_t> find_ptr_or_mapfd_type(register_t) const;
    [[nodiscard]] size_t ctx_size() const;
    std::optional<crab::ptr_no_off_t> find_in_ctx(uint64_t key) const;
    [[nodiscard]] std::vector<uint64_t> get_ctx_keys() const;
    std::optional<crab::ptr_or_mapfd_cells_t> find_in_stack(uint64_t key) const;
    std::optional<crab::ptr_or_mapfd_t> find_ptr_or_mapfd_at_loc(const crab::reg_with_loc_t&) const;
    [[nodiscard]] std::vector<uint64_t> get_stack_keys() const;
    void adjust_bb_for_types(location_t);
    void print_all_register_types() const;
    [[nodiscard]] std::vector<std::string>& get_errors() { return m_errors; }
}; // end region_domain_t

} // namespace crab
