// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include "crab/abstract_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"
#include <boost/optional/optional_io.hpp>

namespace crab {

enum class region {
	T_CTX,
	T_STACK,
	T_PACKET,
	T_SHARED
};


class ptr_no_off_t {
    region m_r;

  public:
    ptr_no_off_t() = default;
    ptr_no_off_t(const ptr_no_off_t &) = default;
    ptr_no_off_t(ptr_no_off_t &&) = default;
    ptr_no_off_t &operator=(const ptr_no_off_t &) = default;
    ptr_no_off_t &operator=(ptr_no_off_t &&) = default;
    ptr_no_off_t(region _r) : m_r(_r) {}

    constexpr region get_region() const { return m_r; }
    void set_region(region);
    void write(std::ostream&) const;
    friend std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p);
    //bool operator==(const ptr_no_off_t& p2);
    //bool operator!=(const ptr_no_off_t& p2);
};

class ptr_with_off_t {
    region m_r;
    int m_offset;

  public:
    ptr_with_off_t() = default;
    ptr_with_off_t(const ptr_with_off_t &) = default;
    ptr_with_off_t(ptr_with_off_t &&) = default;
    ptr_with_off_t &operator=(const ptr_with_off_t &) = default;
    ptr_with_off_t &operator=(ptr_with_off_t &&) = default;
    ptr_with_off_t(region _r, int _off) : m_r(_r), m_offset(_off) {}

    constexpr int get_offset() const { return m_offset; }
    void set_offset(int);
    constexpr region get_region() const { return m_r; }
    void set_region(region);
    void write(std::ostream&) const;
    friend std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p);
    //bool operator==(const ptr_with_off_t& p2);
    //bool operator!=(const ptr_with_off_t& p2);
};

using ptr_t = std::variant<ptr_no_off_t, ptr_with_off_t>;
using register_t = uint8_t;
using location_t = boost::optional<std::pair<label_t, uint32_t>>;

class reg_with_loc_t {
    register_t m_reg;
    location_t m_loc;

  public:
    reg_with_loc_t(register_t _r, location_t _loc) : m_reg(_r), m_loc(_loc) {}
    bool operator==(const reg_with_loc_t& other) const;
    std::size_t hash() const;
    friend std::ostream& operator<<(std::ostream& o, const reg_with_loc_t& reg);
    void write(std::ostream& ) const;
};

class ctx_t {
    using offset_to_ptr_no_off_t = std::unordered_map<int, ptr_no_off_t>;

    offset_to_ptr_no_off_t m_packet_ptrs;

  public:
    ctx_t(const ebpf_context_descriptor_t* desc);
    std::optional<ptr_no_off_t> find(int key) const;
    friend std::ostream& operator<<(std::ostream& o, const ctx_t& _ctx);
};

class stack_t {
    using offset_to_ptr_t = std::unordered_map<int, ptr_t>;

    offset_to_ptr_t m_ptrs;
    bool m_is_bottom;

  public:
    stack_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
    stack_t(offset_to_ptr_t && ptrs, bool is_bottom)
    : m_ptrs(std::move(ptrs)) , m_is_bottom(is_bottom) {}
    
    stack_t operator|(const stack_t& other) const;
    void operator-=(int);
    void set_to_bottom();
    void set_to_top();
    static stack_t bottom();
    static stack_t top();
    bool is_bottom() const;
    bool is_top() const;
    const offset_to_ptr_t &get_ptrs() { return m_ptrs; }
    void insert(int key, ptr_t value);
    std::optional<ptr_t> find(int key) const;
    friend std::ostream& operator<<(std::ostream& o, const stack_t& st);
};

using live_registers_t = std::array<std::shared_ptr<reg_with_loc_t>, 11>;
using global_type_env_t = std::unordered_map<reg_with_loc_t, ptr_t>;

class register_types_t {
    live_registers_t m_cur_def;
    std::shared_ptr<global_type_env_t> m_reg_type_env;
    bool m_is_bottom = false;

  public:
    register_types_t(bool is_bottom = false) : m_reg_type_env(nullptr), m_is_bottom(is_bottom) {}
    explicit register_types_t(live_registers_t&& vars, std::shared_ptr<global_type_env_t> reg_type_env, bool is_bottom = false)
        : m_cur_def(std::move(vars)), m_reg_type_env(reg_type_env), m_is_bottom(is_bottom) {}

    register_types_t operator|(const register_types_t& other) const;
    void operator-=(register_t var);
    void set_to_bottom();
    void set_to_top();
    bool is_bottom() const;
    bool is_top() const;
    void insert(register_t reg, const reg_with_loc_t& reg_with_loc, const ptr_t& type);
    std::optional<ptr_t> find(reg_with_loc_t reg) const;
    std::optional<ptr_t> find(register_t key) const;
    const live_registers_t &get_vars() { return m_cur_def; }
    friend std::ostream& operator<<(std::ostream& o, const register_types_t& p);
};

}

class region_domain_t final {

    bool m_is_bottom = false;
    location_t error_location = boost::none;
    crab::stack_t m_stack;
    crab::register_types_t m_registers;
    std::shared_ptr<crab::ctx_t> m_ctx;

  public:

    region_domain_t() = default;
    region_domain_t(region_domain_t&& o) = default;
    region_domain_t(const region_domain_t& o) = default;
    region_domain_t& operator=(region_domain_t&& o) = default;
    region_domain_t& operator=(const region_domain_t& o) = default;
    region_domain_t(crab::register_types_t&& _types, crab::stack_t&& _st, std::shared_ptr<crab::ctx_t> _ctx)
            : m_stack(std::move(_st)), m_registers(std::move(_types)), m_ctx(_ctx) {}
    // eBPF initialization: R1 points to ctx, R10 to stack, etc.
    static region_domain_t setup_entry();
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
    void operator-=(variable_t var);

    //// abstract transformers
    void operator()(const Undefined &, location_t loc = boost::none, int print = 0);
    void operator()(const Bin &, location_t loc = boost::none, int print = 0);
    void operator()(const Un &, location_t loc = boost::none, int print = 0);
    void operator()(const LoadMapFd &, location_t loc = boost::none, int print = 0);
    void operator()(const Call &, location_t loc = boost::none, int print = 0);
    void operator()(const Exit &, location_t loc = boost::none, int print = 0);
    void operator()(const Jmp &, location_t loc = boost::none, int print = 0);
    void operator()(const Mem &, location_t loc = boost::none, int print = 0);
    void operator()(const Packet &, location_t loc = boost::none, int print = 0);
    void operator()(const LockAdd &, location_t loc = boost::none, int print = 0);
    void operator()(const Assume &, location_t loc = boost::none, int print = 0);
    void operator()(const Assert &, location_t loc = boost::none, int print = 0);
    void operator()(const ValidAccess&, location_t loc = boost::none, int print = 0) {}
    void operator()(const Comparable& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const Addable& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const ValidStore& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const TypeConstraint& s, location_t loc = boost::none, int print = 0);
    void operator()(const ValidSize& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const ValidMapKeyValue& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const ZeroOffset& s, location_t loc = boost::none, int print = 0) {}

    void operator()(const basic_block_t& bb, bool check_termination, int print = 0);
    void write(std::ostream& os) const;
    std::string domain_name() const;
    int get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f);

    void do_load(const Mem&, const Reg&, location_t, int print = 0);
    void do_mem_store(const Mem&, const Reg&, location_t, int print = 0);
    void print_initial_types();
    void report_type_error(std::string, location_t);
    std::optional<crab::ptr_t> find_ptr_type(register_t);

}; // end region_domain_t
