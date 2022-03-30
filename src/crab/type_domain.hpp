// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include "crab/abstract_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"

namespace crab {

enum class region {
	T_CTX,
	T_STACK,
	T_PACKET,
	T_SHARED
};

struct ptr_no_off_t {
    region r;

    ptr_no_off_t() = default;
    ptr_no_off_t(const ptr_no_off_t &) = default;
    ptr_no_off_t(ptr_no_off_t &&) = default;
    ptr_no_off_t &operator=(const ptr_no_off_t &) = default;
    ptr_no_off_t &operator=(ptr_no_off_t &&) = default;
    ptr_no_off_t(region _r) : r(_r) {}

    friend std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p);
    friend bool operator==(const ptr_no_off_t& p1, const ptr_no_off_t& p2);
    friend bool operator!=(const ptr_no_off_t& p1, const ptr_no_off_t& p2);
};

struct ptr_with_off_t {
    region r;
    int offset;

    ptr_with_off_t() = default;
    ptr_with_off_t(const ptr_with_off_t &) = default;
    ptr_with_off_t(ptr_with_off_t &&) = default;
    ptr_with_off_t &operator=(const ptr_with_off_t &) = default;
    ptr_with_off_t &operator=(ptr_with_off_t &&) = default;
    ptr_with_off_t(region _r, int _off) : r(_r), offset(_off) {}

    friend std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p);
    friend bool operator==(const ptr_with_off_t& p1, const ptr_with_off_t& p2);
    friend bool operator!=(const ptr_with_off_t& p1, const ptr_with_off_t& p2);
};

using ptr_t = std::variant<ptr_no_off_t, ptr_with_off_t>;
using register_t = uint8_t;

struct reg_with_loc_t {
    register_t r;
    std::pair<label_t, uint32_t> loc;

    reg_with_loc_t(register_t _r, const label_t& l, uint32_t loc_instr) : r(_r), loc(std::make_pair(l, loc_instr)) {}
    bool operator==(const reg_with_loc_t& other) const;
    std::size_t hash() const;
    friend std::ostream& operator<<(std::ostream& o, const reg_with_loc_t& reg);
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
    live_registers_t m_vars;
    std::shared_ptr<global_type_env_t> m_all_types;
    bool m_is_bottom = false;

  public:
    register_types_t(bool is_bottom = false) : m_all_types(nullptr), m_is_bottom(is_bottom) {}
    explicit register_types_t(live_registers_t&& vars, std::shared_ptr<global_type_env_t> all_types, bool is_bottom = false)
        : m_vars(std::move(vars)), m_all_types(all_types), m_is_bottom(is_bottom) {}

    register_types_t operator|(const register_types_t& other) const;
    void operator-=(register_t var);
    void set_to_bottom();
    void set_to_top();
    bool is_bottom() const;
    bool is_top() const;
    void insert(register_t reg, const reg_with_loc_t& reg_with_loc, const ptr_t& type);
    std::optional<ptr_t> find(reg_with_loc_t reg) const;
    std::optional<ptr_t> find(register_t key) const;
    const live_registers_t &get_vars() { return m_vars; }
    friend std::ostream& operator<<(std::ostream& o, const register_types_t& p);
};

}

class type_domain_t final {

    crab::stack_t m_stack;
    crab::register_types_t m_types;
    std::shared_ptr<crab::ctx_t> m_ctx;
    label_t m_label;
    uint32_t m_curr_pos = 0;

  public:

    type_domain_t() : m_label(label_t::entry) {}
    type_domain_t(type_domain_t&& o) = default;
    type_domain_t(const type_domain_t& o) = default;
    type_domain_t& operator=(type_domain_t&& o) = default;
    type_domain_t& operator=(const type_domain_t& o) = default;
    type_domain_t(crab::register_types_t&& _types, crab::stack_t&& _st, const label_t& _l, std::shared_ptr<crab::ctx_t> _ctx)
            : m_stack(std::move(_st)), m_types(std::move(_types)), m_ctx(_ctx), m_label(_l) {}
    // eBPF initialization: R1 points to ctx, R10 to stack, etc.
    static type_domain_t setup_entry();
    // bottom/top
    static type_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    // inclusion
    bool operator<=(const type_domain_t& other) const;
    // join
    void operator|=(const type_domain_t& abs);
    void operator|=(type_domain_t&& abs);
    type_domain_t operator|(const type_domain_t& other) const;
    type_domain_t operator|(type_domain_t&& abs) const;
    // meet
    type_domain_t operator&(const type_domain_t& other) const;
    // widening
    type_domain_t widen(const type_domain_t& other) const;
    // narrowing
    type_domain_t narrow(const type_domain_t& other) const;
    //forget
    void operator-=(crab::variable_t var);

    //// abstract transformers
    void operator()(const Undefined &);
    void operator()(const Bin &);
    void operator()(const Un &) ;
    void operator()(const LoadMapFd &);
    void operator()(const Call &);
    void operator()(const Exit &);
    void operator()(const Jmp &);
    void operator()(const Mem &);
    void operator()(const Packet &);
    void operator()(const LockAdd &);
    void operator()(const Assume &);
    void operator()(const Assert &);
    void operator()(const basic_block_t& bb, bool check_termination);
    void write(std::ostream& os) const;
    std::string domain_name() const;
    crab::bound_t get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f);

  private:

    void do_load(const Mem&, const Reg&);
    void do_mem_store(const Mem&, const Reg&);

}; // end type_domain_t
