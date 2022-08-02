// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include "crab/abstract_domain.hpp"
#include "crab/region_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"

using crab::ptr_t;
using crab::ptr_or_mapfd_t;
using crab::mapfd_t;
using crab::ptr_with_off_t;
using crab::ptr_no_off_t;
using crab::reg_with_loc_t;
using crab::interval_t;
using crab::bound_t;

using live_registers_t = std::array<std::shared_ptr<reg_with_loc_t>, 11>;
using global_interval_env_t = std::unordered_map<reg_with_loc_t, interval_t>;

class registers_cp_state_t {

    live_registers_t m_cur_def;
    std::shared_ptr<global_interval_env_t> m_interval_env;
    bool m_is_bottom = false;

    public:
        bool is_bottom() const;
        bool is_top() const;
        void set_to_bottom();
        void set_to_top();
        std::optional<interval_t> find(reg_with_loc_t reg) const;
        std::optional<interval_t> find(register_t key) const;
        void insert(register_t, const reg_with_loc_t&, interval_t);
        void operator-=(register_t);
        registers_cp_state_t operator|(const registers_cp_state_t& other) const;
        registers_cp_state_t(bool is_bottom = false) : m_interval_env(nullptr),
            m_is_bottom(is_bottom) {}
        explicit registers_cp_state_t(live_registers_t&& vars,
                std::shared_ptr<global_interval_env_t> interval_env, bool is_bottom = false)
            : m_cur_def(std::move(vars)), m_interval_env(interval_env), m_is_bottom(is_bottom) {}
        explicit registers_cp_state_t(std::shared_ptr<global_interval_env_t> interval_env,
                bool is_bottom = false)
            : m_interval_env(interval_env), m_is_bottom(is_bottom) {}
        void adjust_bb_for_registers(location_t);
        //void print_all_consts();
};

class stack_cp_state_t {
    using interval_values_stack_t = std::unordered_map<unsigned int, interval_t>;

    interval_values_stack_t m_interval_values;
    bool m_is_bottom = false;

    public:
        bool is_bottom() const;
        bool is_top() const;
        void set_to_bottom();
        void set_to_top();
        static stack_cp_state_t top();
        std::optional<interval_t> find(int) const;
        void store(int, interval_t);
        stack_cp_state_t operator|(const stack_cp_state_t& other) const;
        stack_cp_state_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
        explicit stack_cp_state_t(interval_values_stack_t&& interval_values, bool is_bottom = false)
            : m_interval_values(std::move(interval_values)), m_is_bottom(is_bottom) {}
};

class interval_prop_domain_t final {
    registers_cp_state_t m_registers_interval_values;
    stack_cp_state_t m_stack_slots_interval_values;
    bool m_is_bottom = false;

  public:

    interval_prop_domain_t() = default;
    interval_prop_domain_t(interval_prop_domain_t&& o) = default;
    interval_prop_domain_t(const interval_prop_domain_t& o) = default;
    explicit interval_prop_domain_t(registers_cp_state_t&& consts_regs,
            stack_cp_state_t&& interval_stack_slots, bool is_bottom = false) :
        m_registers_interval_values(std::move(consts_regs)), m_stack_slots_interval_values(std::move(interval_stack_slots)),
        m_is_bottom(is_bottom) {}
    interval_prop_domain_t& operator=(interval_prop_domain_t&& o) = default;
    interval_prop_domain_t& operator=(const interval_prop_domain_t& o) = default;
    // eBPF initialization: R1 points to ctx, R10 to stack, etc.
    static interval_prop_domain_t setup_entry();
    // bottom/top
    static interval_prop_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    // inclusion
    bool operator<=(const interval_prop_domain_t& other) const;
    // join
    void operator|=(const interval_prop_domain_t& abs);
    void operator|=(interval_prop_domain_t&& abs);
    interval_prop_domain_t operator|(const interval_prop_domain_t& other) const;
    interval_prop_domain_t operator|(interval_prop_domain_t&& abs) const;
    // meet
    interval_prop_domain_t operator&(const interval_prop_domain_t& other) const;
    // widening
    interval_prop_domain_t widen(const interval_prop_domain_t& other) const;
    // narrowing
    interval_prop_domain_t narrow(const interval_prop_domain_t& other) const;
    //forget
    void operator-=(variable_t var);

    //// abstract transformers
    void operator()(const Undefined &, location_t loc = boost::none, int print = 0) {}
    void operator()(const Bin &, location_t loc = boost::none, int print = 0);
    void operator()(const Un &, location_t loc = boost::none, int print = 0) {}
    void operator()(const LoadMapFd &, location_t loc = boost::none, int print = 0);
    void operator()(const Call &, location_t loc = boost::none, int print = 0);
    void operator()(const Exit &, location_t loc = boost::none, int print = 0) {}
    void operator()(const Jmp &, location_t loc = boost::none, int print = 0) {}
    void operator()(const Mem &, location_t loc = boost::none, int print = 0) {}
    void operator()(const Packet &, location_t loc = boost::none, int print = 0);
    void operator()(const LockAdd &, location_t loc = boost::none, int print = 0) {}
    void operator()(const Assume &, location_t loc = boost::none, int print = 0) {}
    void operator()(const Assert &, location_t loc = boost::none, int print = 0) {}
    void operator()(const ValidAccess&, location_t loc = boost::none, int print = 0) {}
    void operator()(const Comparable& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const Addable& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const ValidStore& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const TypeConstraint& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const ValidSize& s, location_t loc = boost::none, int print = 0);
    void operator()(const ValidMapKeyValue& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const ZeroOffset& s, location_t loc = boost::none, int print = 0) {}
    void operator()(const basic_block_t& bb, bool check_termination, int print = 0) {}
    void write(std::ostream& os) const;
    std::string domain_name() const;
    int get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f) {}

    void do_load(const Mem&, const Reg&, std::optional<ptr_or_mapfd_t>, location_t);
    void do_mem_store(const Mem&, const Reg&, std::optional<ptr_or_mapfd_t>);
    std::optional<interval_t> find_interval_value(register_t) const;
    std::optional<interval_t> find_in_registers(const reg_with_loc_t reg) const;
    void print_initial_types();
    void adjust_bb_for_types(location_t);

}; // end interval_prop_domain_t
