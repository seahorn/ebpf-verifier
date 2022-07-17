// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include "crab/abstract_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"


class registers_cp_state_t {
    using const_values_registers_t = std::array<std::shared_ptr<int>, 11>;

    const_values_registers_t m_const_values;
    bool m_is_bottom = false;

    public:
        bool is_bottom() const;
        bool is_top() const;
        void set_to_bottom();
        void set_to_top();
        registers_cp_state_t operator|(const registers_cp_state_t& other) const;
        registers_cp_state_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
        explicit registers_cp_state_t(const_values_registers_t&& const_values, bool is_bottom = false)
            : m_const_values(std::move(const_values)), m_is_bottom(is_bottom) {}
};

class stack_cp_state_t {
    using const_values_stack_t = std::unordered_map<unsigned int, int>;

    const_values_stack_t m_const_values;
    bool m_is_bottom = false;

    public:
        bool is_bottom() const;
        bool is_top() const;
        void set_to_bottom();
        void set_to_top();
        stack_cp_state_t operator|(const stack_cp_state_t& other) const;
        stack_cp_state_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
        explicit stack_cp_state_t(const_values_stack_t&& const_values, bool is_bottom = false)
            : m_const_values(std::move(const_values)), m_is_bottom(is_bottom) {}
};

class constant_prop_domain_t final {
    registers_cp_state_t m_registers_const_values;
    stack_cp_state_t m_stack_slots_const_values;
    bool m_is_bottom = false;

  public:

    constant_prop_domain_t() = default;
    constant_prop_domain_t(constant_prop_domain_t&& o) = default;
    constant_prop_domain_t(const constant_prop_domain_t& o) = default;
    explicit constant_prop_domain_t(registers_cp_state_t&& consts_regs,
            stack_cp_state_t&& const_stack_slots, bool is_bottom = false) :
        m_registers_const_values(std::move(consts_regs)), m_stack_slots_const_values(std::move(const_stack_slots)),
        m_is_bottom(is_bottom) {}
    constant_prop_domain_t& operator=(constant_prop_domain_t&& o) = default;
    constant_prop_domain_t& operator=(const constant_prop_domain_t& o) = default;
    // eBPF initialization: R1 points to ctx, R10 to stack, etc.
    static constant_prop_domain_t setup_entry();
    // bottom/top
    static constant_prop_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    // inclusion
    bool operator<=(const constant_prop_domain_t& other) const;
    // join
    void operator|=(const constant_prop_domain_t& abs);
    void operator|=(constant_prop_domain_t&& abs);
    constant_prop_domain_t operator|(const constant_prop_domain_t& other) const;
    constant_prop_domain_t operator|(constant_prop_domain_t&& abs) const;
    // meet
    constant_prop_domain_t operator&(const constant_prop_domain_t& other) const;
    // widening
    constant_prop_domain_t widen(const constant_prop_domain_t& other) const;
    // narrowing
    constant_prop_domain_t narrow(const constant_prop_domain_t& other) const;
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
    void operator()(const ValidAccess&, location_t loc = boost::none, int print = 0);
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

  private:

    void do_load(const Mem&, const Reg&, location_t, int print = 0);
    void do_mem_store(const Mem&, const Reg&, location_t, int print = 0);
    void print_initial_types();
    void report_type_error(std::string, location_t);

}; // end constant_prop_domain_t
