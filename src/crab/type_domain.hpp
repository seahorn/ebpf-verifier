// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include "crab/abstract_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"

class type_domain_t final {

    bool m_is_bottom = false;

  public:

    type_domain_t() = default;
    type_domain_t(type_domain_t&& o) = default;
    type_domain_t(const type_domain_t& o) = default;
    type_domain_t& operator=(type_domain_t&& o) = default;
    type_domain_t& operator=(const type_domain_t& o) = default;
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
    void operator()(const basic_block_t& bb, bool check_termination, int print = 0);
    void write(std::ostream& os) const;
    std::string domain_name() const;
    crab::bound_t get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f);

  private:

    void do_load(const Mem&, const Reg&, location_t, int print = 0);
    void do_mem_store(const Mem&, const Reg&, location_t, int print = 0);
    void print_initial_types();
    void report_type_error(std::string, location_t);

}; // end type_domain_t
