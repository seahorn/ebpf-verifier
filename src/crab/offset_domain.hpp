// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include <boost/optional/optional_io.hpp>
#include "crab/abstract_domain.hpp"
#include "crab/region_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"

using crab::ptr_t;
using crab::ptr_with_off_t;
using crab::ptr_no_off_t;

using constant_t = int;   // define a domain for constants
//using symbol_t = register_t;    // a register with unknown value
using weight_t = constant_t; // should be constants + symbols
using slack_var_t = int;

enum class rop_t {
    R_GT,
    R_GE,
    R_LT,
    R_LE
};

struct dist_t {
    slack_var_t m_slack;
    weight_t m_dist;

    dist_t(weight_t d, slack_var_t s = -1) : m_slack(s), m_dist(d) {}
    dist_t() : m_slack(-1), m_dist(0) {}
    bool operator==(const dist_t& d) const;
};      // if dist is +ve, represents `begin+dist+slack;`, if dist is -ve, represents `end+dist+1`

struct inequality_t {
    slack_var_t m_slack;
    rop_t m_rel;
    weight_t m_value;

    inequality_t(slack_var_t slack, rop_t rel, weight_t val) : m_slack(slack), m_rel(rel)
                                                               , m_value(val) {}
    inequality_t() = default;
};    // represents `slack rel value;`, e.g., `s >= 0`

struct forward_and_backward_eq_t {
    dist_t m_forw;
    dist_t m_backw;

    forward_and_backward_eq_t(dist_t forw, dist_t backw) : m_forw(forw), m_backw(backw) {}
    forward_and_backward_eq_t() = default;
};  // represents constraint `p[0] = p[1];`, e.g., `begin+8+s = end`


using register_dists_t = std::array<std::shared_ptr<dist_t>, 11>;        // represents `rn = dist;`, where n \belongs [0,10], e.g., `r1 = begin+8`

class registers_state_t {

    public:
    register_dists_t m_reg_dists;
    bool m_is_bottom = false;

    public:
        registers_state_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
        void set_to_top();
        void set_to_bottom();
        bool is_bottom() const;
        bool is_top() const;
        registers_state_t operator|(const registers_state_t&) const;
        explicit registers_state_t(register_dists_t&& reg_dists, bool is_bottom = false)
            : m_reg_dists(std::move(reg_dists)), m_is_bottom(is_bottom) {}
};

class stack_state_t {
    using stack_slot_dists_t = std::unordered_map<unsigned int, dist_t>;    // represents `sp[n] = dist;`, where n \belongs [0,511], e.g., `sp[508] = begin+16`

    public:
    stack_slot_dists_t m_stack_slot_dists;
    bool m_is_bottom = false;

    public:
        stack_state_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
        void set_to_top();
        void set_to_bottom();
        bool is_bottom() const;
        bool is_top() const;
        stack_state_t operator|(const stack_state_t&) const;
        explicit stack_state_t(stack_slot_dists_t&& stack_dists, bool is_bottom = false)
            : m_stack_slot_dists(std::move(stack_dists)), m_is_bottom(is_bottom) {}
};

class extra_constraints_t {
    public:
    forward_and_backward_eq_t m_eq;
    inequality_t m_ineq;
    bool m_is_bottom = false;

    public:
        extra_constraints_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
        void set_to_top();
        void set_to_bottom();
        bool is_bottom() const;
        bool is_top() const;
        extra_constraints_t operator|(const extra_constraints_t&) const;
        explicit extra_constraints_t(forward_and_backward_eq_t&& fabeq, inequality_t ineq, bool is_bottom = false) : m_eq(fabeq), m_ineq(ineq), m_is_bottom(is_bottom) {}
};

class ctx_t {
    using ctx_dists_t = std::unordered_map<unsigned int, dist_t>;    // represents `cp[n] = dist;`

    public:
    ctx_dists_t m_dists;

    public:
        ctx_t(const ebpf_context_descriptor_t* desc);
};

class offset_domain_t final {

    bool m_is_bottom = false;
    registers_state_t m_reg_state;
    stack_state_t m_stack_state;
    extra_constraints_t m_extra_constraints;
    std::shared_ptr<ctx_t> m_ctx_dists;
    slack_var_t m_slack = 0;

  public:

    offset_domain_t() = default;
    offset_domain_t(offset_domain_t&& o) = default;
    offset_domain_t(const offset_domain_t& o) = default;
    offset_domain_t& operator=(offset_domain_t&& o) = default;
    offset_domain_t& operator=(const offset_domain_t& o) = default;
    offset_domain_t(std::shared_ptr<ctx_t> _ctx) : m_ctx_dists(_ctx), m_slack(0) {}
    explicit offset_domain_t(registers_state_t&& reg, stack_state_t&& stack, extra_constraints_t extra, std::shared_ptr<ctx_t> ctx, slack_var_t s = 0)
        : m_reg_state(std::move(reg)), m_stack_state(std::move(stack)), m_extra_constraints(std::move(extra)), m_ctx_dists(ctx), m_slack(s) {}
    static offset_domain_t setup_entry();
    // bottom/top
    static offset_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    // inclusion
    bool operator<=(const offset_domain_t& other) const;
    // join
    void operator|=(const offset_domain_t& abs);
    void operator|=(offset_domain_t&& abs);
    offset_domain_t operator|(const offset_domain_t& other) const;
    offset_domain_t operator|(offset_domain_t&& abs) const;
    // meet
    offset_domain_t operator&(const offset_domain_t& other) const;
    // widening
    offset_domain_t widen(const offset_domain_t& other) const;
    // narrowing
    offset_domain_t narrow(const offset_domain_t& other) const;
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
    void operator()(const basic_block_t& bb, bool check_termination, int print = 0);
    void write(std::ostream& os) const;
    std::string domain_name() const;
    int get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f);

    void do_load(const Mem&, const Reg&, std::optional<ptr_t>&);
    void do_mem_store(const Mem&, const Reg&, std::optional<ptr_t>&, std::optional<ptr_t>&);
    void do_bin(const Bin&, std::optional<ptr_t>, std::optional<ptr_t>);
}; // end offset_domain_t
