#pragma once

#include <unordered_map>

#include "crab/abstract_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"

using register1_t = unsigned int;
using constant_t = int;   // define a domain for constants
//using symbol_t = register_t;    // a register with unknown value
using weight_t = constant_t; // should be constants + symbols
using slack_var_t = std::string;

enum class rop_t {
    R_GT,
    R_GE,
    R_LT,
    R_LE
};

struct dist_t {
    slack_var_t m_slack;
    weight_t m_dist;
};      // if dist is +ve, represents `begin+dist+slack;`, if dist is -ve, represents `end+dist+1`

struct inequality_t {
    slack_var_t m_slack;
    rop_t m_rel;
    weight_t m_value;
};    // represents `slack rel value;`, e.g., `s >= 0`

using forward_and_backward_eq_t = std::pair<dist_t, dist_t>;    // represents constraint `p[0] = p[1];`, e.g., `begin+8+s = end`

using extra_constraints_t = std::pair<forward_and_backward_eq_t, inequality_t>;

using register_dists_t = std::array<dist_t, 11>;        // represents `rn = dist;`, where n \belongs [0,10], e.g., `r1 = begin+8`

using stack_dists_t = std::unordered_map<unsigned int, dist_t>;    // represents `sp[n] = dist;`, where n \belongs [0,511], e.g., `sp[508] = begin+16`

using ctx_t = std::unordered_map<unsigned int, dist_t>;    // represents `cp[n] = dist;`


class offset_domain_t final {

    bool m_is_bottom = false;
    register_dists_t m_reg_dists;
    stack_dists_t m_stack_dists;
    extra_constraints_t m_extra_constraints;
    std::shared_ptr<ctx_t> m_ctx_dists;

  public:

    offset_domain_t() = default;
    offset_domain_t(offset_domain_t&& o) = default;
    offset_domain_t(const offset_domain_t& o) = default;
    offset_domain_t& operator=(offset_domain_t&& o) = default;
    offset_domain_t& operator=(const offset_domain_t& o) = default;
    //offset_domain_t(crab::register_types_t&& _types, crab::stack_t&& _st, std::shared_ptr<crab::ctx_t> _ctx) = default;
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

  private:
    void do_load(const Mem&, const Reg&, location_t, int print = 0);
    void do_mem_store(const Mem&, const Reg&, location_t, int print = 0);
}; // end offset_domain_t
