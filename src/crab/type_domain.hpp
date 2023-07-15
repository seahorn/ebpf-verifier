// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "crab/abstract_domain.hpp"
#include "crab/region_domain.hpp"
#include "crab/common.hpp"

namespace crab {

class type_domain_t final {
    crab::region_domain_t m_region;
    bool m_is_bottom = false;
    std::vector<std::string> m_errors;

  public:

    type_domain_t() = default;
    type_domain_t(type_domain_t&& o) = default;
    type_domain_t(const type_domain_t& o) = default;
    explicit type_domain_t(crab::region_domain_t&& reg, bool is_bottom = false) :
        m_region(reg), m_is_bottom(is_bottom) {}
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
    void write(std::ostream& os) const {}
    friend std::ostream& operator<<(std::ostream& o, const type_domain_t& dom);
    std::string domain_name() const;
    crab::bound_t get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f) {}
    [[nodiscard]] std::vector<std::string>& get_errors() { return m_errors; }
    void print_ctx() const;
    void print_stack() const;
    std::optional<crab::ptr_or_mapfd_t> find_ptr_or_mapfd_at_loc(const crab::reg_with_loc_t&) const;

  private:

    void do_load(const Mem&, const Reg&, bool, location_t, int print = 0);
    void do_mem_store(const Mem&, const Reg&, location_t, int print = 0);
    void report_type_error(std::string, location_t);
    void print_registers() const;
    void adjust_bb_for_types(location_t);
    void operator+=(std::vector<std::string>& errs) {
        m_errors.insert(m_errors.end(), errs.begin(), errs.end());
    }
}; // end type_domain_t

} // namespace crab

void print_annotated(std::ostream&, const crab::type_domain_t&, const basic_block_t&, int);
