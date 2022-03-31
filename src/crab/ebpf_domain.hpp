// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>
#include <vector>

#include "crab/abstract_domain.hpp"
#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

class ebpf_domain_t final {
  using location_t = boost::optional<std::pair<label_t, uint32_t>>;
  public:
    ebpf_domain_t();
    // Create an instance ebpf domain that resembles the initial state
    // of eBPF (r1 points to context, r10 points to stack, etc).
    static ebpf_domain_t setup_entry(bool check_termination);

    // Generic abstract domain operations
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    bool operator<=(const ebpf_domain_t& other) const;
    void operator|=(ebpf_domain_t&& other);
    void operator|=(const ebpf_domain_t& other);
    ebpf_domain_t operator|(ebpf_domain_t&& other) const;
    ebpf_domain_t operator|(const ebpf_domain_t& other) const;
    ebpf_domain_t operator&(const ebpf_domain_t& other) const;
    ebpf_domain_t widen(const ebpf_domain_t& other) const;
    ebpf_domain_t narrow(const ebpf_domain_t& other) const;

    // Abstract transformers
    void operator()(const basic_block_t& bb, bool check_termination);
    void operator()(const Addable&, location_t loc = boost::none);
    void operator()(const Assert&, location_t loc = boost::none);
    void operator()(const Assume&, location_t loc = boost::none);
    void operator()(const Bin&, location_t loc = boost::none);
    void operator()(const Call&, location_t loc = boost::none);
    void operator()(const Comparable&, location_t loc = boost::none);
    void operator()(const Exit&, location_t loc = boost::none);
    void operator()(const Jmp&, location_t loc = boost::none);
    void operator()(const LoadMapFd&, location_t loc = boost::none);
    void operator()(const LockAdd&, location_t loc = boost::none);
    void operator()(const Mem&, location_t loc = boost::none);
    void operator()(const Packet&, location_t loc = boost::none);
    void operator()(const TypeConstraint&, location_t loc = boost::none);
    void operator()(const Un&, location_t loc = boost::none);
    void operator()(const Undefined&, location_t loc = boost::none);
    void operator()(const ValidAccess&, location_t loc = boost::none);
    void operator()(const ValidMapKeyValue&, location_t loc = boost::none);
    void operator()(const ValidSize&, location_t loc = boost::none);
    void operator()(const ValidStore&, location_t loc = boost::none);
    void operator()(const ZeroOffset&, location_t loc = boost::none);

    void write(std::ostream& o) const;
    std::string domain_name() const;

    // To perform checks while computing fixpoint
    void set_require_check(check_require_func_t f);
    // For termination
    int get_instruction_count_upper_bound();
    // Translate from/to string format
    static ebpf_domain_t from_constraints(const std::set<std::string>& constraints);
    string_invariant to_set();

  private:
    ebpf_domain_t(crab::domains::NumAbsDomain&& inv, crab::domains::array_domain_t&& stack);

    // private generic domain functions
    void operator+=(const linear_constraint_t& cst);
    void operator-=(variable_t var);

    void assign(variable_t lhs, variable_t rhs);
    void assign(variable_t x, const linear_expression_t& e);
    void assign(variable_t x, long e);

    void apply(crab::arith_binop_t op, variable_t x, variable_t y, const number_t& z);
    void apply(crab::arith_binop_t op, variable_t x, variable_t y, variable_t z);
    void apply(crab::bitwise_binop_t op, variable_t x, variable_t y, variable_t z);
    void apply(crab::bitwise_binop_t op, variable_t x, variable_t y, const number_t& k);
    void apply(crab::binop_t op, variable_t x, variable_t y, const number_t& z);
    void apply(crab::binop_t op, variable_t x, variable_t y, variable_t z);

    void apply(crab::domains::NumAbsDomain& inv, crab::binop_t op, variable_t x, variable_t y, const number_t& z,
               bool finite_width = false);
    void apply(crab::domains::NumAbsDomain& inv, crab::binop_t op, variable_t x, variable_t y, variable_t z,
               bool finite_width = false);

    void add(variable_t lhs, variable_t op2);
    void add(variable_t lhs, const number_t& op2);
    void sub(variable_t lhs, variable_t op2);
    void sub(variable_t lhs, const number_t& op2);
    void add_overflow(variable_t lhs, variable_t op2);
    void add_overflow(variable_t lhs, const number_t& op2);
    void sub_overflow(variable_t lhs, variable_t op2);
    void sub_overflow(variable_t lhs, const number_t& op2);
    void neg(variable_t lhs);
    void mul(variable_t lhs, variable_t op2);
    void mul(variable_t lhs, const number_t& op2);
    void div(variable_t lhs, variable_t op2);
    void div(variable_t lhs, const number_t& op2);
    void udiv(variable_t lhs, variable_t op2);
    void udiv(variable_t lhs, const number_t& op2);
    void rem(variable_t lhs, variable_t op2);
    void rem(variable_t lhs, const number_t& op2, bool mod = true);
    void urem(variable_t lhs, variable_t op2);
    void urem(variable_t lhs, const number_t& op2);

    void bitwise_and(variable_t lhs, variable_t op2);
    void bitwise_and(variable_t lhs, const number_t& op2);
    void bitwise_or(variable_t lhs, variable_t op2);
    void bitwise_or(variable_t lhs, const number_t& op2);
    void bitwise_xor(variable_t lhs, variable_t op2);
    void bitwise_xor(variable_t lhs, const number_t& op2);
    void shl_overflow(variable_t lhs, variable_t op2);
    void shl_overflow(variable_t lhs, const number_t& op2);
    void lshr(variable_t lhs, variable_t op2);
    void lshr(variable_t lhs, const number_t& op2);
    void ashr(variable_t lhs, variable_t op2);
    void ashr(variable_t lhs, const number_t& op2);

    void assume(const linear_constraint_t& cst);

    /// Forget everything we know about the value of a variable.
    void havoc(variable_t v);

    void scratch_caller_saved_registers();
    std::optional<uint32_t> get_map_type(const Reg& map_fd_reg) const;
    std::optional<uint32_t> get_map_inner_map_fd(const Reg& map_fd_reg) const;
    crab::interval_t get_map_key_size(const Reg& map_fd_reg) const;
    crab::interval_t get_map_value_size(const Reg& map_fd_reg) const;
    crab::interval_t get_map_max_entries(const Reg& map_fd_reg) const;
    void forget_packet_pointers();
    void do_load_mapfd(const Reg& dst_reg, int mapfd, bool maybe_null);

    void overflow(variable_t lhs);

    void assign_valid_ptr(const Reg& dst_reg, bool maybe_null);

    void require(crab::domains::NumAbsDomain& inv, const linear_constraint_t& cst, const std::string& s);

    // memory check / load / store
    void check_access_stack(crab::domains::NumAbsDomain& inv, const linear_expression_t& lb,
                            const linear_expression_t& ub, const std::string& s);
    void check_access_context(crab::domains::NumAbsDomain& inv, const linear_expression_t& lb,
                              const linear_expression_t& ub, const std::string& s);
    void check_access_packet(crab::domains::NumAbsDomain& inv, const linear_expression_t& lb,
                             const linear_expression_t& ub, const std::string& s,
                             std::optional<variable_t> region_size);
    void check_access_shared(crab::domains::NumAbsDomain& inv, const linear_expression_t& lb,
                             const linear_expression_t& ub, const std::string& s, variable_t region_size);

    void do_load_stack(crab::domains::NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr,
                       int width);
    void do_load_ctx(crab::domains::NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague,
                     int width);
    void do_load_packet_or_shared(crab::domains::NumAbsDomain& inv, const Reg& target_reg,
                                  const linear_expression_t& addr, int width);
    void do_load(const Mem& b, const Reg& target_reg);

    template <typename A, typename X, typename Y>
    void do_store_stack(crab::domains::NumAbsDomain& inv, int width, const A& addr, X val_type, Y val_value,
                        std::optional<variable_t> opt_val_offset, std::optional<variable_t> opt_val_region_size);

    template <typename Type, typename Value>
    void do_mem_store(const Mem& b, Type val_type, Value val_value, std::optional<variable_t> opt_val_offset,
                      std::optional<variable_t> opt_val_region_size);

    friend std::ostream& operator<<(std::ostream& o, const ebpf_domain_t& dom);

    static void initialize_packet(ebpf_domain_t& inv);

  private:
    /// Mapping from variables (including registers, types, offsets,
    /// memory locations, etc.) to numeric intervals or relationships
    /// to other variables.
    crab::domains::NumAbsDomain m_inv;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    crab::domains::array_domain_t stack;

    check_require_func_t check_require{};
    bool get_map_fd_range(const Reg& map_fd_reg, int* start_fd, int* end_fd) const;

    struct TypeDomain {
        void assign_type(crab::domains::NumAbsDomain& inv, const Reg& lhs, type_encoding_t t);
        void assign_type(crab::domains::NumAbsDomain& inv, const Reg& lhs, const Reg& rhs);
        void assign_type(crab::domains::NumAbsDomain& inv, const Reg& lhs,
                         const std::optional<linear_expression_t>& rhs);
        void assign_type(crab::domains::NumAbsDomain& inv, std::optional<variable_t> lhs, const Reg& rhs);
        void assign_type(crab::domains::NumAbsDomain& inv, std::optional<variable_t> lhs, int rhs);

        void havoc_type(crab::domains::NumAbsDomain& inv, const Reg& r);

        [[nodiscard]] int get_type(const crab::domains::NumAbsDomain& inv, variable_t v) const;
        [[nodiscard]] int get_type(const crab::domains::NumAbsDomain& inv, const Reg& r) const;
        [[nodiscard]] int get_type(const crab::domains::NumAbsDomain& inv, int t) const;

        [[nodiscard]] bool same_type(const crab::domains::NumAbsDomain& inv, const Reg& a, const Reg& b) const;
        [[nodiscard]] bool implies_type(const crab::domains::NumAbsDomain& inv, const linear_constraint_t& a,
                                        const linear_constraint_t& b) const;

        crab::domains::NumAbsDomain
        join_over_types(const crab::domains::NumAbsDomain& inv, const Reg& reg,
                        const std::function<void(crab::domains::NumAbsDomain&, type_encoding_t)>& transition) const;
        crab::domains::NumAbsDomain
        join_by_if_else(const crab::domains::NumAbsDomain& inv, const linear_constraint_t& condition,
                        const std::function<void(crab::domains::NumAbsDomain&)>& if_true,
                        const std::function<void(crab::domains::NumAbsDomain&)>& if_false) const;

        bool is_in_group(const crab::domains::NumAbsDomain& inv, const Reg& r, TypeGroup group) const;
    };

    TypeDomain type_inv;

    void assign_region_size(const Reg& r, const crab::interval_t& size);
}; // end ebpf_domain_t
