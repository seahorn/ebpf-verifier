// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/constant_prop_domain.hpp"

bool registers_cp_state_t::is_bottom() const {
    return m_is_bottom;
}

bool registers_cp_state_t::is_top() const {
    if (m_is_bottom) return false;
    for (auto it : m_const_values) {
        if (it != nullptr) return false;
    }
    return true;
}

void registers_cp_state_t::set_to_top() {
    m_const_values = const_values_registers_t{nullptr};
    m_is_bottom = false;
}

void registers_cp_state_t::set_to_bottom() {
    m_is_bottom = true;
}

registers_cp_state_t registers_cp_state_t::operator|(const registers_cp_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    const_values_registers_t const_values_joined;
    for (size_t i = 0; i < m_const_values.size(); i++) {
        if (m_const_values[i] == other.m_const_values[i]) {
            const_values_joined[i] = m_const_values[i];
        }
    }
    return registers_cp_state_t(std::move(const_values_joined));
}

bool stack_cp_state_t::is_bottom() const {
    return m_is_bottom;
}

bool stack_cp_state_t::is_top() const {
    if (m_is_bottom) return false;
    return m_const_values.empty();
}

void stack_cp_state_t::set_to_top() {
    m_const_values.clear();
    m_is_bottom = false;
}

void stack_cp_state_t::set_to_bottom() {
    m_is_bottom = true;
}

stack_cp_state_t stack_cp_state_t::operator|(const stack_cp_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    const_values_stack_t const_values_joined;
    for (auto const&kv: m_const_values) {
        auto it = other.m_const_values.find(kv.first);
        if (it != m_const_values.end() && kv.second == it->second)
            const_values_joined.insert(kv);
    }
    return stack_cp_state_t(std::move(const_values_joined));
}

bool constant_prop_domain_t::is_bottom() const {
    if (m_is_bottom) return true;
    return (m_registers_const_values.is_bottom() || m_stack_slots_const_values.is_bottom());
}

bool constant_prop_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_registers_const_values.is_top() && m_stack_slots_const_values.is_top());
}

constant_prop_domain_t constant_prop_domain_t::bottom() {
    constant_prop_domain_t cp;
    cp.set_to_bottom();
    return cp;
}

void constant_prop_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

void constant_prop_domain_t::set_to_top() {
    m_registers_const_values.set_to_top();
    m_stack_slots_const_values.set_to_top();
}

bool constant_prop_domain_t::operator<=(const constant_prop_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return true;
}

void constant_prop_domain_t::operator|=(const constant_prop_domain_t& abs) {
    constant_prop_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void constant_prop_domain_t::operator|=(constant_prop_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

constant_prop_domain_t constant_prop_domain_t::operator|(const constant_prop_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return constant_prop_domain_t(m_registers_const_values | other.m_registers_const_values,
            m_stack_slots_const_values | other.m_stack_slots_const_values);
}

constant_prop_domain_t constant_prop_domain_t::operator|(constant_prop_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return constant_prop_domain_t(m_registers_const_values | std::move(other.m_registers_const_values),
            m_stack_slots_const_values | std::move(other.m_stack_slots_const_values));
}

constant_prop_domain_t constant_prop_domain_t::operator&(const constant_prop_domain_t& abs) const {
    return abs;
}

constant_prop_domain_t constant_prop_domain_t::widen(const constant_prop_domain_t& abs) const {
    return abs;
}

constant_prop_domain_t constant_prop_domain_t::narrow(const constant_prop_domain_t& other) const {
    return other;
}

void constant_prop_domain_t::write(std::ostream& os) const {}

std::string constant_prop_domain_t::domain_name() const {
    return "constant_prop_domain";
}

int constant_prop_domain_t::get_instruction_count_upper_bound() {
    return 0;
}

string_invariant constant_prop_domain_t::to_set() {
    return string_invariant{};
}

void constant_prop_domain_t::operator()(const Undefined & u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const Un &u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const Call &u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const Exit &u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const Jmp &u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const Packet & u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const Assume &u, location_t loc, int print) {
}

void constant_prop_domain_t::operator()(const ValidAccess& s, location_t loc, int print) {
}

void constant_prop_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
}

void constant_prop_domain_t::operator()(const Assert &u, location_t loc, int print) {
    if (is_bottom()) return;
    std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, u.cst);
}

constant_prop_domain_t constant_prop_domain_t::setup_entry() {
    constant_prop_domain_t typ;
    return typ;
}

void constant_prop_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (is_bottom()) return;
}

void constant_prop_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {
}

void constant_prop_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc, int print) {
}

void constant_prop_domain_t::operator()(const Mem& b, location_t loc, int print) {
    if (is_bottom()) return;

    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), loc, print);
        } else {
            do_mem_store(b, std::get<Reg>(b.value), loc, print);
        }
    }
}

void constant_prop_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    auto label = bb.label();
    uint32_t curr_pos = 0;
    location_t loc;
    for (const Instruction& statement : bb) {
        std::cout << statement << "\n";
        loc = location_t(std::make_pair(label, ++curr_pos));
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }
}

void constant_prop_domain_t::set_require_check(check_require_func_t f) {}
