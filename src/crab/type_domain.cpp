// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

static std::string size(int w) { return std::string("u") + std::to_string(w * 8); }


bool type_domain_t::is_bottom() const {
    return m_is_bottom;
}

bool type_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_region.is_top() && m_offset.is_top());
}

type_domain_t type_domain_t::bottom() {
    type_domain_t typ;
    typ.set_to_bottom();
    return typ;
}

void type_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

void type_domain_t::set_to_top() {
    m_region.set_to_top();
    m_offset.set_to_top();
}

bool type_domain_t::operator<=(const type_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return true;
}

void type_domain_t::operator|=(const type_domain_t& abs) {
}

void type_domain_t::operator|=(type_domain_t&& abs) {
}

type_domain_t type_domain_t::operator|(const type_domain_t& other) const {
    return other;
}

type_domain_t type_domain_t::operator|(type_domain_t&& other) const {
    return other;
}

type_domain_t type_domain_t::operator&(const type_domain_t& abs) const {
    return abs;
}

type_domain_t type_domain_t::widen(const type_domain_t& abs) const {
    return abs;
}

type_domain_t type_domain_t::narrow(const type_domain_t& other) const {
    return other;
}

void type_domain_t::write(std::ostream& os) const { 
}

std::string type_domain_t::domain_name() const {
    return "type_domain";
}

int type_domain_t::get_instruction_count_upper_bound() {
    return 0;
}

string_invariant type_domain_t::to_set() {
    return string_invariant{};
}

void type_domain_t::operator()(const Undefined & u, location_t loc, int print) {
}
void type_domain_t::operator()(const Un &u, location_t loc, int print) {
}
void type_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Call &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Exit &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Jmp &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Packet & u, location_t loc, int print) {
}
void type_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Assume &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Assert &u, location_t loc, int print) {
}

type_domain_t type_domain_t::setup_entry() {
    region_domain_t reg = region_domain_t::setup_entry();
    offset_domain_t off = offset_domain_t::setup_entry();
    type_domain_t typ(std::move(reg), std::move(off));
    return typ;
}

void type_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (is_bottom()) return;

    m_region(bin, loc, print);
    m_offset(bin, loc, print);
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {
    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto it = m_region.m_registers.find(basereg.v);
    ptr_t type_basereg = it.value();
    
    m_region.do_load(b, target_reg, loc, print);
    m_offset.do_load(b, target_reg, type_basereg);
}

void type_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc, int print) {
    int offset = b.access.offset;
    Reg basereg = b.access.basereg;
    int width = b.access.width;

    auto it = m_region.m_registers.find(basereg.v);
    ptr_t type_basereg = it.value();

    auto it2 = m_region.m_registers.find(target_reg.v);
    if (it2) {
        m_region.do_mem_store(b, target_reg, loc, print);
        m_offset.do_mem_store(b, target_reg, type_basereg);
    }
}

void type_domain_t::operator()(const Mem& b, location_t loc, int print) {
    if (is_bottom()) return;
 
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), loc, print);
        } else {
            do_mem_store(b, std::get<Reg>(b.value), loc, print);
        }
    }
}

void type_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    auto label = bb.label();
    uint32_t curr_pos = 0;
    location_t loc;
    for (const Instruction& statement : bb) {
        loc = location_t(std::make_pair(label, ++curr_pos));
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }
}

void type_domain_t::set_require_check(check_require_func_t f) {}
