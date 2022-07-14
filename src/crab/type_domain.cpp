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
    type_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void type_domain_t::operator|=(type_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

type_domain_t type_domain_t::operator|(const type_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_region | other.m_region, m_offset | other.m_offset);
}

type_domain_t type_domain_t::operator|(type_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_region | std::move(other.m_region), m_offset | std::move(m_offset));
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
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const Un &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const Call &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const Exit &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const Jmp &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const Packet & u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const Assume &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}
void type_domain_t::operator()(const Assert &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
}

type_domain_t type_domain_t::setup_entry() {
    region_domain_t reg = region_domain_t::setup_entry();
    offset_domain_t off = offset_domain_t::setup_entry();
    type_domain_t typ(std::move(reg), std::move(off));
    return typ;
}

void type_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (is_bottom()) return;

    std::optional<ptr_t> src_type, dst_type;
    if (std::holds_alternative<Reg>(bin.v)) {   // for va = vb, type of vb
        src_type = m_region.m_registers.find(std::get<Reg>(bin.v).v);
    }
    else {  // for va += vb, type of va
        dst_type = m_region.m_registers.find(bin.dst.v);
    }
    m_region(bin, loc, print);
    m_offset.do_bin(bin, src_type, dst_type);
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {
    Reg basereg = b.access.basereg;
    auto basereg_type = m_region.m_registers.find(basereg.v);

    m_region.do_load(b, target_reg, loc, print);
    m_offset.do_load(b, target_reg, basereg_type);
}

void type_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc, int print) {
    Reg basereg = b.access.basereg;
    auto basereg_type = m_region.m_registers.find(basereg.v);
    auto targetreg_type = m_region.m_registers.find(target_reg.v);

    m_region.do_mem_store(b, target_reg, loc, print);
    m_offset.do_mem_store(b, target_reg, basereg_type, targetreg_type);
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
        std::cout << statement << "\n";
        loc = location_t(std::make_pair(label, ++curr_pos));
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }
}

void type_domain_t::set_require_check(check_require_func_t f) {}
