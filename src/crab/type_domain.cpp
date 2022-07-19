// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

bool type_domain_t::is_bottom() const {
    return m_is_bottom;
}

bool type_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_region.is_top() && m_offset.is_top() && m_constant.is_top());
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
    m_constant.set_to_top();
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
    return type_domain_t(m_region | other.m_region, m_offset | other.m_offset,
            m_constant | other.m_constant);
}

type_domain_t type_domain_t::operator|(type_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_region | std::move(other.m_region), m_offset | std::move(m_offset),
            m_constant | std::move(other.m_constant));
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
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const Un &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const Call &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const Exit &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const Jmp &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const Packet & u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}
void type_domain_t::operator()(const Assume &u, location_t loc, int print) {
    if (is_bottom()) return;
    m_region(u, loc, print);
    m_offset(u, loc, print);
    m_constant(u, loc, print);
}

void type_domain_t::operator()(const ValidAccess& s, location_t loc, int print) {
    auto reg_type = m_region.find_ptr_type(s.reg.v);
    m_offset.check_valid_access(s, reg_type);
}

void type_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
    m_region.check_type_constraint(s);
}

void type_domain_t::operator()(const Assert &u, location_t loc, int print) {
    if (is_bottom()) return;
    std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, u.cst);
}

type_domain_t type_domain_t::setup_entry() {
    region_domain_t reg = region_domain_t::setup_entry();
    offset_domain_t off = offset_domain_t::setup_entry();
    constant_prop_domain_t cp = constant_prop_domain_t::setup_entry();
    type_domain_t typ(std::move(reg), std::move(off), std::move(cp));
    return typ;
}

void type_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (is_bottom()) return;

    std::optional<ptr_t> src_type, dst_type;
    std::shared_ptr<int> src_const_value;
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg r = std::get<Reg>(bin.v);
        src_type = m_region.find_ptr_type(r.v);
        src_const_value = m_constant.find_const_value(r.v);
    }
    else {
        dst_type = m_region.find_ptr_type(bin.dst.v);
    }
    m_region.do_bin(bin, src_const_value, loc, print);
    m_constant.do_bin(bin);
    m_offset.do_bin(bin, src_const_value, src_type, dst_type, loc, print);
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {
    Reg basereg = b.access.basereg;
    auto basereg_type = m_region.find_ptr_type(basereg.v);

    m_region.do_load(b, target_reg, loc, print);
    m_constant.do_load(b, target_reg, basereg_type);
    m_offset.do_load(b, target_reg, basereg_type, loc, print);
}

void type_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc, int print) {
    Reg basereg = b.access.basereg;
    auto basereg_type = m_region.find_ptr_type(basereg.v);
    auto targetreg_type = m_region.find_ptr_type(target_reg.v);

    m_region.do_mem_store(b, target_reg, loc, print);
    m_constant.do_mem_store(b, target_reg, basereg_type);
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

static void print_ptr_no_off_type(ptr_no_off_t ptr, std::optional<dist_t> dist) {
    std::cout << ptr;
    if (dist) {
        std::cout << "<" << dist.value() << ">";
    }
}

static void print_ptr_type(ptr_t ptr, std::optional<dist_t> dist) {
    if (std::holds_alternative<ptr_with_off_t>(ptr)) {
        ptr_with_off_t ptr_with_off = std::get<ptr_with_off_t>(ptr);
        std::cout << ptr_with_off;
    }
    else {
        ptr_no_off_t ptr_no_off = std::get<ptr_no_off_t>(ptr);
        print_ptr_no_off_type(ptr_no_off, dist);
    }
}

void type_domain_t::print_ctx() const {
    std::vector<int> ctx_keys = m_region.get_ctx_keys();
    std::cout << "ctx: {\n";
    for (auto const k : ctx_keys) {
        std::optional<ptr_t> ptr = m_region.find_in_ctx(k);
        std::optional<dist_t> dist = m_offset.find_in_ctx(k);
        if (ptr) {
            std::cout << "  " << k << ": ";
            print_ptr_type(ptr.value(), dist);
            std::cout << ",\n";
        }
    }
    std::cout << "}\n\n";
}

void type_domain_t::print_stack() const {
    std::vector<int> stack_keys = m_region.get_stack_keys();
    std::cout << "stack: {\n";
    for (auto const k : stack_keys) {
        std::optional<ptr_t> ptr = m_region.find_in_stack(k);
        std::optional<dist_t> dist = m_offset.find_in_stack(k);
        if (ptr) {
            std::cout << "  " << k << ": ";
            print_ptr_type(ptr.value(), dist);
            std::cout << ",\n";
        }
    }
    std::cout << "}\n\n";
}

void type_domain_t::print_initial_registers() const {
    auto label = label_t::entry;
    location_t loc = location_t(std::make_pair(label, 0));
    std::cout << "Initial register types:\n";
    m_region.print_registers_at(loc);
}

void type_domain_t::print_initial_types() const {
    print_ctx();
    print_stack();
    print_initial_registers();
}

void type_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    auto label = bb.label();
    uint32_t curr_pos = 0;
    location_t loc;
    if (print > 0) {
        if (label == label_t::entry) {
            print_initial_types();
            m_is_bottom = false;
        }
        std::cout << label << ":\n";
    }

    for (const Instruction& statement : bb) {
        loc = location_t(std::make_pair(label, ++curr_pos));
        if (print > 0) std::cout << " " << curr_pos << ".";
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }

    if (print > 0) {
        auto [it, et] = bb.next_blocks();
        if (it != et) {
            std::cout << "  "
            << "goto ";
            for (; it != et;) {
                std::cout << *it;
                ++it;
                if (it == et) {
                    std::cout << ";";
                } else {
                    std::cout << ",";
                }
            }
        }
        std::cout << "\n\n";
    }
}
