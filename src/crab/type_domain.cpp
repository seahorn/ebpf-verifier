// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

namespace std {
    static ptr_t get_ptr(const ptr_or_mapfd_t& t) {
    return std::visit( overloaded
               {
                   []( const ptr_with_off_t& x ){ return ptr_t{x};},
                   []( const ptr_no_off_t& x ){ return ptr_t{x};},
                   []( auto& ) { return ptr_t{};}
                }, t
            );
    }
}

static std::string size(int w) { return std::string("u") + std::to_string(w * 8); }

static void print_ptr_no_off_type(const ptr_no_off_t& ptr, std::optional<dist_t>& dist) {
    std::cout << ptr;
    if (dist) {
        std::cout << "<" << dist.value() << ">";
    }
}

static void print_ptr_type(const ptr_t& ptr, std::optional<dist_t>& dist) {
    if (std::holds_alternative<ptr_with_off_t>(ptr)) {
        ptr_with_off_t ptr_with_off = std::get<ptr_with_off_t>(ptr);
        std::cout << ptr_with_off;
    }
    else {
        ptr_no_off_t ptr_no_off = std::get<ptr_no_off_t>(ptr);
        print_ptr_no_off_type(ptr_no_off, dist);
    }
}

static void print_ptr_or_mapfd_type(const ptr_or_mapfd_t& ptr_or_mapfd, std::optional<dist_t>& d) {
    if (std::holds_alternative<mapfd_t>(ptr_or_mapfd)) {
        std::cout << std::get<mapfd_t>(ptr_or_mapfd);
    }
    else {
        auto ptr = get_ptr(ptr_or_mapfd);
        print_ptr_type(ptr, d);
    }
}

static void print_number(std::optional<int>& num) {
    std::cout << "number";
    if (num) {
        std::cout << "<" << num.value() << ">";
    }
}

static void print_register(Reg r, std::optional<ptr_or_mapfd_t>& p, std::optional<dist_t>& d,
        std::optional<int>& n) {
    std::cout << r << " : ";
    if (p) {
        print_ptr_or_mapfd_type(p.value(), d);
    }
    else {
        print_number(n);
    }
}

static void print_annotated(const Call& call, std::optional<ptr_or_mapfd_t>& p,
        std::optional<dist_t>& d, std::optional<int>& n) {
    std::cout << "  ";
    print_register(Reg{(uint8_t)R0_RETURN_VALUE}, p, d, n);
    std::cout << " = " << call.name << ":" << call.func << "(...)\n";
}

static void print_annotated(const Bin& b, std::optional<ptr_or_mapfd_t>& p,
        std::optional<dist_t>& d, std::optional<int>& n) {
    std::cout << "  ";
    print_register(b.dst, p, d, n);
    std::cout << " " << b.op << "= " << b.v << "\n";
}

static void print_annotated(const LoadMapFd& u, std::optional<ptr_or_mapfd_t>& p) {
    std::cout << "  ";
    std::optional<dist_t> d;
    std::optional<int> n;
    print_register(u.dst, p, d, n);
    std::cout << " = map_fd " << u.mapfd << "\n";
}

static void print_annotated(const Mem& b, std::optional<ptr_or_mapfd_t>& p,
        std::optional<dist_t>& d, std::optional<int>& n) {
    if (b.is_load) {
        std::cout << "  ";
        print_register(std::get<Reg>(b.value), p, d, n);
        std::cout << " = ";
    }
    std::string sign = b.access.offset < 0 ? " - " : " + ";
    int offset = std::abs(b.access.offset);
    std::cout << "*(" << size(b.access.width) << " *)";
    std::cout << "(" << b.access.basereg << sign << offset << ")\n";
}

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
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

type_domain_t type_domain_t::widen(const type_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

type_domain_t type_domain_t::narrow(const type_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

std::string type_domain_t::domain_name() const {
    return "type_domain";
}

int type_domain_t::get_instruction_count_upper_bound() {
    /* WARNING: The operation is not implemented yet.*/
    return 0;
}

string_invariant type_domain_t::to_set() {
    return string_invariant{};
}

void type_domain_t::operator()(const Undefined & u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const Un &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    if (print > 0) {
        auto reg = reg_with_loc_t(u.dst.v, loc);
        auto region = m_region.find_in_registers(reg);
        print_annotated(u, region);
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const Call &u, location_t loc, int print) {
    if (print > 0) {
        register_t r0_reg{R0_RETURN_VALUE};
        auto r0 = reg_with_loc_t(r0_reg, loc);
        auto region = m_region.find_in_registers(r0);
        auto offset = m_offset.find_in_registers(r0);
        auto constant = m_constant.find_in_registers(r0);
        print_annotated(u, region, offset, constant);
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const Exit &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const Jmp &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const Packet & u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const Assume &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_constant(u, loc);
}

void type_domain_t::operator()(const ValidAccess& s, location_t loc, int print) {
    auto reg_type = m_region.find_ptr_or_mapfd_type(s.reg.v);
    m_offset.check_valid_access(s, reg_type);
}

void type_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
    m_region.check_type_constraint(s);
}

void type_domain_t::operator()(const Assert &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, u.cst);
}

static bool same_region(ptr_or_mapfd_t& p1, ptr_or_mapfd_t& p2) {
    // TODO: refactor/move to appropriate class/struct
    if (std::holds_alternative<ptr_with_off_t>(p1)
            && std::holds_alternative<ptr_with_off_t>(p2)) {
        auto p1_with_off = std::get<ptr_with_off_t>(p1);
        auto p2_with_off = std::get<ptr_with_off_t>(p2);
        return (p1_with_off.get_region() == p2_with_off.get_region());
    }
    else if (std::holds_alternative<ptr_no_off_t>(p1)
            && std::holds_alternative<ptr_no_off_t>(p2)) {
        auto p1_no_off = std::get<ptr_no_off_t>(p1);
        auto p2_no_off = std::get<ptr_no_off_t>(p2);
        return (p1_no_off.get_region() == p2_no_off.get_region());
    }
    return false;
}

void type_domain_t::operator()(const Comparable& u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }

    auto maybe_ptr_type1 = m_region.find_ptr_or_mapfd_type(u.r1.v);
    auto maybe_ptr_type2 = m_region.find_ptr_or_mapfd_type(u.r2.v);
    auto maybe_num_type1 = m_constant.find_const_value(u.r1.v);
    auto maybe_num_type2 = m_constant.find_const_value(u.r2.v);
    if (maybe_ptr_type1 && maybe_ptr_type2) {
        if (!maybe_num_type1 && !maybe_num_type2) {
            // an extra check just to make sure registers are not labelled both ptrs and numbers
            if (same_region(maybe_ptr_type1.value(), maybe_ptr_type2.value())) {
                return;
            }
        }
    }
    else if (!maybe_ptr_type1 && !maybe_ptr_type2) {
        return;
    }
    std::cout << "Non-comparable values\n";
}

void type_domain_t::operator()(const Addable& u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
}

void type_domain_t::operator()(const ValidStore& u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
}


void type_domain_t::operator()(const ValidSize& u, location_t loc, int print) {
    //std::cout << "validSize: " << u << "\n";
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_constant(u, loc);
}

void type_domain_t::operator()(const ValidMapKeyValue& u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
}

void type_domain_t::operator()(const ZeroOffset& u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    auto maybe_ptr_type = m_region.find_ptr_or_mapfd_type(u.reg.v);
    if (maybe_ptr_type && std::holds_alternative<ptr_with_off_t>(maybe_ptr_type.value())) {
        auto ptr_type_with_off = std::get<ptr_with_off_t>(maybe_ptr_type.value());
        if (ptr_type_with_off.get_offset() == 0) return;
    }
    auto maybe_dist = m_offset.find_offset_info(u.reg.v);
    if (maybe_dist && maybe_dist.value().m_dist == 0) return;
    std::cout << "Zero Offset assertion fail\n";
}

type_domain_t type_domain_t::setup_entry() {
    region_domain_t reg = region_domain_t::setup_entry();
    offset_domain_t off = offset_domain_t::setup_entry();
    constant_prop_domain_t cp = constant_prop_domain_t::setup_entry();
    type_domain_t typ(std::move(reg), std::move(off), std::move(cp));
    return typ;
}

void type_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (print > 0) {
        auto reg_with_loc = reg_with_loc_t(bin.dst.v, loc);
        auto region = m_region.find_in_registers(reg_with_loc);
        auto offset = m_offset.find_in_registers(reg_with_loc);
        auto constant = m_constant.find_in_registers(reg_with_loc);
        print_annotated(bin, region, offset, constant);
        return;
    }

    std::optional<ptr_or_mapfd_t> src_type, dst_type;
    std::optional<int> src_const_value;
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg r = std::get<Reg>(bin.v);
        src_type = m_region.find_ptr_or_mapfd_type(r.v);
        src_const_value = m_constant.find_const_value(r.v);
    }
    dst_type = m_region.find_ptr_or_mapfd_type(bin.dst.v);
    m_region.do_bin(bin, src_const_value, loc);
    m_constant.do_bin(bin, loc);
    m_offset.do_bin(bin, src_const_value, src_type, dst_type, loc);
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {

    if (print > 0) {
        auto target_reg_loc = reg_with_loc_t(target_reg.v, loc);
        auto region = m_region.find_in_registers(target_reg_loc);
        auto offset = m_offset.find_in_registers(target_reg_loc);
        auto constant = m_constant.find_in_registers(target_reg_loc);
        print_annotated(b, region, offset, constant);
        return;
    }

    Reg basereg = b.access.basereg;
    auto basereg_type = m_region.find_ptr_or_mapfd_type(basereg.v);

    m_region.do_load(b, target_reg, loc);
    m_constant.do_load(b, target_reg, basereg_type, loc);
    m_offset.do_load(b, target_reg, basereg_type, loc);
}

void type_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc, int print) {

    if (print > 0) {
        std::cout << "  " << b << ";\n";
        return;
    }

    Reg basereg = b.access.basereg;
    auto basereg_type = m_region.find_ptr_or_mapfd_type(basereg.v);
    auto targetreg_type = m_region.find_ptr_or_mapfd_type(target_reg.v);

    m_region.do_mem_store(b, target_reg, loc);
    m_constant.do_mem_store(b, target_reg, basereg_type);
    m_offset.do_mem_store(b, target_reg, basereg_type, targetreg_type);
}

void type_domain_t::operator()(const Mem& b, location_t loc, int print) {
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), loc, print);
        } else {
            do_mem_store(b, std::get<Reg>(b.value), loc, print);
        }
    } else {
        std::string s = std::to_string(static_cast<unsigned int>(std::get<Imm>(b.value).v));
        std::string desc = std::string("\tEither loading to a number (not allowed) or storing a number (not allowed yet) - ") + s + "\n";
        //report_type_error(desc, loc);
        std::cout << desc;
        return;
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
    std::cout << "stack: ";
    std::cout << "{\n";
    for (auto const k : stack_keys) {
        auto ptr_or_mapfd = m_region.find_in_stack(k);
        auto dist = m_offset.find_in_stack(k);
        if (ptr_or_mapfd) {
            std::cout << "  " << k << ": ";
            print_ptr_or_mapfd_type(ptr_or_mapfd.value(), dist);
            std::cout << ",";
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

void type_domain_t::adjust_bb_for_types(location_t loc) {
    m_region.adjust_bb_for_types(loc);
    m_offset.adjust_bb_for_types(loc);
    m_constant.adjust_bb_for_types(loc);
}

void type_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    auto label = bb.label();
    uint32_t curr_pos = 0;
    location_t loc = location_t(std::make_pair(label, curr_pos));
    adjust_bb_for_types(loc);

    if (print > 0) {
        if (label == label_t::entry) {
            print_initial_types();
            m_is_bottom = false;
        }
        std::cout << label << ":\n";
    }

    for (const Instruction& statement : bb) {
        loc = location_t(std::make_pair(label, ++curr_pos));
        if (print > 0)
            std::cout << "   " << curr_pos << ".";
        //if (print <= 0) std::cout << statement << "\n";
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }

    if (print > 0) {
        auto [it, et] = bb.next_blocks();
        if (it != et) {
            std::cout << "  " << "goto ";
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

void type_domain_t::write(std::ostream& o) const {
    if (is_bottom()) {
        o << "_|_";
    } else {
        o << m_region << "\n";
    }
}

std::ostream& operator<<(std::ostream& o, const type_domain_t& typ) {
    typ.write(o);
    return o;
}
