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

static void print_number(std::optional<interval_t>& num) {
    std::cout << "number";
    if (num) {
        std::cout << "<" << num.value() << ">";
    }
}

static void print_register(Reg r, std::optional<ptr_or_mapfd_t>& p, std::optional<dist_t>& d,
        std::optional<interval_t> n) {
    std::cout << r << " : ";
    if (p) {
        print_ptr_or_mapfd_type(p.value(), d);
    }
    else {
        print_number(n);
    }
}

static void print_annotated(const Call& call, std::optional<ptr_or_mapfd_t>& p,
        std::optional<dist_t>& d, std::optional<interval_t>& n) {
    std::cout << "  ";
    print_register(Reg{(uint8_t)R0_RETURN_VALUE}, p, d, n);
    std::cout << " = " << call.name << ":" << call.func << "(...)\n";
}

static void print_annotated(const Bin& b, std::optional<ptr_or_mapfd_t>& p,
        std::optional<dist_t>& d, std::optional<interval_t>& n) {
    std::cout << "  ";
    print_register(b.dst, p, d, n);
    std::cout << " " << b.op << "= " << b.v << "\n";
}

static void print_annotated(const LoadMapFd& u, std::optional<ptr_or_mapfd_t>& p) {
    std::cout << "  ";
    std::optional<dist_t> d;
    std::optional<interval_t> n;
    print_register(u.dst, p, d, n);
    std::cout << " = map_fd " << u.mapfd << "\n";
}

static void print_annotated(const Mem& b, std::optional<ptr_or_mapfd_t>& p,
        std::optional<dist_t>& d, std::optional<interval_t>& n) {
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
    return (m_region.is_top() && m_offset.is_top() && m_interval.is_top());
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
    m_interval.set_to_top();
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
            m_interval | other.m_interval);
}

type_domain_t type_domain_t::operator|(type_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_region | std::move(other.m_region),
            m_offset | std::move(other.m_offset), m_interval | std::move(other.m_interval));
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
    m_interval(u, loc);
}

void type_domain_t::operator()(const Un &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    if (print > 0) {
        auto reg = reg_with_loc_t(u.dst.v, loc);
        auto region = m_region.find_ptr_or_mapfd_at_loc(reg);
        print_annotated(u, region);
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const Call &u, location_t loc, int print) {
    if (print > 0) {
        register_t r0_reg{R0_RETURN_VALUE};
        auto r0 = reg_with_loc_t(r0_reg, loc);
        auto region = m_region.find_ptr_or_mapfd_at_loc(r0);
        auto offset = m_offset.find_offset_at_loc(r0);
        auto interval = m_interval.find_interval_at_loc(r0);
        print_annotated(u, region, offset, interval);
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const Exit &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const Jmp &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const Packet & u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const Assume &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    m_region(u, loc);
    m_offset(u, loc);
    m_interval(u, loc);
}

void type_domain_t::operator()(const ValidAccess& s, location_t loc, int print) {
    auto reg_type = m_region.find_ptr_or_mapfd_type(s.reg.v);
    m_offset.check_valid_access(s, reg_type);
}

void type_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
    m_region(s, loc);
}

void type_domain_t::operator()(const Assert &u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }
    std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, u.cst);
}

static bool is_mapfd_type(const ptr_or_mapfd_t& ptr_or_mapfd) {
    return (std::holds_alternative<mapfd_t>(ptr_or_mapfd));
}

static region_t get_region(const ptr_t& ptr) {
    if (std::holds_alternative<ptr_with_off_t>(ptr)) {
        return std::get<ptr_with_off_t>(ptr).get_region();
    }
    else {
        return std::get<ptr_no_off_t>(ptr).get_region();
    }
}

void type_domain_t::operator()(const Comparable& u, location_t loc, int print) {
    if (print > 0) {
        std::cout << "  " << u << "\n";
        return;
    }

    auto maybe_ptr_or_mapfd1 = m_region.find_ptr_or_mapfd_type(u.r1.v);
    auto maybe_ptr_or_mapfd2 = m_region.find_ptr_or_mapfd_type(u.r2.v);
    auto maybe_interval1 = m_interval.find_interval_value(u.r1.v);
    auto maybe_interval2 = m_interval.find_interval_value(u.r2.v);
    if (maybe_ptr_or_mapfd1 && maybe_ptr_or_mapfd2) {
        if (!maybe_interval1 && !maybe_interval2) {
            // an extra check just to make sure registers are not labelled both ptrs and numbers
            auto ptr_or_mapfd1 = maybe_ptr_or_mapfd1.value();
            auto ptr_or_mapfd2 = maybe_ptr_or_mapfd1.value();
            if (is_mapfd_type(ptr_or_mapfd1) && is_mapfd_type(ptr_or_mapfd2)) {
                return;
            }
            else if (!is_mapfd_type(ptr_or_mapfd1) && !is_mapfd_type(ptr_or_mapfd2)) {
                auto ptr1 = get_ptr(ptr_or_mapfd1);
                auto ptr2 = get_ptr(ptr_or_mapfd2);
                if (get_region(ptr1) == get_region(ptr2)) {
                    return;
                }
            }
        }
    }
    else if (!maybe_ptr_or_mapfd1 && !maybe_ptr_or_mapfd2) {
        // all other cases when we do not have a ptr or mapfd, the type is a number
        return;
    }
    std::cout << "Non-comparable types\n";
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
    m_interval(u, loc);
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
    if (maybe_dist) {
        auto dist_val = maybe_dist.value().m_dist;
        auto single_val = dist_val.singleton();
        if (single_val) {
            auto dist_value = single_val.value();
            if (dist_value == number_t(0)) return;
        }
    }
    std::cout << "Zero Offset assertion fail\n";
}

type_domain_t type_domain_t::setup_entry() {
    region_domain_t reg = region_domain_t::setup_entry();
    offset_domain_t off = offset_domain_t::setup_entry();
    interval_prop_domain_t cp = interval_prop_domain_t::setup_entry();
    type_domain_t typ(std::move(reg), std::move(off), std::move(cp));
    return typ;
}

void type_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (print > 0) {
        auto reg_with_loc = reg_with_loc_t(bin.dst.v, loc);
        auto region = m_region.find_ptr_or_mapfd_at_loc(reg_with_loc);
        auto offset = m_offset.find_offset_at_loc(reg_with_loc);
        auto interval = m_interval.find_interval_at_loc(reg_with_loc);
        print_annotated(bin, region, offset, interval);
        return;
    }

    std::optional<ptr_or_mapfd_t> src_type, dst_type;
    std::optional<interval_t> src_interval_value;
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg r = std::get<Reg>(bin.v);
        src_type = m_region.find_ptr_or_mapfd_type(r.v);
        src_interval_value = m_interval.find_interval_value(r.v);
    }
    dst_type = m_region.find_ptr_or_mapfd_type(bin.dst.v);
    m_region.do_bin(bin, src_interval_value, loc);
    m_interval(bin, loc);
    m_offset.do_bin(bin, src_interval_value, src_type, dst_type, loc);
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {

    if (print > 0) {
        auto target_reg_loc = reg_with_loc_t(target_reg.v, loc);
        auto region = m_region.find_ptr_or_mapfd_at_loc(target_reg_loc);
        auto offset = m_offset.find_offset_at_loc(target_reg_loc);
        auto interval = m_interval.find_interval_at_loc(target_reg_loc);
        print_annotated(b, region, offset, interval);
        return;
    }

    Reg basereg = b.access.basereg;
    auto basereg_type = m_region.find_ptr_or_mapfd_type(basereg.v);

    m_region.do_load(b, target_reg, loc);
    m_interval.do_load(b, target_reg, basereg_type, loc);
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
    m_interval.do_mem_store(b, target_reg, basereg_type);
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

// the method does not work well as it requires info about the label of basic block we are in
// this info is not available when we are only printing any state
// but it is available when we are processing a basic block for all its instructions:w
//
void type_domain_t::print_registers() const {
    std::cout << "\tregister types: {\n";
    for (size_t i = 0; i < NUM_REGISTERS; i++) {
        register_t reg = (register_t)i;
        auto maybe_ptr_or_mapfd_type = m_region.find_ptr_or_mapfd_type(reg);
        auto maybe_offset = m_offset.find_offset_info(reg);
        auto maybe_interval = m_interval.find_interval_value(reg);
        if (maybe_ptr_or_mapfd_type || maybe_interval) {
            std::cout << "\t\t";
            print_register(Reg{(uint8_t)reg}, maybe_ptr_or_mapfd_type, maybe_offset,
                    maybe_interval);
            std::cout << "\n";
        }
    }
    std::cout << "\t}\n";
}

void type_domain_t::print_ctx() const {
    std::vector<int> ctx_keys = m_region.get_ctx_keys();
    std::cout << "\tctx: {\n";
    for (auto const& k : ctx_keys) {
        auto ptr = m_region.find_in_ctx(k);
        auto dist = m_offset.find_in_ctx(k);
        if (ptr) {
            std::cout << "\t\t" << k << ": ";
            print_ptr_type(ptr.value(), dist);
            std::cout << ",\n";
        }
    }
    std::cout << "\t}\n";
}

void type_domain_t::print_stack() const {
    std::vector<int> stack_keys_region = m_region.get_stack_keys();
    std::vector<int> stack_keys_interval = m_interval.get_stack_keys();
    std::cout << "\tstack: {\n";
    for (auto const k : stack_keys_region) {
        auto ptr_or_mapfd = m_region.find_in_stack(k);
        auto dist = m_offset.find_in_stack(k);
        if (ptr_or_mapfd) {
            std::cout << "\t\t" << k << ": ";
            print_ptr_or_mapfd_type(ptr_or_mapfd.value(), dist);
            std::cout << ",\n";
        }
    }
    for (auto const k : stack_keys_interval) {
        auto interval = m_interval.find_in_stack(k);
        if (interval) {
            std::cout << "\t\t" << k << ": ";
            print_number(interval);
            std::cout << ",\n";
        }
    }
    std::cout << "\t}\n";
}

void type_domain_t::adjust_bb_for_types(location_t loc) {
    m_region.adjust_bb_for_types(loc);
    m_offset.adjust_bb_for_types(loc);
    m_interval.adjust_bb_for_types(loc);
}

void type_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    auto label = bb.label();
    if (print < 0) {
        std::cout << "state of stack and ctx in program:\n";
        print_ctx();
        print_stack();
        std::cout << "\n";
        return;
    }
    if (print > 0) {
        if (label == label_t::entry) {
            m_is_bottom = false;
        }
        std::cout << label << ":\n";
    }

    uint32_t curr_pos = 0;
    location_t loc = location_t(std::make_pair(label, curr_pos));
    if (print == 0)
        adjust_bb_for_types(loc);

    for (const Instruction& statement : bb) {
        loc = location_t(std::make_pair(label, ++curr_pos));
        if (print > 0)
            std::cout << "   " << curr_pos << ".";
        //if (print <= 0) std::cout << statement << "\n";
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
        //if (print > 0 && error_location->first == loc->first && error_location->second == loc->second) std::cout << "type_error\n";
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
    }
}

std::ostream& operator<<(std::ostream& o, const type_domain_t& typ) {
    typ.write(o);
    return o;
}
