// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "crab/common.hpp"

namespace std {
    template <>
    struct hash<crab::reg_with_loc_t> {
        size_t operator()(const crab::reg_with_loc_t& reg) const { return reg.hash(); }
    };

    static crab::ptr_t get_ptr(const crab::ptr_or_mapfd_t& t) {
    return std::visit( overloaded
               {
                   []( const crab::ptr_with_off_t& x ){ return crab::ptr_t{x};},
                   []( const crab::ptr_no_off_t& x ){ return crab::ptr_t{x};},
                   []( auto& ) { return crab::ptr_t{};}
                }, t
            );
    }
}

namespace crab {

bool same_region(const ptr_t& ptr1, const ptr_t& ptr2) {
    return ((std::holds_alternative<ptr_with_off_t>(ptr1)
                && std::holds_alternative<ptr_with_off_t>(ptr2))
            || (std::holds_alternative<ptr_no_off_t>(ptr1)
                && std::holds_alternative<ptr_no_off_t>(ptr2)));
}

inline std::ostream& operator<<(std::ostream& o, const region_t& t) {
    o << static_cast<std::underlying_type<region_t>::type>(t);
    return o;
}

bool operator==(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
    return (p1.get_region() == p2.get_region() && p1.get_offset() == p2.get_offset()
            && p1.get_region_size() == p2.get_region_size());
}

bool operator!=(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
    return !(p1 == p2);
}

interval_t ptr_with_off_t::get_region_size() const { return m_region_size; }

void ptr_with_off_t::set_offset(interval_t off) { m_offset = off; }

void ptr_with_off_t::set_region_size(interval_t region_sz) { m_region_size = region_sz; }

void ptr_with_off_t::set_region(region_t r) { m_r = r; }

ptr_with_off_t ptr_with_off_t::operator|(const ptr_with_off_t& other) const {
    return ptr_with_off_t(m_r, m_offset | other.m_offset, m_region_size | other.m_region_size);
}

bool operator==(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
    return (p1.get_region() == p2.get_region());
}

bool operator!=(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
    return !(p1 == p2);
}

void ptr_no_off_t::set_region(region_t r) { m_r = r; }

bool operator==(const mapfd_t& m1, const mapfd_t& m2) {
    return (m1.get_value_type() == m2.get_value_type());
}

std::ostream& operator<<(std::ostream& o, const mapfd_t& m) {
    m.write(o);
    return o;
}

bool mapfd_t::has_type_map_programs() const {
    return (m_value_type == EbpfMapValueType::PROGRAM);
}

void mapfd_t::write(std::ostream& o) const {
    if (has_type_map_programs()) {
        o << "map_fd_programs";
    }
    else {
        o << "map_fd";
    }
}

void reg_with_loc_t::write(std::ostream& o) const {
    o << "r" << static_cast<unsigned int>(m_reg) << "@" << m_loc->second << " in " << m_loc->first << " ";
}

std::ostream& operator<<(std::ostream& o, const reg_with_loc_t& reg) {
    reg.write(o);
    return o;
}

bool reg_with_loc_t::operator==(const reg_with_loc_t& other) const {
    return (m_reg == other.m_reg && m_loc == other.m_loc);
}

std::size_t reg_with_loc_t::hash() const {
    // Similar to boost::hash_combine
    using std::hash;

    std::size_t seed = hash<register_t>()(m_reg);
    seed ^= hash<int>()(m_loc->first.from) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= hash<int>()(m_loc->first.to) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= hash<int>()(m_loc->second) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

    return seed;
}

inline std::string get_reg_ptr(const region_t& r) {
    switch (r) {
        case region_t::T_CTX:
            return "ctx_p";
        case region_t::T_STACK:
            return "stack_p";
        case region_t::T_PACKET:
            return "packet_p";
        default:
            return "shared_p";
    }
}

void ptr_with_off_t::write(std::ostream& o) const {
    o << get_reg_ptr(m_r) << "<" << m_offset;
    if (m_region_size.lb() >= number_t{0}) o << "," << m_region_size;
    o << ">";
}

std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p) {
    p.write(o);
    return o;
}

void ptr_no_off_t::write(std::ostream& o) const {
    o << get_reg_ptr(get_region());
}

std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p) {
    p.write(o);
    return o;
}

} // namespace crab

void print_ptr_type(const crab::ptr_t& ptr) {
    if (std::holds_alternative<crab::ptr_with_off_t>(ptr)) {
        crab::ptr_with_off_t ptr_with_off = std::get<crab::ptr_with_off_t>(ptr);
        std::cout << ptr_with_off;
    }
    else {
        crab::ptr_no_off_t ptr_no_off = std::get<crab::ptr_no_off_t>(ptr);
        std::cout << ptr_no_off;
    }
}

void print_ptr_or_mapfd_type(const crab::ptr_or_mapfd_t& ptr_or_mapfd) {
    if (std::holds_alternative<crab::mapfd_t>(ptr_or_mapfd)) {
        std::cout << std::get<crab::mapfd_t>(ptr_or_mapfd);
    }
    else {
        auto ptr = get_ptr(ptr_or_mapfd);
        print_ptr_type(ptr);
    }
}

void print_register(Reg r, std::optional<crab::ptr_or_mapfd_t>& p) {
    std::cout << r << " : ";
    if (p) {
        print_ptr_or_mapfd_type(p.value());
    }
}

inline std::string size_(int w) { return std::string("u") + std::to_string(w * 8); }

void print_annotated(std::ostream& o, const Call& call, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(Reg{(uint8_t)R0_RETURN_VALUE}, p);
    o << " = " << call.name << ":" << call.func << "(...)\n";
}

void print_annotated(std::ostream& o, const Bin& b, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(b.dst, p);
    o << " " << b.op << "= " << b.v << "\n";
}

void print_annotated(std::ostream& o, const LoadMapFd& u, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(u.dst, p);
    o << " = map_fd " << u.mapfd << "\n";
}

void print_annotated(std::ostream& o, const Mem& b, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(std::get<Reg>(b.value), p);
    o << " = ";
    std::string sign = b.access.offset < 0 ? " - " : " + ";
    int offset = std::abs(b.access.offset);
    o << "*(" << size_(b.access.width) << " *)";
    o << "(" << b.access.basereg << sign << offset << ")\n";
}
