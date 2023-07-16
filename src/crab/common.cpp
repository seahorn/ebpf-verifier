// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "crab/common.hpp"

/*
namespace std {
    crab::ptr_t get_ptr(const crab::ptr_or_mapfd_t& t) {
    return std::visit( overloaded
               {
                   []( const crab::ptr_with_off_t& x ){ return crab::ptr_t{x};},
                   []( const crab::ptr_no_off_t& x ){ return crab::ptr_t{x};},
                   []( auto& ) { return crab::ptr_t{};}
                }, t
            );
    }
} // namespace std
*/

namespace crab {

bool ptr_with_off_t::operator==(const ptr_with_off_t& other) const {
    return (m_r == other.m_r && m_offset == other.m_offset
            && m_region_size == other.m_region_size);
}

bool ptr_with_off_t::operator!=(const ptr_with_off_t& other) const {
    return !(*this == other);
}

bool ptr_no_off_t::operator==(const ptr_no_off_t& other) const {
    return (m_r == other.m_r);
}

bool ptr_no_off_t::operator!=(const ptr_no_off_t& other) const {
    return !(*this == other);
}

bool mapfd_t::operator==(const mapfd_t& other) const {
    return (m_mapfd == other.m_mapfd);
}

mapfd_t mapfd_t::operator|(const mapfd_t& other) const {
    auto value_type = m_value_type == other.m_value_type ? m_value_type : EbpfMapValueType::ANY;
    return mapfd_t(m_mapfd | other.m_mapfd, value_type);
}

interval_t ptr_with_off_t::get_region_size() const { return m_region_size; }

void ptr_with_off_t::set_offset(interval_t off) { m_offset = off; }

void ptr_with_off_t::set_region_size(interval_t region_sz) { m_region_size = region_sz; }

void ptr_with_off_t::set_region(region_t r) { m_r = r; }

ptr_with_off_t ptr_with_off_t::operator|(const ptr_with_off_t& other) const {
    return ptr_with_off_t(m_r, m_offset | other.m_offset, m_region_size | other.m_region_size);
}

void ptr_no_off_t::set_region(region_t r) { m_r = r; }

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
