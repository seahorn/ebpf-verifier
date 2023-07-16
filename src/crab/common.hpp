// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <boost/optional/optional_io.hpp>
#include <functional>
#include <optional>
#include <vector>

#include "string_constraints.hpp"
#include "asm_syntax.hpp"

constexpr int NUM_REGISTERS = 11;

constexpr int STACK_BEGIN = 0;
constexpr int CTX_BEGIN = 0;
constexpr int PACKET_BEGIN = 0;
constexpr int SHARED_BEGIN = 0;

namespace crab {

enum class region_t {
	T_CTX,
	T_STACK,
	T_PACKET,
	T_SHARED
};

class ptr_no_off_t {
    region_t m_r;

  public:
    ptr_no_off_t() = default;
    ptr_no_off_t(const ptr_no_off_t &) = default;
    ptr_no_off_t(ptr_no_off_t &&) = default;
    ptr_no_off_t &operator=(const ptr_no_off_t &) = default;
    ptr_no_off_t &operator=(ptr_no_off_t &&) = default;
    ptr_no_off_t(region_t _r) : m_r(_r) {}

    [[nodiscard]] region_t get_region() const { return m_r; }
    void set_region(region_t);
    void write(std::ostream&) const;
    friend std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p);
    bool operator==(const ptr_no_off_t&) const;
    bool operator!=(const ptr_no_off_t&) const;
};

class ptr_with_off_t {
    region_t m_r;
    interval_t m_offset;
    interval_t m_region_size = interval_t::top();

  public:
    ptr_with_off_t() = default;
    ptr_with_off_t(const ptr_with_off_t &) = default;
    ptr_with_off_t(ptr_with_off_t &&) = default;
    ptr_with_off_t &operator=(const ptr_with_off_t &) = default;
    ptr_with_off_t &operator=(ptr_with_off_t &&) = default;
    ptr_with_off_t(region_t _r, interval_t _off, interval_t _region_sz)
        : m_r(_r), m_offset(_off), m_region_size(_region_sz) {}
    ptr_with_off_t(region_t _r, interval_t _off) : m_r(_r), m_offset(_off) {}
    ptr_with_off_t operator|(const ptr_with_off_t&) const;
    interval_t get_region_size() const;
    void set_region_size(interval_t);
    [[nodiscard]] interval_t get_offset() const { return m_offset; }
    void set_offset(interval_t);
    [[nodiscard]] region_t get_region() const { return m_r; }
    void set_region(region_t);
    void write(std::ostream&) const;
    friend std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p);
    bool operator==(const ptr_with_off_t&) const;
    bool operator!=(const ptr_with_off_t&) const;
};

class mapfd_t {
    interval_t m_mapfd;
    EbpfMapValueType m_value_type;

  public:
    mapfd_t(const mapfd_t&) = default;
    mapfd_t(mapfd_t&&) = default;
    mapfd_t &operator=(const mapfd_t&) = default;
    mapfd_t &operator=(mapfd_t&&) = default;
    mapfd_t operator|(const mapfd_t&) const;
    mapfd_t(interval_t mapfd, EbpfMapValueType val_type)
        : m_mapfd(mapfd), m_value_type(val_type) {}
    friend std::ostream& operator<<(std::ostream&, const mapfd_t&);
    bool operator==(const mapfd_t&) const;
    bool operator!=(const mapfd_t&) const;
    void write(std::ostream&) const;

    bool has_type_map_programs() const;
    [[nodiscard]] EbpfMapValueType get_value_type() const { return m_value_type; }
    [[nodiscard]] interval_t get_mapfd() const { return m_mapfd; }
};

using ptr_t = std::variant<ptr_no_off_t, ptr_with_off_t>;
using register_t = uint8_t;
using location_t = boost::optional<std::pair<label_t, uint32_t>>;

class reg_with_loc_t {
    register_t m_reg;
    location_t m_loc;

  public:
    reg_with_loc_t(register_t _r, location_t _loc) : m_reg(_r), m_loc(_loc) {}
    bool operator==(const reg_with_loc_t& other) const;
    std::size_t hash() const;
    friend std::ostream& operator<<(std::ostream& o, const reg_with_loc_t& reg);
    void write(std::ostream& ) const;
};

using ptr_or_mapfd_t = std::variant<ptr_with_off_t, ptr_no_off_t, mapfd_t>;

inline bool is_mapfd_type(const std::optional<ptr_or_mapfd_t>& ptr_or_mapfd) {
    return (ptr_or_mapfd && std::holds_alternative<mapfd_t>(*ptr_or_mapfd));
}

inline bool same_region(const ptr_or_mapfd_t& ptr1, const ptr_or_mapfd_t& ptr2) {
    if (std::holds_alternative<ptr_no_off_t>(ptr1) && std::holds_alternative<ptr_no_off_t>(ptr2))
        return true;
    return (std::holds_alternative<ptr_with_off_t>(ptr1)
            && std::holds_alternative<ptr_with_off_t>(ptr2)
            && std::get<ptr_with_off_t>(ptr1).get_region()
                == std::get<ptr_with_off_t>(ptr2).get_region());
}

inline bool is_stack_ptr(const std::optional<ptr_or_mapfd_t>& ptr) {
    return (ptr && std::holds_alternative<ptr_with_off_t>(*ptr)
            && std::get<ptr_with_off_t>(*ptr).get_region() == region_t::T_STACK);
}

inline bool is_ctx_ptr(const std::optional<ptr_or_mapfd_t>& ptr) {
    return (ptr && std::holds_alternative<ptr_with_off_t>(*ptr)
            && std::get<ptr_with_off_t>(*ptr).get_region() == region_t::T_CTX);
}

inline bool is_packet_ptr(const std::optional<ptr_or_mapfd_t>& ptr) {
    return (ptr && std::holds_alternative<ptr_no_off_t>(*ptr));
}

inline bool is_shared_ptr(const std::optional<ptr_or_mapfd_t>& ptr) {
    return (ptr && std::holds_alternative<ptr_with_off_t>(*ptr)
            && std::get<ptr_with_off_t>(*ptr).get_region() == region_t::T_SHARED);
}

inline std::ostream& operator<<(std::ostream& o, const region_t& t) {
    o << static_cast<std::underlying_type<region_t>::type>(t);
    return o;
}


} // namespace crab


namespace std {
    template <>
    struct hash<crab::reg_with_loc_t> {
        size_t operator()(const crab::reg_with_loc_t& reg) const { return reg.hash(); }
    };

    template <>
    struct equal_to<crab::ptr_t> {
        constexpr bool operator()(const crab::ptr_t& lhs, const crab::ptr_t& rhs) const {
            if (lhs.index() != rhs.index()) return false;
            return std::visit( overloaded
               {
                   []( const crab::ptr_with_off_t& x, const crab::ptr_with_off_t& y ){ return x == y;},
                   []( const crab::ptr_no_off_t& x, const crab::ptr_no_off_t& y ){ return x == y;},
                   []( auto& , auto& ) { return true;}
                }, lhs, rhs
            );
        }
    };

    template <>
    struct equal_to<crab::ptr_or_mapfd_t> {
        constexpr bool operator()(const crab::ptr_or_mapfd_t& lhs, const crab::ptr_or_mapfd_t& rhs) const {
            if (lhs.index() != rhs.index()) return false;
            return std::visit( overloaded
               {
                   []( const crab::ptr_with_off_t& x, const crab::ptr_with_off_t& y ){ return x == y;},
                   []( const crab::ptr_no_off_t& x, const crab::ptr_no_off_t& y ){ return x == y;},
                   []( const crab::mapfd_t& x, const crab::mapfd_t& y ){ return x == y;},
                   []( auto& , auto& ) { return true;}
                }, lhs, rhs
            );
        }
    };

    //crab::ptr_t get_ptr(const crab::ptr_or_mapfd_t& t);
}

