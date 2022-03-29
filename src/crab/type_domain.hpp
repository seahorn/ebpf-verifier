// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include "crab/abstract_domain.hpp"
#include "crab/cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"

namespace crab {

enum class region {
	T_CTX,
	T_STACK,
	T_PACKET,
	T_SHARED
};

inline std::string get_region(const region& r) {
    switch (r) {
        case region::T_CTX:
            return "ctx";
        case region::T_STACK:
            return "stack";
        case region::T_PACKET:
            return "packet";
        default:
            return "shared";
    }
}

inline std::ostream& operator<<(std::ostream& o, const region& t) {
    o << static_cast<std::underlying_type<region>::type>(t);
    return o;
}

struct ptr_no_off_t {
    region r;

    ptr_no_off_t() = default;
    ptr_no_off_t(const ptr_no_off_t &) = default;
    ptr_no_off_t(ptr_no_off_t &&) = default;
    ptr_no_off_t &operator=(const ptr_no_off_t &) = default;
    ptr_no_off_t &operator=(ptr_no_off_t &&) = default;

    ptr_no_off_t(region _r) : r(_r) {}

    friend std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p) {
        return o << "{" << get_region(p.r) << "}";
    }
  
    // temporarily make operators friend functions in order to avoid duplicate symbol errors
    friend bool operator==(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
        return (p1.r == p2.r);
    }

    friend bool operator!=(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
        return !(p1 == p2);
    }
};

struct ptr_with_off_t {
    region r;
    int offset;

    ptr_with_off_t() = default;
    ptr_with_off_t(const ptr_with_off_t &) = default;
    ptr_with_off_t(ptr_with_off_t &&) = default;
    ptr_with_off_t &operator=(const ptr_with_off_t &) = default;
    ptr_with_off_t &operator=(ptr_with_off_t &&) = default;

    ptr_with_off_t(region _r, int _off) : r(_r), offset(_off) {}

    friend std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p) {
        o << "{" << get_region(p.r) << ", " << p.offset << "}";
        return o;
    }

    // temporarily make operators friend functions in order to avoid duplicate symbol errors
    friend bool operator==(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
        return (p1.r == p2.r && p1.offset == p2.offset);
    }

    friend bool operator!=(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
        return !(p1 == p2);
    }
};

using ptr_t = std::variant<ptr_no_off_t, ptr_with_off_t>;
using register_t = uint8_t;

struct reg_with_loc_t {
    register_t r;
    std::pair<label_t, uint32_t> loc;

    reg_with_loc_t() : r(11), loc(std::make_pair(label_t::entry, 0)) {}
    reg_with_loc_t(register_t _r, const label_t& l, uint32_t loc_instr) : r(_r), loc(std::make_pair(l, loc_instr)) {}

    bool operator==(const reg_with_loc_t& other) const {
        return (r < 11 && r == other.r);
    }

    std::size_t hash() const {
        // Similar to boost::hash_combine
        using std::hash;

        std::size_t seed = hash<register_t>()(r);
        seed ^= hash<int>()(loc.first.from) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= hash<int>()(loc.second) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

        return seed;
    }
};
}


namespace std {
    template <>
    struct std::hash<crab::reg_with_loc_t> {
        std::size_t operator()(const crab::reg_with_loc_t& reg) const { return reg.hash(); }
    };

    // does not seem to work for me
    template <>
    struct std::equal_to<crab::ptr_t> {
        constexpr bool operator()(const crab::ptr_t& p1, const crab::ptr_t& p2) const {
            if (p1.index() != p2.index()) return false;
            if (std::holds_alternative<crab::ptr_no_off_t>(p1)) {
                auto ptr_no_off1 = std::get<crab::ptr_no_off_t>(p1);
                auto ptr_no_off2 = std::get<crab::ptr_no_off_t>(p2);
                return (ptr_no_off1.r == ptr_no_off2.r);
            }
            else {
                auto ptr_with_off1 = std::get<crab::ptr_with_off_t>(p1);
                auto ptr_with_off2 = std::get<crab::ptr_with_off_t>(p2);
                return (ptr_with_off1.r == ptr_with_off2.r && ptr_with_off1.offset == ptr_with_off2.offset);
            }
        }
    };
}


namespace crab {

class ctx_t {
    using offset_to_ptr_no_off_t = std::unordered_map<int, ptr_no_off_t>;

    offset_to_ptr_no_off_t m_packet_ptrs;

  public:
    ctx_t(const ebpf_context_descriptor_t* desc)
    {
        if (desc->data != -1)
            m_packet_ptrs[desc->data] = crab::ptr_no_off_t(crab::region::T_PACKET);
        if (desc->end != -1)
            m_packet_ptrs[desc->end] = crab::ptr_no_off_t(crab::region::T_PACKET);
    }

    std::optional<ptr_no_off_t> find(int key) const {
        auto it = m_packet_ptrs.find(key);
        if (it == m_packet_ptrs.end()) return {};
        return it->second;
    }

    friend std::ostream& operator<<(std::ostream& o, const ctx_t& _ctx) {

        o << "type of context: " << (_ctx.m_packet_ptrs.empty() ? "_|_" : "") << "\n";
        for (const auto& it : _ctx.m_packet_ptrs) {
            o << "\tstores at " << it.first << ": " << it.second << "\n";
        }
        return o;
    }
};

class stack_t {
    using offset_to_ptr_t = std::unordered_map<int, ptr_t>;

    offset_to_ptr_t m_ptrs;
    bool m_is_bottom;

  public:
    stack_t(bool is_bottom = false) : m_is_bottom(is_bottom) {}
    stack_t(offset_to_ptr_t && ptrs, bool is_bottom)
    : m_ptrs(std::move(ptrs)) , m_is_bottom(is_bottom) {}
    
    stack_t operator|(const stack_t& other) const {
        if (is_bottom() || other.is_top()) {
            return other;
        } else if (other.is_bottom() || is_top()) {
            return *this;
        }
        offset_to_ptr_t out_ptrs;
        for (auto const&kv: m_ptrs) {
            auto it = other.find(kv.first);
            if (it && kv.second == it.value())
                out_ptrs.insert(kv);
        }
        return stack_t(std::move(out_ptrs), false);
    }

    void set_to_bottom() {
        m_ptrs.clear();
        m_is_bottom = true;
    }

    void set_to_top() {
        m_ptrs.clear();
        m_is_bottom = false;
    }

    static stack_t bottom() { return stack_t(true); }

    static stack_t top() { return stack_t(false); }

    bool is_bottom() const { return m_is_bottom; }

    bool is_top() const {
        if (m_is_bottom)
            return false;
        return m_ptrs.empty();
    }

    const offset_to_ptr_t &get_ptrs() { return m_ptrs; }

    void insert(int key, ptr_t value) { m_ptrs.insert(std::make_pair(key, value)); }

    std::optional<ptr_t> find(int key) const {
        auto it = m_ptrs.find(key);
        if (it == m_ptrs.end()) return {};
        return it->second;
    }

    friend std::ostream& operator<<(std::ostream& o, const stack_t& st);
};

using live_registers_t = std::array<reg_with_loc_t, 11>;
using global_type_env_t = std::unordered_map<reg_with_loc_t, ptr_t>;

class register_types_t {
    live_registers_t m_vars;
    std::shared_ptr<global_type_env_t> m_all_types;
    bool m_is_bottom = false;

  public:
    register_types_t(bool is_bottom = false) : m_all_types(nullptr), m_is_bottom(is_bottom) {}
    explicit register_types_t(live_registers_t&& vars, std::shared_ptr<global_type_env_t> all_types, bool is_bottom = false)
        : m_vars(std::move(vars)), m_all_types(all_types), m_is_bottom(is_bottom) {}

    register_types_t operator|(const register_types_t& other) const {
        if (is_bottom() || other.is_top()) {
            return other;
        } else if (other.is_bottom() || is_top()) {
            return *this;
        }
        live_registers_t out_vars;
        for (size_t i = 0; i < m_vars.size(); i++) {
            auto it1 = find(m_vars[i]);
            auto it2 = other.find(other.m_vars[i]);
            if (it1 && it2 && it1.value() == it2.value()) {
                out_vars[i] = m_vars[i];
            }
        }

        return register_types_t(std::move(out_vars), m_all_types, false);
    }

    void set_to_bottom() {
        m_vars = live_registers_t{};
        m_is_bottom = true;
    }

    void set_to_top() {
        m_vars = live_registers_t{};
        m_is_bottom = false;
    }

    bool is_bottom() const { return m_is_bottom; }

    bool is_top() const {
        if (m_is_bottom) { return false; }
        return (m_all_types == nullptr || m_vars.empty());
    }

    void insert(register_t reg, const reg_with_loc_t& reg_with_loc, const ptr_t& type) {
        auto it = m_all_types->find(reg_with_loc);
        if (it == m_all_types->end())
            m_all_types->insert(std::make_pair(reg_with_loc, type));
        else
            it->second = type;
        //auto it = m_all_types->insert(std::make_pair(reg_with_loc, type));
        //if (not it.second) it.first->second = type;
        m_vars[reg] = reg_with_loc;
    }

    std::optional<ptr_t> find(const reg_with_loc_t& reg) const {
        auto it = m_all_types->find(reg);
        if (it == m_all_types->end()) return {};
        return it->second;
    }

    std::optional<ptr_t> find(register_t key) const {
        auto reg = m_vars[key];
        return find(reg);
    }

    const live_registers_t &get_vars() { return m_vars; }

    friend std::ostream& operator<<(std::ostream& o, const register_types_t& p);
};

}

class type_domain_t final {

    crab::stack_t m_stack;
    crab::register_types_t m_types;
    std::shared_ptr<crab::ctx_t> m_ctx;
    label_t m_label;
    uint32_t m_curr_pos = 0;

  public:

  type_domain_t() : m_label(label_t::entry) {}
  type_domain_t(type_domain_t&& o) = default;
  type_domain_t(const type_domain_t& o) = default;
  type_domain_t& operator=(type_domain_t&& o) = default;
  type_domain_t& operator=(const type_domain_t& o) = default;
  type_domain_t(crab::register_types_t&& _types, crab::stack_t&& _st, const label_t& _l, std::shared_ptr<crab::ctx_t> _ctx)
            : m_stack(std::move(_st)), m_types(std::move(_types)), m_ctx(_ctx), m_label(_l) {}
  // eBPF initialization: R1 points to ctx, R10 to stack, etc.
  static type_domain_t setup_entry();
  // bottom/top
  static type_domain_t bottom();
  void set_to_top();
  void set_to_bottom();
  bool is_bottom() const;
  bool is_top() const;
  // inclusion
  bool operator<=(const type_domain_t& other) const;
  // join
  void operator|=(const type_domain_t& abs);
  void operator|=(type_domain_t&& abs);
  type_domain_t operator|(const type_domain_t& other) const;
  type_domain_t operator|(type_domain_t&& abs) const;
  // meet
  type_domain_t operator&(const type_domain_t& other) const;
  // widening
  type_domain_t widen(const type_domain_t& other) const;
  // narrowing
  type_domain_t narrow(const type_domain_t& other) const;
  //forget
  void operator-=(variable_t var);

  //// abstract transformers
  void operator()(const Undefined &);
  void operator()(const Bin &);
  void operator()(const Un &) ;
  void operator()(const LoadMapFd &);
  void operator()(const Call &);
  void operator()(const Exit &);
  void operator()(const Jmp &);
  void operator()(const Mem &);
  void operator()(const Packet &);
  void operator()(const LockAdd &);
  void operator()(const Assume &);
  void operator()(const Assert &);
  void operator()(const basic_block_t& bb, bool check_termination) {
      m_curr_pos = 0;
      m_label = bb.label();
      std::cout << m_label << ":\n";
      for (const Instruction& statement : bb) {
        std::cout << "  " << statement << "\n";
        m_curr_pos++;
        std::visit(*this, statement);
    }
    std::cout << "\n";
  }
  void write(std::ostream& os) const;
  std::string domain_name() const;
  int get_instruction_count_upper_bound();
  string_invariant to_set();
  void set_require_check(check_require_func_t f);

  private:

  void do_load(const Mem&, const Reg&);
  void do_mem_store(const Mem&, const Reg&);

}; // end type_domain_t
