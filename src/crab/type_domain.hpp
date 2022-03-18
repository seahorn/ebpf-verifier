// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include "crab/cfg.hpp"

namespace crab {

enum class region {
	T_CTX,
	T_STACK,
	T_PACKET,
	T_SHARED
};

std::string get_region(const region& r) {
    switch (r) {
        case region::T_CTX:
            return "ctx";
        case region::T_STACK:
            return "stack";
        case region::T_PACKET:
            return "packet";
        case region::T_SHARED:
            return "shared";
        default:
            return "undefined";
    }
}

std::ostream& operator<<(std::ostream& o, const region& t) {
    o << static_cast<std::underlying_type<region>::type>(t);
    return o;
}

struct ptr_no_off_t {
    region r;

    ptr_no_off_t(region _r) : r(_r) {}
    ptr_no_off_t(const ptr_no_off_t& p) : r(p.r) {}

    friend bool operator==(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
        return (p1.r == p2.r);
    }

    friend bool operator!=(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
        return !(p2 == p1);
    }

    friend std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p) {
        return o << "{" << get_region(p.r) << "}";
    }
};

struct ptr_with_off_t {
    region r;
    int offset;

    ptr_with_off_t(region _r, int _off) : r(_r), offset(_off) {}
    ptr_with_off_t(const ptr_with_off_t& p) : r(p.r), offset(p.offset) {}

    friend bool operator==(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
        return (p1.r == p2.r);
    }

    friend bool operator!=(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
        return !(p1 == p2);
    }

    friend std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p) {
        return o << "{" << get_region(p.r) << ", " << p.offset << "}";
    }
};

using ptr_t = std::variant<ptr_no_off_t, ptr_with_off_t>;


struct reg_with_loc_t {
    int r;
    std::pair<label_t, uint32_t> loc;

    reg_with_loc_t() : r(-1), loc(std::make_pair(label_t::entry, 0)) {}
    reg_with_loc_t(int _r, const label_t& l, uint32_t loc_instr) : r(_r), loc(std::make_pair(l, loc_instr)) {}

    bool operator==(const reg_with_loc_t& other) const {
        return (r != -1 && r == other.r);
    }
};
}

// adapted from top answer in
// https://stackoverflow.com/questions/17016175/c-unordered-map-using-a-custom-class-type-as-the-key
// works for now but needs to be checked again
template <>
struct std::hash<crab::reg_with_loc_t>
{
    std::size_t operator()(const crab::reg_with_loc_t& reg) const
    {
        using std::size_t;
        using std::hash;
        using std::string;

        // Compute individual hash values for first,
        // second and third and combine them using XOR
        // and bit shifting:

        return ((hash<int>()(reg.r)
               ^ (hash<int>()(reg.loc.first.from) << 1)) >> 1)
               ^ (hash<int>()(reg.loc.second) << 1);
    }
};

namespace crab {


using offset_to_ptr_no_off_t = std::unordered_map<uint64_t, ptr_no_off_t>;
using offset_to_ptr_t = std::unordered_map<uint64_t, ptr_t>;

struct ctx_t {
  private:
    offset_to_ptr_no_off_t packet_ptrs;

  public:
    ctx_t(const ebpf_context_descriptor_t* desc)
    {
        packet_ptrs.insert(std::make_pair(desc->data, crab::ptr_no_off_t(crab::region::T_PACKET)));
        packet_ptrs.insert(std::make_pair(desc->end, crab::ptr_no_off_t(crab::region::T_PACKET)));
    }

    std::optional<ptr_no_off_t> find(int key) const {
        auto it = packet_ptrs.find(key);
        if (it == packet_ptrs.end()) return {};
        return it->second;
    }
};

struct stack_t {
  private:
    offset_to_ptr_t ptrs;
    bool _is_bottom;

  public:
    explicit stack_t(bool is_bottom = false) : _is_bottom(is_bottom) {}

    stack_t operator|(const stack_t& other) const {
        stack_t st{};
        for (auto& e : ptrs) {
            auto it = other.ptrs.find(e.first);
            if (it == other.ptrs.end() || it->second == e.second) {
                st.ptrs.insert(e);
            }
        }

        for (auto& e : other.ptrs) {
            auto it = ptrs.find(e.first);
            if (it == ptrs.end()) {
                st.ptrs.insert(e);
            }
        }
        return st;
    }

    void set_to_bottom() {
        this->~stack_t();
        new (this) stack_t(true);
    }

    void set_to_top() {
        this->~stack_t();
        new (this) stack_t(false);
    }

    static stack_t bottom() { return stack_t(true); }

    static stack_t top() { return stack_t(false); }

    bool is_bottom() const { return _is_bottom; }

    bool is_top() const {
        if (_is_bottom)
            return false;
        return ptrs.empty();
    }

    offset_to_ptr_t get_ptrs() const { return ptrs; }

    void insert(int key, ptr_t value) { ptrs.insert(std::make_pair(key, value)); }

    std::optional<ptr_t> find(int key) {
        auto it = ptrs.find(key);
        if (it == ptrs.end()) return {};
        return it->second;
    }

    friend std::ostream& operator<<(std::ostream& o, const stack_t& st) {
        o << "Stack: {";
        for (auto s : st.get_ptrs()) {
            o << s.first << ": ";
            if (std::holds_alternative<ptr_with_off_t>(s.second)) {
                auto t = std::get<ptr_with_off_t>(s.second);
                o << t << ", ";
            }
            else {
                auto t = std::get<ptr_no_off_t>(s.second);
                o << t << ", ";
            }
        }
        return o << "}";
    }
};

using all_types_t = std::unordered_map<reg_with_loc_t, ptr_t>;
using reg_live_vars_t = std::array<reg_with_loc_t, 11>;

struct types_t {
  private:
    reg_live_vars_t vars;
    std::shared_ptr<all_types_t> all_types;
    bool _is_bottom = false;

  public:
    types_t(bool is_bottom = false) : _is_bottom(is_bottom) {}
    explicit types_t(reg_live_vars_t _vars, std::shared_ptr<all_types_t> _all_types, bool is_bottom = false)
        : vars(_vars), all_types(_all_types), _is_bottom(is_bottom) {}

    types_t operator|(const types_t& other) const {
        reg_live_vars_t _vars;
        for (int i = 0; i < vars.size(); i++) {
            auto it1 = all_types->find(vars[i]);
            auto it2 = other.all_types->find(other.vars[i]);
            if (it1 != all_types->end() && it2 != other.all_types->end()) {
                if (it1->second == it2->second) {
                    _vars[i] = vars[i];
                }
            }
        }

        types_t v(_vars, all_types, false);
        return v;
    }

    void set_to_bottom() {
        this->~types_t();
        new (this) types_t(true);
    }

    bool is_bottom() const { return _is_bottom; }

    void insert(uint32_t reg, const reg_with_loc_t& reg_with_loc, const ptr_t& type) {
        auto it = all_types->insert(std::make_pair(reg_with_loc, type));
        if (not it.second) it.first->second = type;
        vars[reg] = reg_with_loc;
    }

    std::optional<ptr_t> find(const reg_with_loc_t& reg) const {
        auto it = all_types->find(reg);
        if (it == all_types->end()) return {};
        return it->second;
    }

    std::optional<ptr_t> find(uint32_t key) const {
        auto reg = vars[key];
        return find(reg);
    }

    reg_live_vars_t get_vars() const { return vars; }

    friend std::ostream& operator<<(std::ostream& o, const types_t& typ) {
        for (const auto& v : typ.get_vars()) {
            auto it = typ.find(v);
            if (it) {
                o << "\ttype of r" << v.r << ": ";
                if (std::holds_alternative<ptr_with_off_t>(it.value())) {
                    auto t = std::get<ptr_with_off_t>(it.value());
                    o << t << "\n";
                }
                else {
                    auto t = std::get<ptr_no_off_t>(it.value());
                    o << t << "\n";
                }
            }
        }
        return o;
    }
};

}

class type_domain_t final {
  private:
    crab::stack_t stack;
    crab::types_t types;
    std::shared_ptr<crab::ctx_t> ctx;
    label_t label;
    uint32_t m_curr_pos = 0;

  public:

  type_domain_t() : label(label_t::entry) {}
  type_domain_t(const crab::types_t& _types, const crab::stack_t& _st, const label_t& _l, std::shared_ptr<crab::ctx_t> _ctx)
            : stack(_st), types(_types), ctx(_ctx), label(_l) {}
  // eBPF initialization: R1 points to ctx, R10 to stack, etc.
  static type_domain_t setup_entry(std::shared_ptr<crab::ctx_t>, std::shared_ptr<crab::all_types_t>);
  // bottom/top
  static type_domain_t bottom();
  void set_to_top();
  void set_to_bottom();
  bool is_bottom() const;
  bool is_top() const;
  // inclusion
  bool operator<=(const type_domain_t& other) const;
  // join
  void operator|=(type_domain_t& other) const;
  void operator|=(const type_domain_t& other) const;
  friend std::ostream& operator<<(std::ostream&, const type_domain_t&);
  type_domain_t operator|(type_domain_t& other) const;
  type_domain_t operator|(const type_domain_t& other) const&;
  // meet
  type_domain_t operator&(const type_domain_t& other) const;
  // widening
  type_domain_t widen(const type_domain_t& other) const;
  // narrowing
  type_domain_t narrow(const type_domain_t& other) const;

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
  void operator()(const basic_block_t& bb) {
      m_curr_pos = 0;
      label = bb.label();
      std::cout << label << ": \n";
      for (const Instruction& statement : bb) {
        m_curr_pos++;
        std::visit(*this, statement);
        std::cout << *this << "\n";
    }
  }

  private:

  void do_load(const Mem&, const Reg&);
  void do_mem_store(const Mem&, const Reg&);

}; // end type_domain_t
