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
	T_SHARED,
};

struct ptr_no_off_t {
    region r;

    ptr_no_off_t(region _r) : r(_r) {}
    ptr_no_off_t(const ptr_no_off_t& p) : r(p.r) {}

    bool operator!=(const ptr_no_off_t& p) {
        return r != p.r;
    }

    bool operator==(const ptr_no_off_t& p) {
        return r == p.r;
    }
};

struct ptr_with_off_t {
    region r;
    int offset;

    ptr_with_off_t(region _r, int _off) : r(_r), offset(_off) {}
    ptr_with_off_t(const ptr_with_off_t& p) : r(p.r), offset(p.offset) {}

    bool operator!=(const ptr_with_off_t& p) {
        return r != p.r;
    }

    bool operator==(const ptr_with_off_t& p) {
        return r == p.r;
    }
};

struct reg_with_loc_t {
    int r;
    std::pair<label_t, int> loc;

    reg_with_loc_t() : r(-1), loc(std::make_pair(label_t::entry, -1)) {}
    reg_with_loc_t(int _r, const label_t& l, int loc_instr) : r(_r), loc(std::make_pair(l, loc_instr)) {}

    bool operator==(const reg_with_loc_t& other) const {
        return (r != -1 && r == other.r && loc.first == other.loc.first && loc.second == other.loc.second);
    }
};


using ptr_t = std::variant<ptr_no_off_t, ptr_with_off_t>;

using types_t = std::unordered_map<reg_with_loc_t, ptr_t>;

using offset_to_ptr_no_off_t = std::unordered_map<uint64_t, ptr_no_off_t>;
using offset_to_ptr_t = std::unordered_map<uint64_t, ptr_t>;

struct ctx_t {
    offset_to_ptr_no_off_t packet_ptrs;

    ctx_t(const ebpf_context_descriptor_t* desc)
    {
        packet_ptrs.insert(std::make_pair(desc->data, crab::ptr_no_off_t(crab::region::T_PACKET)));
        packet_ptrs.insert(std::make_pair(desc->end, crab::ptr_no_off_t(crab::region::T_PACKET)));
    }
};

struct stack_t {
    offset_to_ptr_t ptrs;

    stack_t operator|(const stack_t& other) const {
        stack_t st{};
        for (auto& e : ptrs) {
            auto it = other.ptrs.find(e.first);
            if (it == other.ptrs.end()) {
                st.ptrs.insert(e);
            }
            else {
                if (it->second.index() == e.second.index()) {
                    if (std::holds_alternative<ptr_no_off_t>(it->second)) {
                        ptr_no_off_t t = std::get<ptr_no_off_t>(it->second);
                        ptr_no_off_t t1 = std::get<ptr_no_off_t>(e.second);
                        if (t == t1) st.ptrs.insert(e);
                    }
                    else {
                        ptr_with_off_t t = std::get<ptr_with_off_t>(it->second);
                        ptr_with_off_t t1 = std::get<ptr_with_off_t>(e.second);
                        if (t == t1) st.ptrs.insert(e);
                    }
                }
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
};

struct live_def_t {
    std::array<reg_with_loc_t, 11> vars;

    live_def_t operator|(const live_def_t& other) const {
        live_def_t v{};
        for (int i = 0; i < vars.size(); i++) {
            if (vars[i] == other.vars[i]) {
                std::cout << "equal at: " << i << "\n";
                v.vars[i] = vars[i];
            }
        }
        return v;
    }
};

}

class type_domain_t final {

    crab::stack_t stack;
    std::shared_ptr<crab::types_t> types;
    crab::live_def_t live_def;
    std::shared_ptr<crab::ctx_t> ctx;
    label_t label;

  public:

  type_domain_t(const label_t& _l) : label(_l) {}
  type_domain_t(const crab::live_def_t& _live, const crab::stack_t& _st, const label_t& _l,
          std::shared_ptr<crab::types_t> _types, std::shared_ptr<crab::ctx_t> _ctx)
            : stack(_st), types(_types), live_def(_live), ctx(_ctx), label(_l) {}
  // eBPF initialization: R1 points to ctx, R10 to stack, etc.
  static type_domain_t setup_entry(std::shared_ptr<crab::ctx_t>, std::shared_ptr<crab::types_t>);
  // bottom/top
  void set_to_top();
  void set_to_bottom();
  bool is_bottom() const;
  bool is_top() const;
  // inclusion
  bool operator<=(const type_domain_t& other) const;
  // join
  void operator|=(type_domain_t& other) const;
  void operator|=(const type_domain_t& other) const;
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
      label = bb.label();
      for (const Instruction& statement : bb) {
        std::visit(*this, statement);
    }
  }

  private:

  void do_load(const Mem&, const Reg&);
  void do_mem_store(const Mem&, const Reg&);

}; // end type_domain_t

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
