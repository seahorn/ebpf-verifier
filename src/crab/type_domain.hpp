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


struct ptr_with_off_t;

struct ptr_no_off_t {
    region r;

    ptr_no_off_t(region _r) : r(_r) {}
    ptr_no_off_t(const ptr_no_off_t& p) : r(p.r) {}
    bool operator!=(const ptr_with_off_t& p) {
        return false;
    }
    bool operator!=(const ptr_no_off_t& p) {
        return r != p.r;
    }
};

struct ptr_with_off_t {
    region r;
    int offset;

    ptr_with_off_t(region _r, int _off) : r(_r), offset(_off) {}
    ptr_with_off_t(const ptr_with_off_t& p) : r(p.r), offset(p.offset) {}
    bool operator!=(const ptr_no_off_t& p) {
        return false;
    }
    bool operator!=(const ptr_with_off_t& p) {
        return r != p.r;
    }
};

struct reg_with_loc_t {
    uint8_t r;
    int loc;
};

using ptr_t = std::variant<ptr_no_off_t, ptr_with_off_t>;

using stack_t = std::unordered_map<int, ptr_t>;
using types_t = std::unordered_map<uint8_t, ptr_t>;
using ctx_t = std::unordered_map<int, ptr_no_off_t>;
}

class type_domain_t final {

    crab::stack_t stack;
    crab::types_t types;
    crab::ctx_t ctx;

  public:

  type_domain_t() {}
  // eBPF initialization: R1 points to ctx, R10 to stack, etc.
  static type_domain_t setup_entry(const crab::ctx_t&);
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
  type_domain_t operator|(const type_domain_t& other) const;
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
      for (const Instruction& statement : bb) {
        std::visit(*this, statement);
    }
  }

  private:

  void do_load(const Mem&, const Reg&);
  void do_mem_store(const Mem&, const Reg&);

}; // end type_domain_t
