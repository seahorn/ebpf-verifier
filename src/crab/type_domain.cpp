// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

using crab::___print___;
using crab::ptr_t;
using crab::ptr_with_off_t;
using crab::ptr_no_off_t;
using crab::ctx_t;
using crab::global_type_env_t;
using crab::reg_with_loc_t;
using crab::live_registers_t;
using crab::register_types_t;


bool type_domain_t::is_bottom() const {
    return (m_stack.is_bottom() || m_types.is_bottom());
}

bool type_domain_t::is_top() const {
    return (m_stack.is_top() || m_types.is_top());
}

type_domain_t type_domain_t::bottom() {
    type_domain_t typ;
    typ.set_to_bottom();
    return typ;
}

void type_domain_t::set_to_bottom() {
    m_stack.set_to_bottom();
    m_types.set_to_bottom();
}

type_domain_t type_domain_t::operator|(const type_domain_t& other) const& {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_types | std::move(other.m_types), m_stack | std::move(other.m_stack), m_label, other.m_ctx);
}

std::ostream& operator<<(std::ostream& o, const type_domain_t& t) {
    o << t.m_types;
    o << "\t" << t.m_stack << "\n";
    return o;
}

void type_domain_t::operator()(const Undefined & u) {}
void type_domain_t::operator()(const Un &u) {}
void type_domain_t::operator()(const LoadMapFd &u) {}
void type_domain_t::operator()(const Call &u) {}
void type_domain_t::operator()(const Exit &u) {}
void type_domain_t::operator()(const Jmp &u) {}
void type_domain_t::operator()(const Packet & u) {}
void type_domain_t::operator()(const LockAdd &u) {}
void type_domain_t::operator()(const Assume &u) {}
void type_domain_t::operator()(const Assert &u) {}

type_domain_t type_domain_t::setup_entry() {

    ebpf_context_descriptor_t context_descriptor{0, 0, 4, -1};
    std::shared_ptr<ctx_t> ctx = std::make_shared<ctx_t>(&context_descriptor);
    std::shared_ptr<global_type_env_t> all_types = std::make_shared<global_type_env_t>();

    live_registers_t vars;
    register_types_t typ(std::move(vars), all_types, true);

    auto r1 = reg_with_loc_t(R1_ARG, label_t::entry, 0);
    auto r10 = reg_with_loc_t(R10_STACK_POINTER, label_t::entry, 0);

    typ.insert(R1_ARG, r1, ptr_with_off_t(crab::region::T_CTX, 0));
    typ.insert(R10_STACK_POINTER, r10, ptr_with_off_t(crab::region::T_STACK, 512));

    type_domain_t inv(std::move(typ), crab::stack_t::bottom(), label_t::entry, ctx);

    return inv;
}

void type_domain_t::operator()(const Bin& bin) {

    std::cout << "  " << bin << "\n";
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        switch (bin.op)
        {
            case Bin::Op::MOV: {

                auto it = m_types.find(src.v);
                if (!it) {
                    CRAB_ERROR("type error: assigning an unknown pointer or a number - R", (int)src.v);
                }

                auto reg = reg_with_loc_t(bin.dst.v, m_label, m_curr_pos);
                m_types.insert(bin.dst.v, reg, it.value());
            }

            default:
                break;
        }
    }
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg) {

    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto it = m_types.find(basereg.v);
    if (!it) {
        CRAB_ERROR("type_error: loading from an unknown pointer, or from number - R", (int)basereg.v);
    }
    ptr_t type_basereg = it.value();

    if (std::holds_alternative<ptr_no_off_t>(type_basereg)) {
        CRAB_ERROR("type_error: loading from either packet or shared region not allowed - R", (int)basereg.v);
    }

    ptr_with_off_t type_with_off = std::get<ptr_with_off_t>(type_basereg);
    int load_at = offset+type_with_off.offset;

    switch (type_with_off.r) {
        case crab::region::T_STACK: {

            auto it = m_stack.find(load_at);

            if (!it) {
                CRAB_ERROR("type_error: no field at loaded offset ", load_at, " in stack");
            }
            ptr_t type_loaded = it.value();

            if (std::holds_alternative<ptr_with_off_t>(type_loaded)) {
                ptr_with_off_t type_loaded_with_off = std::get<ptr_with_off_t>(type_loaded);
                auto reg = reg_with_loc_t(target_reg.v, m_label, m_curr_pos);
                m_types.insert(target_reg.v, reg, type_loaded_with_off);
            }
            else {
                ptr_no_off_t type_loaded_no_off = std::get<ptr_no_off_t>(type_loaded);
                auto reg = reg_with_loc_t(target_reg.v, m_label, m_curr_pos);
                m_types.insert(target_reg.v, reg, type_loaded_no_off);
            }

            break;
        }
        case crab::region::T_CTX: {

            auto it = m_ctx->find(load_at);

            if (!it) {
                CRAB_ERROR("type_error: no field at loaded offset ", load_at, " in context");
            }
            ptr_no_off_t type_loaded = it.value();

            auto reg = reg_with_loc_t(target_reg.v, m_label, m_curr_pos);
            m_types.insert(target_reg.v, reg, type_loaded);
            break;
        }

        default: {
            assert(false);
        }
    }
}

void type_domain_t::do_mem_store(const Mem& b, const Reg& target_reg) {

    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto it = m_types.find(basereg.v);
    if (!it) {
        CRAB_ERROR("type_error: storing at an unknown pointer, or from number - R", (int)basereg.v);
    }
    ptr_t type_basereg = it.value();

    auto it2 = m_types.find(target_reg.v);
    if (!it2) {
        CRAB_ERROR("type_error: storing either a number or an unknown pointer - R", (int)target_reg.v);
    }
    ptr_t type_stored = it2.value();

    if (std::holds_alternative<ptr_with_off_t>(type_stored)) {
        ptr_with_off_t type_stored_with_off = std::get<ptr_with_off_t>(type_stored);
        if (type_stored_with_off.r == crab::region::T_STACK) {
            CRAB_ERROR("type_error: we cannot store stack pointer, R", (int)target_reg.v, ", into stack");
        }
    }

    if (std::holds_alternative<ptr_no_off_t>(type_basereg)) {
        CRAB_ERROR("type_error: we cannot store pointer, R", (int)target_reg.v, ", into packet or shared");
    }

    ptr_with_off_t type_basereg_with_off = std::get<ptr_with_off_t>(type_basereg);
    if (type_basereg_with_off.r == crab::region::T_CTX) {
        CRAB_ERROR("type_error: we cannot store pointer, R", (int)target_reg.v, ", into ctx");
    }

    int store_at = offset+type_basereg_with_off.offset;

    auto it3 = m_stack.find(store_at);
    if (it3) {
        auto type_in_stack = it3.value();
        if (type_stored != type_in_stack) {
            CRAB_ERROR("type_error: type being stored at offset ", store_at, " is not the same as stored already in stack");
        }
    }
    else {
        m_stack.insert(store_at, type_stored);
    }
}

void type_domain_t::operator()(const Mem& b) {

    std::cout << "  " << b << "\n";
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value));
        } else {
            do_mem_store(b, std::get<Reg>(b.value));
        }
    } else {
        CRAB_ERROR("Either loading to a number (not allowed) or storing a number (not allowed yet) - ", std::get<Imm>(b.value).v);
    }
}
