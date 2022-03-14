// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

using crab::___print___;

using crab::ptr_t;
using crab::ptr_with_off_t;
using crab::ptr_no_off_t;
using crab::ctx_t;

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

type_domain_t type_domain_t::setup_entry(const crab::offset_to_ptr_t& _ctx) {

    type_domain_t inv;

    inv.types.insert(std::make_pair(R1_ARG, ptr_with_off_t(crab::region::T_CTX, 0)));
    inv.types.insert(std::make_pair(R10_STACK_POINTER, ptr_with_off_t(crab::region::T_STACK, 512)));

    for (auto& p : _ctx) {
        inv.ctx.insert(p);
    }

    return inv;
}

void type_domain_t::operator()(const Bin& bin) {

    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        switch (bin.op)
        {
            case Bin::Op::MOV: {

                auto it = types.find(src.v);
                if (it == types.end()) {
                    CRAB_ERROR("type error: assigning an unknown pointer or a number");
                }

                types.insert(std::make_pair(bin.dst.v, it->second));
            }

            default:
                break;
        }
    }
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg) {

    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto it = types.find(basereg.v);
    if (it == types.end()) {
        CRAB_ERROR("type_error: loading from an unknown pointer, or from number");
    }

    ptr_t type_basereg = it->second;

    if (std::holds_alternative<ptr_no_off_t>(type_basereg)) {
        CRAB_ERROR("type_error: loading from either packet or shared region not allowed");
    }

    ptr_with_off_t type_with_off = std::get<ptr_with_off_t>(type_basereg);
    uint64_t load_at = offset+type_with_off.offset;

    switch (type_with_off.r) {
        case crab::region::T_STACK: {

            auto it = stack.find(load_at);

            if (it == stack.end()) {
                CRAB_ERROR("type_error: no field at loaded offset in stack");
            }
            ptr_t type_loaded = it->second;

            if (std::holds_alternative<ptr_with_off_t>(type_loaded)) {
                ptr_with_off_t type_loaded_with_off = std::get<ptr_with_off_t>(type_loaded);
                types.insert(std::make_pair(target_reg.v, type_loaded_with_off));
            }
            else {
                ptr_no_off_t type_loaded_no_off = std::get<ptr_no_off_t>(type_loaded);
                types.insert(std::make_pair(target_reg.v, type_loaded_no_off));
            }

            break;
        }
        case crab::region::T_CTX: {

            auto it = ctx.find(load_at);

            if (it == ctx.end()) {
                CRAB_ERROR("type_error: no field at loaded offset in context");
            }
            ptr_no_off_t type_loaded = it->second;

            types.insert(std::make_pair(target_reg.v, type_loaded));
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

    auto it = types.find(basereg.v);
    if (it == types.end()) {
        CRAB_ERROR("type_error: storing at an unknown pointer, or from number");
    }

    ptr_t type_basereg = it->second;

    auto it2 = types.find(target_reg.v);
    if (it2 == types.end()) {
        CRAB_ERROR("type_error: storing either a number or an unknown pointer");
    }

    ptr_t type_stored = it2->second;

    if (std::holds_alternative<ptr_with_off_t>(type_stored)) {
        ptr_with_off_t type_stored_with_off = std::get<ptr_with_off_t>(type_stored);
        if (type_stored_with_off.r == crab::region::T_STACK) {
            CRAB_ERROR("type_error: we do not store stack pointers into stack");
        }
    }

    if (std::holds_alternative<ptr_no_off_t>(type_basereg)) {
        CRAB_ERROR("type_error: we cannot store pointers into packet or shared");
    }

    ptr_with_off_t type_basereg_with_off = std::get<ptr_with_off_t>(type_basereg);
    if (type_basereg_with_off.r == crab::region::T_CTX) {
        CRAB_ERROR("type_error: we cannot store pointers into ctx");
    }

    uint64_t store_at = offset+type_basereg_with_off.offset;

    auto it3 = stack.find(store_at);
    if (it3 == stack.end()) {
        stack.insert(std::make_pair(store_at, type_stored));
    }
    else {
        auto type_in_stack = it3->second;
        if (type_stored.index() != type_in_stack.index()) {
            CRAB_ERROR("type_error: type being stored is not the same as stored already in stack");
        }
        if (std::holds_alternative<ptr_with_off_t>(type_stored)) {
            if (std::get<ptr_with_off_t>(type_stored) != std::get<ptr_with_off_t>(type_in_stack)) {
                CRAB_ERROR("type_error: type being stored is not the same as stored already in stack");
            }
        }
        else {
            if (std::get<ptr_no_off_t>(type_stored) != std::get<ptr_no_off_t>(type_in_stack)) {
                CRAB_ERROR("type_error: type being stored is not the same as stored already in stack");
            }
        }
    }
}

void type_domain_t::operator()(const Mem& b) {

    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value));
        } else {
            do_mem_store(b, std::get<Reg>(b.value));
        }
    } else {
        CRAB_ERROR("Either loading to a number (not allowed) or storing a number (not allowed yet)");
    }
}
