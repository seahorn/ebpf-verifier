// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

using crab::___print___;
using crab::ptr_t;
using crab::ptr_with_off_t;
using crab::ptr_no_off_t;
using crab::ctx_t;
using crab::types_t;
using crab::reg_with_loc_t;

void update(std::shared_ptr<types_t> m, const reg_with_loc_t& key, const ptr_t& value) {
    auto it = m->insert(std::make_pair(key, value));
    if (not it.second) it.first->second = value;
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

type_domain_t type_domain_t::setup_entry(std::shared_ptr<ctx_t> _ctx, std::shared_ptr<types_t> _types) {

    type_domain_t inv(label_t::entry);

    inv.types = _types;
    inv.ctx = _ctx;

    inv.live_vars[R1_ARG] = reg_with_loc_t(R1_ARG, label_t::entry, -1);
    inv.live_vars[R10_STACK_POINTER] = reg_with_loc_t(R10_STACK_POINTER, label_t::entry, -1);

    return inv;
}

void type_domain_t::operator()(const Bin& bin) {

    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        switch (bin.op)
        {
            case Bin::Op::MOV: {

                auto reg_to_look = live_vars[src.v];    // need checks that array actually contains an element, not default value
                auto it = types->find(reg_to_look);
                if (it == types->end()) {
                    CRAB_ERROR("type error: assigning an unknown pointer or a number - R", src.v);
                }

                auto reg = reg_with_loc_t(bin.dst.v, label, -1);
                update(types, reg, it->second);
                live_vars[bin.dst.v] = reg;
            }

            default:
                break;
        }
    }
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg) {

    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto reg_to_look = live_vars[basereg.v];
    auto it = types->find(reg_to_look);
    if (it == types->end()) {
        CRAB_ERROR("type_error: loading from an unknown pointer, or from number - R", basereg.v);
    }

    ptr_t type_basereg = it->second;

    if (std::holds_alternative<ptr_no_off_t>(type_basereg)) {
        CRAB_ERROR("type_error: loading from either packet or shared region not allowed - R", basereg.v);
    }

    ptr_with_off_t type_with_off = std::get<ptr_with_off_t>(type_basereg);
    uint64_t load_at = offset+type_with_off.offset;

    switch (type_with_off.r) {
        case crab::region::T_STACK: {

            auto it = stack.find(load_at);

            if (it == stack.end()) {
                CRAB_ERROR("type_error: no field at loaded offset ", load_at, " in stack");
            }
            ptr_t type_loaded = it->second;

            if (std::holds_alternative<ptr_with_off_t>(type_loaded)) {
                ptr_with_off_t type_loaded_with_off = std::get<ptr_with_off_t>(type_loaded);
                auto reg = reg_with_loc_t(target_reg.v, label, -1);
                update(types, reg, type_loaded_with_off);
                live_vars[target_reg.v] = reg;
            }
            else {
                ptr_no_off_t type_loaded_no_off = std::get<ptr_no_off_t>(type_loaded);
                auto reg = reg_with_loc_t(target_reg.v, label, -1);
                update(types, reg, type_loaded_no_off);
                live_vars[target_reg.v] = reg;
            }

            break;
        }
        case crab::region::T_CTX: {

            auto ptrs = ctx->packet_ptrs;
            auto it = ptrs.find(load_at);

            if (it == ptrs.end()) {
                CRAB_ERROR("type_error: no field at loaded offset ", load_at, " in context");
            }
            ptr_no_off_t type_loaded = it->second;

            auto reg = reg_with_loc_t(target_reg.v, label, -1);
            update(types, reg, type_loaded);
            live_vars[target_reg.v] = reg;
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

    auto reg_to_look = live_vars[basereg.v];
    auto it = types->find(reg_to_look);
    if (it == types->end()) {
        CRAB_ERROR("type_error: storing at an unknown pointer, or from number - R", (int)basereg.v);
    }

    ptr_t type_basereg = it->second;

    reg_to_look = live_vars[target_reg.v];
    auto it2 = types->find(reg_to_look);
    if (it2 == types->end()) {
        CRAB_ERROR("type_error: storing either a number or an unknown pointer - R", (int)target_reg.v);
    }

    ptr_t type_stored = it2->second;

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

    uint64_t store_at = offset+type_basereg_with_off.offset;

    auto it3 = stack.find(store_at);
    if (it3 == stack.end()) {
        stack.insert(std::make_pair(store_at, type_stored));
    }
    else {
        auto type_in_stack = it3->second;
        if (type_stored.index() != type_in_stack.index()) {
            CRAB_ERROR("type_error: type being stored at offset ", store_at, " is not the same as stored already in stack");
        }
        if (std::holds_alternative<ptr_with_off_t>(type_stored)) {
            if (std::get<ptr_with_off_t>(type_stored) != std::get<ptr_with_off_t>(type_in_stack)) {
                CRAB_ERROR("type_error: type being stored at offset ", store_at, " is not the same as stored already in stack");
            }
        }
        else {
            if (std::get<ptr_no_off_t>(type_stored) != std::get<ptr_no_off_t>(type_in_stack)) {
                CRAB_ERROR("type_error: type being stored at offset ", store_at, " is not the same as stored already in stack");
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
        CRAB_ERROR("Either loading to a number (not allowed) or storing a number (not allowed yet) - ", std::get<Imm>(b.value).v);
    }
}
