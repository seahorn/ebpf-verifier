// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

static std::string size(int w) { return std::string("u") + std::to_string(w * 8); }


bool type_domain_t::is_bottom() const {
    return false;
}

bool type_domain_t::is_top() const {
    return false;
}

type_domain_t type_domain_t::bottom() {
    type_domain_t typ;
    typ.set_to_bottom();
    return typ;
}

void type_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

void type_domain_t::set_to_top() {
}

bool type_domain_t::operator<=(const type_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return true;
}

void type_domain_t::operator|=(const type_domain_t& abs) {
}

void type_domain_t::operator|=(type_domain_t&& abs) {
}

type_domain_t type_domain_t::operator|(const type_domain_t& other) const {
    return other;
}

type_domain_t type_domain_t::operator|(type_domain_t&& other) const {
    return other;
}

type_domain_t type_domain_t::operator&(const type_domain_t& abs) const {
    return abs;
}

type_domain_t type_domain_t::widen(const type_domain_t& abs) const {
    return abs;
}

type_domain_t type_domain_t::narrow(const type_domain_t& other) const {
    return other;
}

void type_domain_t::write(std::ostream& os) const { 
}

std::string type_domain_t::domain_name() const {
    return "type_domain";
}

crab::bound_t type_domain_t::get_instruction_count_upper_bound() {
    return crab::bound_t(crab::number_t(0));
}

string_invariant type_domain_t::to_set() {
    return string_invariant{};
}

void type_domain_t::operator()(const Undefined & u, location_t loc, int print) {
}
void type_domain_t::operator()(const Un &u, location_t loc, int print) {
}
void type_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Call &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Exit &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Jmp &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Packet & u, location_t loc, int print) {
}
void type_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Assume &u, location_t loc, int print) {
}
void type_domain_t::operator()(const Assert &u, location_t loc, int print) {
}

type_domain_t type_domain_t::setup_entry() {
    type_domain_t inv;
    return inv;
}

void type_domain_t::report_type_error(std::string s, location_t loc) {
}

void type_domain_t::operator()(const Bin& bin, location_t loc, int print) {
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {
}

void type_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc, int print) {
}

void type_domain_t::operator()(const Mem& b, location_t loc, int print) {
}

void type_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
}

void type_domain_t::set_require_check(check_require_func_t f) {}
