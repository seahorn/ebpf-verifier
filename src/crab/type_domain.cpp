// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "type_domain.hpp"

namespace crab {

bool type_domain_t::is_bottom() const {
    return m_is_bottom;
}

bool type_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_region.is_top());
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
    m_region.set_to_top();
}

bool type_domain_t::operator<=(const type_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return true;
}

void type_domain_t::operator|=(const type_domain_t& abs) {
    type_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void type_domain_t::operator|=(type_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

type_domain_t type_domain_t::operator|(const type_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_region | other.m_region);
}

type_domain_t type_domain_t::operator|(type_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_region | std::move(other.m_region));
}

type_domain_t type_domain_t::operator&(const type_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

type_domain_t type_domain_t::widen(const type_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

type_domain_t type_domain_t::narrow(const type_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

std::string type_domain_t::domain_name() const {
    return "type_domain";
}

crab::bound_t type_domain_t::get_instruction_count_upper_bound() {
    /* WARNING: The operation is not implemented yet.*/
    return crab::bound_t{crab::number_t{0}};
}

string_invariant type_domain_t::to_set() {
    return string_invariant{};
}

void type_domain_t::operator()(const Undefined& u, location_t loc, int print) {}

void type_domain_t::operator()(const Un& u, location_t loc, int print) {
    /* WARNING: The operation is not implemented yet.*/
}

void type_domain_t::operator()(const LoadMapFd& u, location_t loc, int print) {
    m_region(u, loc);
}

void type_domain_t::operator()(const Call& u, location_t loc, int print) {

    for (ArgPair param : u.pairs) {
        if (param.kind == ArgPair::Kind::PTR_TO_WRITABLE_MEM) {
            auto maybe_ptr_or_mapfd = m_region.find_ptr_or_mapfd_type(param.mem.v);
            if (!maybe_ptr_or_mapfd) continue;
            auto ptr_or_mapfd = maybe_ptr_or_mapfd.value();
            if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd)) {
                auto ptr_with_off = std::get<ptr_with_off_t>(ptr_or_mapfd);
                if (ptr_with_off.get_region() == region_t::T_STACK) {
                    auto offset_singleton = ptr_with_off.get_offset().to_interval().singleton();
                    if (!offset_singleton) {
                        //std::cout << "type error: storing at an unknown offset in stack\n";
                        m_errors.push_back("storing at an unknown offset in stack");
                        continue;
                    }
                    // TODO: forget the stack at [offset, offset+width]
                }
            }
        }
    }
    m_region(u, loc);
}

void type_domain_t::operator()(const Exit& u, location_t loc, int print) {}

void type_domain_t::operator()(const Jmp& u, location_t loc, int print) {}

void type_domain_t::operator()(const LockAdd& u, location_t loc, int print) {}

void type_domain_t::operator()(const Packet& u, location_t loc, int print) {
    m_region(u, loc);
}

void type_domain_t::operator()(const Assume& s, location_t loc, int print) {
    Condition cond = s.cond;
    auto right = cond.right;
    const auto& maybe_left_type = m_region.find_ptr_or_mapfd_type(cond.left.v);
    if (std::holds_alternative<Reg>(right)) {
        const auto& right_reg = std::get<Reg>(right);
        const auto& maybe_right_type = m_region.find_ptr_or_mapfd_type(right_reg.v);
        if (maybe_left_type && maybe_right_type) {
            // both pointers
        }
        else if (!maybe_left_type && !maybe_right_type) {
            // both numbers
        }
        else {
            // We should only reach here if `--assume-assert` is off
            assert(!thread_local_options.assume_assertions || is_bottom());
            // be sound in any case, it happens to flush out bugs:
            m_region.set_registers_to_top();
        }
    }
    else {}
}

void type_domain_t::operator()(const ValidDivisor& s, location_t loc, int print) {
    m_region(s, loc);
}

void type_domain_t::operator()(const ValidAccess& s, location_t loc, int print) {
    m_region(s, loc);
}

void type_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
    m_region(s, loc);
}

void type_domain_t::operator()(const Assert& u, location_t loc, int print) {
    std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, u.cst);
}

void type_domain_t::operator()(const Comparable& u, location_t loc, int print) {

    auto maybe_ptr_or_mapfd1 = m_region.find_ptr_or_mapfd_type(u.r1.v);
    auto maybe_ptr_or_mapfd2 = m_region.find_ptr_or_mapfd_type(u.r2.v);
    if (maybe_ptr_or_mapfd1 && maybe_ptr_or_mapfd2) {
        // an extra check just to make sure registers are not labelled both ptrs and numbers
        if (is_mapfd_type(maybe_ptr_or_mapfd1) && is_mapfd_type(maybe_ptr_or_mapfd2)) return;
        if (!is_shared_ptr(maybe_ptr_or_mapfd1)
                && same_region(*maybe_ptr_or_mapfd1, *maybe_ptr_or_mapfd2)) return;
    }
    else if (!maybe_ptr_or_mapfd2) {
        // two numbers can be compared
        // if r1 is a pointer, r2 must be a number
        return;
    }
    //std::cout << "type error: Non-comparable types\n";
    m_errors.push_back("Non-comparable types");
}

void type_domain_t::operator()(const Addable& u, location_t loc, int print) {
    m_region(u, loc);
}

void type_domain_t::operator()(const ValidStore& u, location_t loc, int print) {
    m_region(u, loc);
}

void type_domain_t::operator()(const ValidSize& u, location_t loc, int print) {
    /* WARNING: The operation is not implemented yet.*/
}

void type_domain_t::operator()(const ValidMapKeyValue& u, location_t loc, int print) {

    // TODO: move map-related function to common
    //auto fd_type = m_region.get_map_type(u.map_fd_reg);

    int width;
    if (u.key) {
        auto key_size = m_region.get_map_key_size(u.map_fd_reg).singleton();
        if (!key_size.has_value()) {
            m_errors.push_back("Map key size is not singleton");
            return;
        }
        width = (int)key_size.value();
    } else {
        auto value_size = m_region.get_map_value_size(u.map_fd_reg).singleton();
        if (!value_size.has_value()) {
            m_errors.push_back("Map value size is not singleton");
            return;
        }
        width = (int)value_size.value();
    }
    auto maybe_ptr_or_mapfd_basereg = m_region.find_ptr_or_mapfd_type(u.access_reg.v);
    auto maybe_mapfd = m_region.find_ptr_or_mapfd_type(u.map_fd_reg.v);
    if (maybe_ptr_or_mapfd_basereg && maybe_mapfd) {
        if (is_mapfd_type(maybe_mapfd)) {
            auto ptr_or_mapfd_basereg = maybe_ptr_or_mapfd_basereg.value();
            if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd_basereg)) {
                auto ptr_with_off = std::get<ptr_with_off_t>(ptr_or_mapfd_basereg);
                if (ptr_with_off.get_region() == region_t::T_STACK) {
                    auto offset_singleton = ptr_with_off.get_offset().to_interval().singleton();
                    if (!offset_singleton) {
                        //std::cout << "type error: reading the stack at an unknown offset\n";
                        m_errors.push_back("reading the stack at an unknown offset");
                        return;
                    }
                    auto offset_to_check = (uint64_t)offset_singleton.value();
                    auto it2 = m_region.find_in_stack(offset_to_check);
                    if (it2) {
                        //std::cout << "type error: map update with a non-numerical value\n";
                        m_errors.push_back("map update with a non-numerical value");
                    }
                    return;
                }
            }
            else if (std::holds_alternative<ptr_no_off_t>(ptr_or_mapfd_basereg)) {
                // We do not check packet ptr accesses yet
                return;
            }
            m_errors.push_back("Only stack or packet can be used as a parameter");
        }
    }
    //std::cout << "type error: valid map key value assertion failed\n";
    m_errors.push_back("valid map key value assertion failed");
}

void type_domain_t::operator()(const ZeroCtxOffset& u, location_t loc, int print) {
    m_region(u, loc);
}

type_domain_t type_domain_t::setup_entry() {
    auto&& reg = crab::region_domain_t::setup_entry();
    type_domain_t typ(std::move(reg));
    return typ;
}

void type_domain_t::operator()(const Bin& bin, location_t loc, int print) {

    auto dst_ptr_or_mapfd = m_region.find_ptr_or_mapfd_type(bin.dst.v);

    std::optional<ptr_or_mapfd_t> src_ptr_or_mapfd;
    std::optional<interval_t> src_interval;
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg r = std::get<Reg>(bin.v);
        src_ptr_or_mapfd = m_region.find_ptr_or_mapfd_type(r.v);
    }
    else {
        int64_t imm;
        if (bin.is64) {
            imm = static_cast<int64_t>(std::get<Imm>(bin.v).v);
        }
        else {
            imm = static_cast<int>(std::get<Imm>(bin.v).v);
        }
        src_interval = interval_t{crab::number_t{imm}};
    }

    using Op = Bin::Op;
    // for all operations except mov, add, sub, the src and dst should be numbers
    if ((src_ptr_or_mapfd || dst_ptr_or_mapfd)
            && (bin.op != Op::MOV && bin.op != Op::ADD && bin.op != Op::SUB)) {
        //std::cout << "type error: operation on pointers not allowed\n";
        m_errors.push_back("operation on pointers not allowed");
        m_region -= bin.dst.v;
        return;
    }

    m_region.do_bin(bin, src_interval, src_ptr_or_mapfd, dst_ptr_or_mapfd, loc);
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, bool unknown_ptr,
        location_t loc, int print) {
    m_region.do_load(b, target_reg, unknown_ptr, loc);
}

void type_domain_t::do_mem_store(const Mem& b, location_t loc, int print) {
    m_region.do_mem_store(b, loc);
}

void type_domain_t::operator()(const Mem& b, location_t loc, int print) {
    auto basereg = b.access.basereg;
    auto ptr_or_mapfd_opt = m_region.find_ptr_or_mapfd_type(basereg.v);
    bool unknown_ptr = !ptr_or_mapfd_opt.has_value();
    if (unknown_ptr) {
        std::string s = std::to_string(static_cast<unsigned int>(basereg.v));
        m_errors.push_back(
                std::string("load/store using an unknown pointer, or number - r") + s);
    }
    if (!unknown_ptr && !b.is_load) {
        do_mem_store(b, loc, print);
    }
    else if (std::holds_alternative<Reg>(b.value)) {
        auto targetreg = std::get<Reg>(b.value);
        if (b.is_load) do_load(b, targetreg, unknown_ptr, loc, print);
    }
}

// the method does not work well as it requires info about the label of basic block we are in
// this info is not available when we are only printing any state
// but it is available when we are processing a basic block for all its instructions:w
//
void type_domain_t::print_registers() const {
    std::cout << "  register types: {\n";
    for (size_t i = 0; i < NUM_REGISTERS; i++) {
        register_t reg = (register_t)i;
        auto maybe_ptr_or_mapfd_type = m_region.find_ptr_or_mapfd_type(reg);
        if (maybe_ptr_or_mapfd_type) {
            std::cout << "    ";
            print_register(std::cout, Reg{(uint8_t)reg}, maybe_ptr_or_mapfd_type);
            std::cout << "\n";
        }
    }
    std::cout << "  }\n";
}

void type_domain_t::print_ctx() const {
    std::vector<uint64_t> ctx_keys = m_region.get_ctx_keys();
    std::cout << "  ctx: {\n";
    for (auto const& k : ctx_keys) {
        auto ptr = m_region.find_in_ctx(k);
        if (ptr) {
            std::cout << "    " << k << ": ";
            print_ptr_type(std::cout, ptr_or_mapfd_t{ptr.value()});
            std::cout << ",\n";
        }
    }
    std::cout << "  }\n";
}

void type_domain_t::print_stack() const {
    std::vector<uint64_t> stack_keys_region = m_region.get_stack_keys();
    std::cout << "  stack: {\n";
    for (auto const& k : stack_keys_region) {
        auto maybe_ptr_or_mapfd_cells = m_region.find_in_stack(k);
        if (maybe_ptr_or_mapfd_cells) {
            auto ptr_or_mapfd_cells = maybe_ptr_or_mapfd_cells.value();
            int width = ptr_or_mapfd_cells.second;
            auto ptr_or_mapfd = ptr_or_mapfd_cells.first;
            std::cout << "    [" << k << "-" << k+width-1 << "] : ";
            print_ptr_or_mapfd_type(std::cout, ptr_or_mapfd);
            std::cout << ",\n";
        }
    }
    std::cout << "  }\n";
}

void type_domain_t::adjust_bb_for_types(location_t loc) {
    m_region.adjust_bb_for_types(loc);
}

void type_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {

    if (print != 0) {
        print_annotated(std::cout, *this, bb, print);
        return;
    }

    auto label = bb.label();
    uint32_t curr_pos = 0;
    location_t loc = location_t(std::make_pair(label, curr_pos));
    if (print == 0)
        adjust_bb_for_types(loc);

    for (const Instruction& statement : bb) {
        loc = location_t(std::make_pair(label, ++curr_pos));
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }

    operator+=(m_region.get_errors());
}

std::optional<crab::ptr_or_mapfd_t>
type_domain_t::find_ptr_or_mapfd_at_loc(const crab::reg_with_loc_t& loc) const {
    return m_region.find_ptr_or_mapfd_at_loc(loc);
}

std::ostream& operator<<(std::ostream& o, const type_domain_t& typ) {
    typ.write(o);
    return o;
}

} // namespace crab

void print_annotated(std::ostream& o, const crab::type_domain_t& typ,
        const basic_block_t& bb, int print) {
    if (typ.is_bottom()) {
        o << bb << "\n";
        return;
    }
    if (print < 0) {
        o << "state of stack and ctx in program:\n";
        typ.print_ctx();
        typ.print_stack();
        o << "\n";
        return;
    }

    o << bb.label() << ":\n";
    uint32_t curr_pos = 0;
    for (const Instruction& statement : bb) {
        ++curr_pos;
        location_t loc = location_t(std::make_pair(bb.label(), curr_pos));
        o << "   " << curr_pos << ".";
        if (std::holds_alternative<Call>(statement)) {
            auto r0_reg = crab::reg_with_loc_t(register_t{R0_RETURN_VALUE}, loc);
            auto region = typ.find_ptr_or_mapfd_at_loc(r0_reg);
            print_annotated(o, std::get<Call>(statement), region);
        }
        else if (std::holds_alternative<Bin>(statement)) {
            auto b = std::get<Bin>(statement);
            auto reg_with_loc = crab::reg_with_loc_t(b.dst.v, loc);
            auto region = typ.find_ptr_or_mapfd_at_loc(reg_with_loc);
            print_annotated(o, b, region);
        }
        else if (std::holds_alternative<Mem>(statement)) {
            auto u = std::get<Mem>(statement);
            if (u.is_load) {
                auto target_reg = std::get<Reg>(u.value);
                auto target_reg_loc = crab::reg_with_loc_t(target_reg.v, loc);
                auto region = typ.find_ptr_or_mapfd_at_loc(target_reg_loc);
                print_annotated(o, u, region);
            }
            else o << "  " << u << "\n";
        }
        else if (std::holds_alternative<LoadMapFd>(statement)) {
            auto u = std::get<LoadMapFd>(statement);
            auto reg = crab::reg_with_loc_t(u.dst.v, loc);
            auto region = typ.find_ptr_or_mapfd_at_loc(reg);
            print_annotated(o, u, region);
        }
        else o << "  " << statement << "\n";
    }

    auto [it, et] = bb.next_blocks();
    if (it != et) {
        o << "  " << "goto ";
        for (; it != et;) {
            o << *it;
            ++it;
            if (it == et) {
                o << ";";
            } else {
                o << ",";
            }
        }
    }
    o << "\n\n";
}

