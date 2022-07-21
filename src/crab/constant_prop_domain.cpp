// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/constant_prop_domain.hpp"

namespace std {
    template <>
    struct hash<crab::reg_with_loc_t> {
        size_t operator()(const crab::reg_with_loc_t& reg) const { return reg.hash(); }
    };
}

bool registers_cp_state_t::is_bottom() const {
    return m_is_bottom;
}

bool registers_cp_state_t::is_top() const {
    if (m_is_bottom) return false;
    if (m_constant_env == nullptr) return true;
    for (auto it : m_cur_def) {
        if (it != nullptr) return false;
    }
    return true;
}

void registers_cp_state_t::set_to_top() {
    m_cur_def = live_registers_t{nullptr};
    m_is_bottom = false;
}

void registers_cp_state_t::set_to_bottom() {
    m_is_bottom = true;
}

void registers_cp_state_t::insert(register_t reg, const reg_with_loc_t& reg_with_loc,
        int constant) {
    (*m_constant_env)[reg_with_loc] = constant;
    m_cur_def[reg] = std::make_shared<reg_with_loc_t>(reg_with_loc);
}

std::optional<int> registers_cp_state_t::find(reg_with_loc_t reg) const {
    auto it = m_constant_env->find(reg);
    if (it == m_constant_env->end()) return {};
    return it->second;
}

std::optional<int> registers_cp_state_t::find(register_t key) const {
    if (m_cur_def[key] == nullptr) return {};
    const reg_with_loc_t& reg = *(m_cur_def[key]);
    return find(reg);
}

registers_cp_state_t registers_cp_state_t::operator|(const registers_cp_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    live_registers_t consts_joined;
    for (size_t i = 0; i < m_cur_def.size(); i++) {
        if (m_cur_def[i] == nullptr || other.m_cur_def[i] == nullptr) continue;
        auto it1 = find(*(m_cur_def[i]));
        auto it2 = other.find(*(other.m_cur_def[i]));
        if (it1 && it2) {
            int const1 = it1.value(), const2 = it2.value();
            if (const1 == const2) {
                consts_joined[i] = m_cur_def[i];
            }
        }
    }
    return registers_cp_state_t(std::move(consts_joined), m_constant_env);
}

//void registers_cp_state_t::print_all_consts() {
//    std::cout << "\nprinting all constant values: \n";
//    for (size_t i = 0; i < m_cur_def.size(); i++) {
//        if (m_cur_def[i]) {
//            std::cout << "r" << i << " = " << *m_cur_def[i] << "\n";
//        }
//    }
//    std::cout << "==============================\n\n";
//}

void registers_cp_state_t::operator-=(register_t var) {
    if (is_bottom()) {
        return;
    }
    m_cur_def[var] = nullptr;
}

bool stack_cp_state_t::is_bottom() const {
    return m_is_bottom;
}

bool stack_cp_state_t::is_top() const {
    if (m_is_bottom) return false;
    return m_const_values.empty();
}

void stack_cp_state_t::set_to_top() {
    m_const_values.clear();
    m_is_bottom = false;
}

void stack_cp_state_t::set_to_bottom() {
    m_is_bottom = true;
}

stack_cp_state_t stack_cp_state_t::top() {
    return stack_cp_state_t(false);
}

std::optional<int> stack_cp_state_t::find(int key) const {
    auto it = m_const_values.find(key);
    if (it == m_const_values.end()) return {};
    return it->second;
}

void stack_cp_state_t::store(int key, int val) {
    m_const_values[key] = val;
}

stack_cp_state_t stack_cp_state_t::operator|(const stack_cp_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    const_values_stack_t const_values_joined;
    for (auto const&kv: m_const_values) {
        auto it = other.m_const_values.find(kv.first);
        if (it != m_const_values.end() && kv.second == it->second)
            const_values_joined.insert(kv);
    }
    return stack_cp_state_t(std::move(const_values_joined));
}

bool constant_prop_domain_t::is_bottom() const {
    if (m_is_bottom) return true;
    return (m_registers_const_values.is_bottom() || m_stack_slots_const_values.is_bottom());
}

bool constant_prop_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_registers_const_values.is_top() && m_stack_slots_const_values.is_top());
}

constant_prop_domain_t constant_prop_domain_t::bottom() {
    constant_prop_domain_t cp;
    cp.set_to_bottom();
    return cp;
}

void constant_prop_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

void constant_prop_domain_t::set_to_top() {
    m_registers_const_values.set_to_top();
    m_stack_slots_const_values.set_to_top();
}


std::optional<int> constant_prop_domain_t::find_const_value(register_t reg) const {
    return m_registers_const_values.find(reg);
}

std::optional<int> constant_prop_domain_t::find_in_registers(const reg_with_loc_t reg) const {
    return m_registers_const_values.find(reg);
}

bool constant_prop_domain_t::operator<=(const constant_prop_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return true;
}

void constant_prop_domain_t::operator|=(const constant_prop_domain_t& abs) {
    constant_prop_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void constant_prop_domain_t::operator|=(constant_prop_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

constant_prop_domain_t constant_prop_domain_t::operator|(const constant_prop_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return constant_prop_domain_t(m_registers_const_values | other.m_registers_const_values,
            m_stack_slots_const_values | other.m_stack_slots_const_values);
}

constant_prop_domain_t constant_prop_domain_t::operator|(constant_prop_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return constant_prop_domain_t(m_registers_const_values | std::move(other.m_registers_const_values),
            m_stack_slots_const_values | std::move(other.m_stack_slots_const_values));
}

constant_prop_domain_t constant_prop_domain_t::operator&(const constant_prop_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

constant_prop_domain_t constant_prop_domain_t::widen(const constant_prop_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

constant_prop_domain_t constant_prop_domain_t::narrow(const constant_prop_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

void constant_prop_domain_t::write(std::ostream& os) const {}

std::string constant_prop_domain_t::domain_name() const {
    return "constant_prop_domain";
}

int constant_prop_domain_t::get_instruction_count_upper_bound() {
    /* WARNING: The operation is not implemented yet.*/
    return 0;
}

string_invariant constant_prop_domain_t::to_set() {
    return string_invariant{};
}

void constant_prop_domain_t::operator()(const Undefined & u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const Un &u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const Call &u, location_t loc, int print) {}
void constant_prop_domain_t::operator()(const Exit &u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const Jmp &u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const Packet & u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const LockAdd &u, location_t loc, int print) {
}
void constant_prop_domain_t::operator()(const Assume &u, location_t loc, int print) {
}

void constant_prop_domain_t::operator()(const ValidAccess& s, location_t loc, int print) {
}

void constant_prop_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
}

void constant_prop_domain_t::operator()(const Assert &u, location_t loc, int print) {
    if (is_bottom()) return;
    std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, u.cst);
}

constant_prop_domain_t constant_prop_domain_t::setup_entry() {
    std::shared_ptr<global_constant_env_t> all_constants = std::make_shared<global_constant_env_t>();
    registers_cp_state_t registers(all_constants);

    constant_prop_domain_t cp(std::move(registers), stack_cp_state_t::top());
    return cp;
}

void constant_prop_domain_t::do_bin(const Bin& bin, location_t loc) {
    auto dst_v = m_registers_const_values.find(bin.dst.v);
    std::optional<int> updated_dst_const = {};

    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        auto src_v = m_registers_const_values.find(src.v);

        if (!src_v) {
            m_registers_const_values -= bin.dst.v;;
            return;
        }

        auto src_const = src_v.value();
        switch (bin.op)
        {
            // ra = rb;
            case Bin::Op::MOV: {
                updated_dst_const = src_const;
                break;
            }
            // ra += rb
            case Bin::Op::ADD: {
                // both ra and rb are numbers, so handle here
                if (dst_v) {
                    updated_dst_const = dst_v.value() + src_const;
                }
                break;
            }
            // ra -= rb
            case Bin::Op::SUB: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() - src_const;
                }
                break;
            }
            // ra *= rb
            case Bin::Op::MUL: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() * src_const;
                }
                break;
            }
            // ra /= rb
            case Bin::Op::DIV: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() / src_const;
                }
                break;
            }
            // ra %= rb
            case Bin::Op::MOD: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() % src_const;
                }
                break;
            }
            // ra |= rb
            case Bin::Op::OR: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() | src_const;
                }
                break;
            }
            // ra &= rb
            case Bin::Op::AND: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() & src_const;
                }
                break;
            }
            // ra <<= rb
            case Bin::Op::LSH: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() << src_const;
                }
                break;
            }
            // ra >>= rb
            case Bin::Op::RSH: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() >> src_const;
                }
                break;
            }
            // ra >>>= rb
            case Bin::Op::ARSH: {
                if (dst_v) {
                    updated_dst_const = (int64_t)dst_v.value() >> src_const;
                }
                break;
            }
            // ra ^= rb
            case Bin::Op::XOR: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() ^ src_const;
                }
                break;
            }
        }
        //std::cout << "value of vb: " << *src_const << "\n";
    }
    else {
        int imm = static_cast<int>(std::get<Imm>(bin.v).v);
        switch (bin.op)
        {
            // ra = c, where c is a constant
            case Bin::Op::MOV: {
                updated_dst_const = imm;
                break;
            }
            // ra += c, where c is a constant
            case Bin::Op::ADD: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() + imm;
                }
                break;
            }
            // ra -= c
            case Bin::Op::SUB: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() - imm;
                }
                break;
            }
            // ra *= c
            case Bin::Op::MUL: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() * imm;
                }
                break;
            }
            // ra /= c
            case Bin::Op::DIV: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() / imm;
                }
                break;
            }
            // ra %= c
            case Bin::Op::MOD: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() % imm;
                }
                break;
            }
            // ra |= c
            case Bin::Op::OR: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() | imm;
                }
                break;
            }
            // ra &= c
            case Bin::Op::AND: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() & imm;
                }
                break;
            }
            // ra <<= c
            case Bin::Op::LSH: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() << imm;
                }
                break;
            }
            // ra >>= c
            case Bin::Op::RSH: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() >> imm;
                }
                break;
            }
            // ra >>>= c
            case Bin::Op::ARSH: {
                if (dst_v) {
                    updated_dst_const = (int64_t)dst_v.value() >> imm;
                }
                break;
            }
            // ra ^= c
            case Bin::Op::XOR: {
                if (dst_v) {
                    updated_dst_const = dst_v.value() ^ imm;
                }
                break;
            }
         }
    }
    auto reg_with_loc = reg_with_loc_t(bin.dst.v, loc);
    if (updated_dst_const)
        m_registers_const_values.insert(bin.dst.v, reg_with_loc, updated_dst_const.value());
}

void constant_prop_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (is_bottom()) return;
    do_bin(bin, loc);
}

void constant_prop_domain_t::do_load(const Mem& b, const Reg& target_reg, std::optional<ptr_t> basereg_type, location_t loc) {
    if (!basereg_type) {
        m_registers_const_values -= target_reg.v;
        return;
    }

    ptr_t basereg_ptr_type = basereg_type.value();
    int offset = b.access.offset;

    auto reg_with_loc = reg_with_loc_t(target_reg.v, loc);
    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_type)) {
        auto p_with_off = std::get<ptr_with_off_t>(basereg_ptr_type);
        int to_load = p_with_off.get_offset() + offset;

        if (p_with_off.get_region() == crab::region::T_STACK) {
            auto it = m_stack_slots_const_values.find(to_load);
            if (!it) {
                m_registers_const_values -= target_reg.v;
                return;
            }
            m_registers_const_values.insert(target_reg.v, reg_with_loc, it.value());
        }
        else {
            m_registers_const_values -= target_reg.v;
        }
    }
    else {  // we are loading from packet or shared
        m_registers_const_values -= target_reg.v;
    }
}

void constant_prop_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, std::optional<ptr_t> basereg_type) {
    int offset = b.access.offset;

    if (!basereg_type) {
        return;
    }
    ptr_t basereg_ptr_type = basereg_type.value();
    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_type)) {
        auto basereg_ptr_with_off_type = std::get<ptr_with_off_t>(basereg_ptr_type);
        int store_at = basereg_ptr_with_off_type.get_offset() + offset;
        if (basereg_ptr_with_off_type.get_region() == crab::region::T_STACK) {
            auto it = m_registers_const_values.find(target_reg.v);
            if (it) {
                m_stack_slots_const_values.store(store_at, it.value());
            }
        }
    }
    else {}
}

void constant_prop_domain_t::operator()(const Mem& b, location_t loc, int print) {
    if (is_bottom()) return;

    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), {}, loc);
        } else {
            do_mem_store(b, std::get<Reg>(b.value), {});
        }
    }
}

void constant_prop_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    auto label = bb.label();
    uint32_t curr_pos = 0;
    location_t loc;
    for (const Instruction& statement : bb) {
        std::cout << statement << "\n";
        loc = location_t(std::make_pair(label, ++curr_pos));
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }
}

void constant_prop_domain_t::set_require_check(check_require_func_t f) {}
