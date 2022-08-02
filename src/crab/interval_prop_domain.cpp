// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/interval_prop_domain.hpp"

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
    if (m_interval_env == nullptr) return true;
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
        interval_t interval) {
    (*m_interval_env)[reg_with_loc] = interval;
    m_cur_def[reg] = std::make_shared<reg_with_loc_t>(reg_with_loc);
}

std::optional<interval_t> registers_cp_state_t::find(reg_with_loc_t reg) const {
    auto it = m_interval_env->find(reg);
    if (it == m_interval_env->end()) return {};
    return it->second;
}

std::optional<interval_t> registers_cp_state_t::find(register_t key) const {
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
    live_registers_t intervals_joined;
    location_t loc = location_t(std::make_pair(label_t(-2, -2), 0));
    for (size_t i = 0; i < m_cur_def.size(); i++) {
        if (m_cur_def[i] == nullptr || other.m_cur_def[i] == nullptr) continue;
        auto it1 = find(*(m_cur_def[i]));
        auto it2 = other.find(*(other.m_cur_def[i]));
        if (it1 && it2) {
            auto interval1 = it1.value(), interval2 = it2.value();
            auto reg = reg_with_loc_t((register_t)i, loc);
            intervals_joined[i] = std::make_shared<reg_with_loc_t>(reg);
            (*m_interval_env)[reg] = interval1 | interval2;
        }
    }
    return registers_cp_state_t(std::move(intervals_joined), m_interval_env);
}

void registers_cp_state_t::adjust_bb_for_registers(location_t loc) {
    location_t old_loc = location_t(std::make_pair(label_t(-2, -2), 0));
    for (size_t i = 0; i < m_cur_def.size(); i++) {
        auto new_reg = reg_with_loc_t((register_t)i, loc);
        auto it = find((register_t)i);
        if (!it) continue;
        m_cur_def[i] = std::make_shared<reg_with_loc_t>(new_reg);
        (*m_interval_env)[new_reg] = it.value();

        auto old_reg = reg_with_loc_t((register_t)i, old_loc);
        if (*m_cur_def[i] == old_reg)
            m_interval_env->erase(old_reg);
    }
}

//void registers_cp_state_t::print_all_consts() {
//    std::cout << "\nprinting all interval values: \n";
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
    return m_interval_values.empty();
}

void stack_cp_state_t::set_to_top() {
    m_interval_values.clear();
    m_is_bottom = false;
}

void stack_cp_state_t::set_to_bottom() {
    m_is_bottom = true;
}

stack_cp_state_t stack_cp_state_t::top() {
    return stack_cp_state_t(false);
}

std::optional<interval_t> stack_cp_state_t::find(int key) const {
    auto it = m_interval_values.find(key);
    if (it == m_interval_values.end()) return {};
    return it->second;
}

void stack_cp_state_t::store(int key, interval_t val) {
    m_interval_values[key] = val;
}

stack_cp_state_t stack_cp_state_t::operator|(const stack_cp_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    interval_values_stack_t interval_values_joined;
    for (auto const&kv: m_interval_values) {
        auto it = other.m_interval_values.find(kv.first);
        if (it != m_interval_values.end() && kv.second == it->second)
            interval_values_joined.insert(kv);
    }
    return stack_cp_state_t(std::move(interval_values_joined));
}

bool interval_prop_domain_t::is_bottom() const {
    if (m_is_bottom) return true;
    return (m_registers_interval_values.is_bottom() || m_stack_slots_interval_values.is_bottom());
}

bool interval_prop_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_registers_interval_values.is_top() && m_stack_slots_interval_values.is_top());
}

interval_prop_domain_t interval_prop_domain_t::bottom() {
    interval_prop_domain_t cp;
    cp.set_to_bottom();
    return cp;
}

void interval_prop_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

void interval_prop_domain_t::set_to_top() {
    m_registers_interval_values.set_to_top();
    m_stack_slots_interval_values.set_to_top();
}

std::optional<interval_t> interval_prop_domain_t::find_interval_value(register_t reg) const {
    return m_registers_interval_values.find(reg);
}

std::optional<interval_t> interval_prop_domain_t::find_in_registers(const reg_with_loc_t reg) const {
    return m_registers_interval_values.find(reg);
}

bool interval_prop_domain_t::operator<=(const interval_prop_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return true;
}

void interval_prop_domain_t::operator|=(const interval_prop_domain_t& abs) {
    interval_prop_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void interval_prop_domain_t::operator|=(interval_prop_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

interval_prop_domain_t interval_prop_domain_t::operator|(const interval_prop_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return interval_prop_domain_t(m_registers_interval_values | other.m_registers_interval_values,
            m_stack_slots_interval_values | other.m_stack_slots_interval_values);
}

interval_prop_domain_t interval_prop_domain_t::operator|(interval_prop_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return interval_prop_domain_t(m_registers_interval_values | std::move(other.m_registers_interval_values),
            m_stack_slots_interval_values | std::move(other.m_stack_slots_interval_values));
}

interval_prop_domain_t interval_prop_domain_t::operator&(const interval_prop_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

interval_prop_domain_t interval_prop_domain_t::widen(const interval_prop_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

interval_prop_domain_t interval_prop_domain_t::narrow(const interval_prop_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

void interval_prop_domain_t::write(std::ostream& os) const {}

std::string interval_prop_domain_t::domain_name() const {
    return "interval_prop_domain";
}

int interval_prop_domain_t::get_instruction_count_upper_bound() {
    /* WARNING: The operation is not implemented yet.*/
    return 0;
}

string_invariant interval_prop_domain_t::to_set() {
    return string_invariant{};
}

interval_prop_domain_t interval_prop_domain_t::setup_entry() {
    std::shared_ptr<global_interval_env_t> all_intervals = std::make_shared<global_interval_env_t>();
    registers_cp_state_t registers(all_intervals);

    interval_prop_domain_t cp(std::move(registers), stack_cp_state_t::top());
    return cp;
}

void interval_prop_domain_t::operator()(const ValidSize& s, location_t loc, int print) {
    auto reg_v = m_registers_interval_values.find(s.reg.v);
    if (reg_v) {
        auto reg_value = reg_v.value();
        std::cout << "valid size assertion: " << reg_value << "\n";
        if ((s.can_be_zero && reg_value.lb() >= bound_t(0))
                || (!s.can_be_zero && reg_value.lb() > bound_t(0))) {
            return;
        }
    }
    std::cout << "Valid Size assertion fail\n";
}

void interval_prop_domain_t::do_bin(const Bin& bin, location_t loc) {
    auto dst_v = m_registers_interval_values.find(bin.dst.v);
    std::optional<interval_t> updated_dst_interval = {};

    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        auto src_v = m_registers_interval_values.find(src.v);

        if (!src_v) {
            m_registers_interval_values -= bin.dst.v;;
            return;
        }

        auto src_interval = src_v.value();
        switch (bin.op)
        {
            // ra = rb;
            case Bin::Op::MOV: {
                updated_dst_interval = src_interval;
                break;
            }
            // ra += rb
            case Bin::Op::ADD: {
                // both ra and rb are numbers, so handle here
                if (dst_v) {
                    updated_dst_interval = dst_v.value() + src_interval;
                }
                break;
            }
            // ra -= rb
            case Bin::Op::SUB: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() - src_interval;
                }
                break;
            }
            /*
            // ra *= rb
            case Bin::Op::MUL: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() * src_interval;
                }
                break;
            }
            // ra /= rb
            case Bin::Op::DIV: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() / src_interval;
                }
                break;
            }
            // ra %= rb
            case Bin::Op::MOD: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() % src_interval;
                }
                break;
            }
            // ra |= rb
            case Bin::Op::OR: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() | src_interval;
                }
                break;
            }
            // ra &= rb
            case Bin::Op::AND: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() & src_interval;
                }
                break;
            }
            // ra <<= rb
            case Bin::Op::LSH: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() << src_interval;
                }
                break;
            }
            // ra >>= rb
            case Bin::Op::RSH: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() >> src_interval;
                }
                break;
            }
            // ra >>>= rb
            case Bin::Op::ARSH: {
                if (dst_v) {
                    updated_dst_interval = (int64_t)dst_v.value() >> src_interval;
                }
                break;
            }
            // ra ^= rb
            case Bin::Op::XOR: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() ^ src_interval;
                }
                break;
            }
            */
            default: {
                m_registers_interval_values -= bin.dst.v;
                break;
            }
        }
        //std::cout << "value of vb: " << *src_interval << "\n";
    }
    else {
        int imm = static_cast<int>(std::get<Imm>(bin.v).v);
        switch (bin.op)
        {
            // ra = c, where c is a interval
            case Bin::Op::MOV: {

                updated_dst_interval = interval_t(number_t(imm));
                break;
            }
            // ra += c, where c is a interval
            case Bin::Op::ADD: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() + interval_t(number_t(imm));
                }
                break;
            }
            // ra -= c
            case Bin::Op::SUB: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() - interval_t(number_t(imm));
                }
                break;
            }
            /*
            // ra *= c
            case Bin::Op::MUL: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() * interval_t(number_t(imm));
                }
                break;
            }
            // ra /= c
            case Bin::Op::DIV: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() / interval_t(number_t(imm));
                }
                break;
            }
            // ra %= c
            case Bin::Op::MOD: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() % interval_t(number_t(imm));
                }
                break;
            }
            // ra |= c
            case Bin::Op::OR: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() | interval_t(number_t(imm));
                }
                break;
            }
            // ra &= c
            case Bin::Op::AND: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() & interval_t(number_t(imm));
                }
                break;
            }
            // ra <<= c
            case Bin::Op::LSH: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() << interval_t(number_t(imm));
                }
                break;
            }
            // ra >>= c
            case Bin::Op::RSH: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() >> interval_t(number_t(imm));
                }
                break;
            }
            // ra >>>= c
            case Bin::Op::ARSH: {
                if (dst_v) {
                    updated_dst_interval = (int64_t)dst_v.value() >> interval_t(number_t(imm));
                }
                break;
            }
            // ra ^= c
            case Bin::Op::XOR: {
                if (dst_v) {
                    updated_dst_interval = dst_v.value() ^ interval_t(number_t(imm));
                }
                break;
            }
            */
            default: {
                m_registers_interval_values -= bin.dst.v;
                break;
            }
        }
    }
    auto reg_with_loc = reg_with_loc_t(bin.dst.v, loc);
    if (updated_dst_interval)
        m_registers_interval_values.insert(bin.dst.v, reg_with_loc, updated_dst_interval.value());
}

void interval_prop_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    do_bin(bin, loc);
}

void interval_prop_domain_t::do_load(const Mem& b, const Reg& target_reg,
        std::optional<ptr_or_mapfd_t> basereg_type, location_t loc) {
    if (!basereg_type) {
        m_registers_interval_values -= target_reg.v;
        return;
    }

    auto basereg_ptr_or_mapfd_type = basereg_type.value();
    int offset = b.access.offset;

    auto reg_with_loc = reg_with_loc_t(target_reg.v, loc);
    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_or_mapfd_type)) {
        auto p_with_off = std::get<ptr_with_off_t>(basereg_ptr_or_mapfd_type);
        if (p_with_off.get_region() != crab::region_t::T_STACK) {
            m_registers_interval_values -= target_reg.v;
            return;
        }

        int to_load = p_with_off.get_offset() + offset;
        auto it = m_stack_slots_interval_values.find(to_load);
        if (!it) {
            m_registers_interval_values -= target_reg.v;
            return;
        }
        m_registers_interval_values.insert(target_reg.v, reg_with_loc, it.value());
    }
    else {  // we are loading from packet or shared
        m_registers_interval_values -= target_reg.v;
    }
}

void interval_prop_domain_t::do_mem_store(const Mem& b, const Reg& target_reg,
        std::optional<ptr_or_mapfd_t> basereg_type) {
    int offset = b.access.offset;

    if (!basereg_type) {
        return;
    }
    auto basereg_ptr_or_mapfd_type = basereg_type.value();
    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_or_mapfd_type)) {
        auto basereg_ptr_with_off_type = std::get<ptr_with_off_t>(basereg_ptr_or_mapfd_type);
        int store_at = basereg_ptr_with_off_type.get_offset() + offset;
        if (basereg_ptr_with_off_type.get_region() == crab::region_t::T_STACK) {
            auto it = m_registers_interval_values.find(target_reg.v);
            if (it) {
                m_stack_slots_interval_values.store(store_at, it.value());
            }
        }
    }
    else {}
}

void interval_prop_domain_t::operator()(const Mem& b, location_t loc, int print) {
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), {}, loc);
        } else {
            do_mem_store(b, std::get<Reg>(b.value), {});
        }
    }
}

void interval_prop_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    auto label = bb.label();
    uint32_t curr_pos = 0;
    location_t loc;
    for (const Instruction& statement : bb) {
        std::cout << statement << "\n";
        loc = location_t(std::make_pair(label, ++curr_pos));
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }
}

void interval_prop_domain_t::adjust_bb_for_types(location_t loc) {
    m_registers_interval_values.adjust_bb_for_registers(loc);
}
