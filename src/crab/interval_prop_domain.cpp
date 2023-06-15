// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

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
        auto old_reg = reg_with_loc_t((register_t)i, old_loc);

        auto it = find((register_t)i);
        if (!it) continue;

        if (*m_cur_def[i] == old_reg)
            m_interval_env->erase(old_reg);

        m_cur_def[i] = std::make_shared<reg_with_loc_t>(new_reg);
        (*m_interval_env)[new_reg] = it.value();

    }
}

void registers_cp_state_t::operator-=(register_t var) {
    if (is_bottom()) {
        return;
    }
    m_cur_def[var] = nullptr;
}

void registers_cp_state_t::print_all_register_types() const {
    std::cout << "\tinterval types: {\n";
    for (auto const& kv : *m_interval_env) {
        std::cout << "\t\t" << kv.first << " : " << kv.second << "\n";
    }
    std::cout << "\t}\n";
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

std::optional<interval_cells_t> stack_cp_state_t::find(uint64_t key) const {
    auto it = m_interval_values.find(key);
    if (it == m_interval_values.end()) return {};
    return it->second;
}

void stack_cp_state_t::store(uint64_t key, interval_t val, int width) {
    m_interval_values[key] = std::make_pair(val, width);
}

void stack_cp_state_t::operator-=(uint64_t key) {
    auto it = find(key);
    if (it)
        m_interval_values.erase(key);
}

bool stack_cp_state_t::all_numeric(uint64_t start_loc, int width) const {
    auto overlapping_cells = find_overlapping_cells(start_loc, width);
    if (overlapping_cells.empty()) return false;
    for (std::size_t i = 0; i < overlapping_cells.size()-1; i++) {
        int width_i = find(overlapping_cells[i]).value().second;
        if (overlapping_cells[i]+width_i != overlapping_cells[i+1]) return false;
    }
    return true;
}

void stack_cp_state_t::remove_overlap(const std::vector<uint64_t>& keys, uint64_t start, int width) {
    for (auto& key : keys) {
        auto type = find(key);
        auto width_key = type.value().second;
        if (key < start) {
            int new_width = start-key;
            store(key, interval_t::top(), new_width);
        }
        if (key+width_key > start+width) {
            int new_width = key+width_key-(start+width);
            store(start+width, interval_t::top(), new_width);
        }
        if (key >= start) *this -= key;
    }
}

std::vector<uint64_t> stack_cp_state_t::find_overlapping_cells(uint64_t start, int width) const {
    std::vector<uint64_t> overlapping_cells;
    auto it = m_interval_values.begin();
    while (it != m_interval_values.end() && it->first < start) {
        it++;
    }
    if (it != m_interval_values.begin()) {
        it--;
        auto key = it->first;
        auto width_key = it->second.second;
        if (key < start && key+width_key > start) overlapping_cells.push_back(key);
    }

    for (; it != m_interval_values.end(); it++) {
        auto key = it->first;
        if (key >= start && key < start+width) overlapping_cells.push_back(key);
        if (key >= start+width) break;
    }
    return overlapping_cells;
}

void join_stack(const stack_cp_state_t& stack1, uint64_t key1, int& loc1,
        const stack_cp_state_t& stack2, uint64_t key2, int& loc2,
        interval_values_stack_t& interval_values_joined) {
    auto type1 = stack1.find(key1);    auto type2 = stack2.find(key2);
    auto& cells1 = type1.value();   auto& cells2 = type2.value();
    int width1 = cells1.second; int width2 = cells2.second;
    auto& interval1 = cells1.first; auto& interval2 = cells2.first;
    if (key1 == key2) {
        if (width1 == width2) {
            interval_values_joined[key1] = std::make_pair(interval1 | interval2, width1);
            loc1++; loc2++;
        }
        else if (width1 < width2) {
            interval_values_joined[key1] = std::make_pair(interval_t::top(), width1);
            loc1++;
        }
        else {
            interval_values_joined[key1] = std::make_pair(interval_t::top(), width2);
            loc2++;
        }
    }
    else if (key1 > key2) {
        if (key2+width2 > key1+width1) {
            interval_values_joined[key1] = std::make_pair(interval_t::top(), width1);
            loc1++;
        }
        else if (key2+width2 > key1) {
            interval_values_joined[key1] = std::make_pair(interval_t::top(), key2+width2-key1);
            loc2++;
        }
        else loc2++;
    }
    else {
        join_stack(stack2, key2, loc2, stack1, key1, loc1, interval_values_joined);
    }
}

stack_cp_state_t stack_cp_state_t::operator|(const stack_cp_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    interval_values_stack_t interval_values_joined;
    auto stack1_keys = get_keys();
    auto stack2_keys = other.get_keys();
    int i = 0, j = 0;
    while (i < static_cast<int>(stack1_keys.size()) && j < static_cast<int>(stack2_keys.size())) {
        int key1 = stack1_keys[i], key2 = stack2_keys[j];
        join_stack(*this, key1, i, other, key2, j, interval_values_joined);
    }
    return stack_cp_state_t(std::move(interval_values_joined));
}

size_t stack_cp_state_t::size() const {
    return m_interval_values.size();
}

std::vector<uint64_t> stack_cp_state_t::get_keys() const {
    std::vector<uint64_t> keys;
    keys.reserve(size());

    for (auto const&kv : m_interval_values) {
        keys.push_back(kv.first);
    }
    return keys;
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

std::optional<interval_t> interval_prop_domain_t::find_interval_at_loc(const reg_with_loc_t reg) const {
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

void interval_prop_domain_t::operator()(const Un& u, location_t loc, int print) {
    auto reg_with_loc = reg_with_loc_t(u.dst.v, loc);
    m_registers_interval_values.insert(u.dst.v, reg_with_loc, interval_t::top());
}

void interval_prop_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    m_registers_interval_values -= u.dst.v;
}

void interval_prop_domain_t::operator()(const ValidSize& s, location_t loc, int print) {
    auto reg_v = m_registers_interval_values.find(s.reg.v);
    if (reg_v) {
        auto reg_value = reg_v.value();
        if ((s.can_be_zero && reg_value.lb() >= bound_t(0))
                || (!s.can_be_zero && reg_value.lb() > bound_t(0))) {
            return;
        }
    }
    std::cout << "Valid Size assertion fail\n";
}

void interval_prop_domain_t::do_call(const Call& u, const interval_values_stack_t& store_in_stack,
        location_t loc) {

    auto r0 = register_t{R0_RETURN_VALUE};
    for (const auto& kv : store_in_stack) {
        auto key = kv.first;
        auto width = kv.second.second;
        auto overlapping_cells
            = m_stack_slots_interval_values.find_overlapping_cells(key, width);
        m_stack_slots_interval_values.remove_overlap(overlapping_cells, key, width);
        m_stack_slots_interval_values.store(kv.first, kv.second.first, kv.second.second);
    }
    if (u.is_map_lookup) {
        m_registers_interval_values -= r0;
    }
    else {
        auto r0_with_loc = reg_with_loc_t(r0, loc);
        m_registers_interval_values.insert(r0, r0_with_loc, interval_t::top());
    }
}

void interval_prop_domain_t::operator()(const Packet &u, location_t loc, int print) {
    auto r0 = register_t{R0_RETURN_VALUE};
    auto r0_with_loc = reg_with_loc_t(r0, loc);
    m_registers_interval_values.insert(r0, r0_with_loc, interval_t::top());
}

void interval_prop_domain_t::operator()(const Assume &s, location_t loc, int print) {
    // TODO: generalize for intervals
    using Op = Condition::Op;
    Condition cond = s.cond;
    int64_t imm = 0;
    bool is_imm = false;
    auto reg_with_loc = reg_with_loc_t(cond.left.v, loc);
    auto left_reg_optional = m_registers_interval_values.find(cond.left.v);
    if (!left_reg_optional) {
        return;
    }
    auto left_value = left_reg_optional.value();
    bound_t right_value = bound_t(-1);
    if (std::holds_alternative<Reg>(cond.right)) {
        auto reg = std::get<Reg>(cond.right).v;
        auto right_reg_optional = m_registers_interval_values.find(reg);
        if (!right_reg_optional) {
            std::cout << "type error: assumption for an unknown register\n";
            return;
        }
        auto right_reg = right_reg_optional.value();
        auto right_reg_singleton = right_reg.singleton();
        if (!right_reg_singleton) {
            std::cout << "assumption for a non-singleton register\n";
            return;
        }
        right_value = right_reg_singleton.value();
    }
    else {
        imm = std::get<Imm>(cond.right).v;
        is_imm = true;
        right_value = bound_t(static_cast<int>(imm));
    }
    bool is_right_within_left_interval = left_value.lb() <= right_value
        && right_value <= left_value.ub();
    switch (cond.op) {
        case Op::EQ: {
            if (is_right_within_left_interval)
                m_registers_interval_values.insert(cond.left.v, reg_with_loc, interval_t(right_value));
            return;
        }
        case Op::NE: {
            if (right_value <= left_value.lb() || right_value >= left_value.ub()) {
                if (right_value == left_value.lb())
                    m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                            interval_t(bound_t(left_value.lb() + 1), left_value.ub()));
                else if (right_value == left_value.ub())
                    m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                            interval_t(left_value.lb(), bound_t(left_value.ub() - 1)));
                return;
            }
            break;
        }
        case Op::SGE:
        case Op::GE:
        {
            if (is_right_within_left_interval || right_value < left_value.lb()) {
                if (is_right_within_left_interval) {
                    if (cond.op == Op::GE && is_imm) {
                        auto value = bound_t(static_cast<unsigned int>(imm));
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(value, left_value.ub()));
                    }
                    else {
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(right_value, left_value.ub()));
                    }
                }
                return;
            }
            break;
        }
        case Op::SLE:
        case Op::LE:
        {
            if (is_right_within_left_interval || right_value > left_value.ub()) {
                if (is_right_within_left_interval) {
                    if (cond.op == Op::LE && is_imm && left_value.lb() < bound_t(0)) {
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(bound_t(0), right_value));
                    }
                    else {
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(left_value.lb(), right_value));
                    }
                }
                return;
            }
            break;
        }
        case Op::SGT:
        case Op::GT: {
            auto right_value_plus_1 = right_value + bound_t(1);
            bool is_right_plus_1_within_left_interval = left_value.lb() <= right_value_plus_1
                && right_value_plus_1 <= left_value.ub();
            if (is_right_plus_1_within_left_interval || right_value_plus_1 < left_value.lb()) {
                if (is_right_plus_1_within_left_interval) {
                    if (cond.op == Op::GT && is_imm) {
                        auto value = bound_t(static_cast<unsigned int>(imm));
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(value + bound_t(1), left_value.ub()));
                    }
                    else {
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(right_value_plus_1, left_value.ub()));
                    }
                }
                return;
            }
            break;
        }
        case Op::SLT:
        case Op::LT: {
            auto right_value_minus_1 = right_value - bound_t(1);
            bool is_right_minus_1_within_left_interval = left_value.lb() <= right_value_minus_1
                && right_value_minus_1 <= left_value.ub();
            if (is_right_minus_1_within_left_interval || right_value_minus_1 > left_value.ub()) {
                if (is_right_minus_1_within_left_interval) {
                    if (cond.op == Op::LT && is_imm) {
                        auto value = bound_t(static_cast<unsigned int>(imm));
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(left_value.lb(), value - bound_t(1)));
                    }
                    else {
                        m_registers_interval_values.insert(cond.left.v, reg_with_loc,
                                interval_t(left_value.lb(), right_value_minus_1));
                    }
                }
                return;
            }
            break;
        }
        default: return;
        m_registers_interval_values.insert(cond.left.v, reg_with_loc, interval_t::bottom());
    }
}

void interval_prop_domain_t::do_bin(const Bin& bin,
        const std::optional<interval_t>& src_interval_opt,
        const std::optional<interval_t>& dst_interval_opt,
        const std::optional<ptr_or_mapfd_t>& src_ptr_or_mapfd_opt,
        const std::optional<ptr_or_mapfd_t>& dst_ptr_or_mapfd_opt,
        const interval_t& subtract_interval, location_t loc) {
    using Op = Bin::Op;
    // if op is not MOV,
        // we skip handling in this domain is when dst is pointer and src is numerical value
    if (bin.op != Op::MOV && dst_ptr_or_mapfd_opt && src_interval_opt) return;
    // if op is MOV,
        // we skip handling in this domain is when both dst and src are pointers
        // when dst is not known and src is pointer
    if (bin.op == Op::MOV &&
            ((dst_ptr_or_mapfd_opt && src_ptr_or_mapfd_opt)
             || (!dst_interval_opt && src_ptr_or_mapfd_opt)))
        return;

    uint64_t imm = std::holds_alternative<Imm>(bin.v) ? std::get<Imm>(bin.v).v : 0;
    interval_t src_interval, dst_interval;
    if (src_interval_opt) src_interval = std::move(src_interval_opt.value());
    if (dst_interval_opt) dst_interval = std::move(dst_interval_opt.value());

    auto reg_with_loc = reg_with_loc_t(bin.dst.v, loc);
    switch (bin.op)
    {
        // ra = b
        case Op::MOV: {
            if (src_interval_opt)
                dst_interval = src_interval;
            else if (dst_interval_opt) {
                m_registers_interval_values -= bin.dst.v;
                return;
            }
            break;
        }
        // ra += b
        case Op::ADD: {
            if (dst_ptr_or_mapfd_opt && src_ptr_or_mapfd_opt) return;
            if (dst_interval_opt && src_interval_opt)
                dst_interval += src_interval;
            else if (dst_interval_opt && src_ptr_or_mapfd_opt) {
                m_registers_interval_values -= bin.dst.v;
                return;
            }
            break;
        }
        // ra -= b
        case Op::SUB: {
            if (dst_ptr_or_mapfd_opt && src_ptr_or_mapfd_opt)
                dst_interval = subtract_interval;
            else if (dst_interval_opt && src_interval_opt)
                dst_interval -= src_interval;
            else if (dst_interval_opt && src_ptr_or_mapfd_opt) {
                m_registers_interval_values -= bin.dst.v;
                return;
            }
            break;
        }
        // ra *= b
        case Op::MUL: {
            dst_interval *= src_interval;
            break;
        }
        // ra /= b
        case Op::DIV: {
            dst_interval /= src_interval;
            break;
        }
        // ra %= b
        case Op::MOD: {
            dst_interval = dst_interval.SRem(src_interval);
            break;
        }
        // ra |= b
        case Op::OR: {
            dst_interval = dst_interval.Or(src_interval);
            break;
        }
        // ra &= b
        case Op::AND: {
            dst_interval = dst_interval.And(src_interval);
            if ((int32_t)imm > 0)
                dst_interval = interval_t(number_t(0), number_t(static_cast<int>(imm)));
            break;
        }
        // ra <<= b
        case Op::LSH: {
            dst_interval = dst_interval.Shl(src_interval);
            break;
        }
        // ra >>= b
        case Op::RSH: {
            dst_interval = dst_interval.LShr(src_interval);
            break;
        }
        // ra >>>= b
        case Op::ARSH: {
            dst_interval = dst_interval.AShr(src_interval);
            break;
        }
        // ra ^= b
        case Op::XOR: {
            dst_interval = dst_interval.Xor(src_interval);
            break;
        }
        default: {
            dst_interval = interval_t::top();
            break;
        }
    }
    m_registers_interval_values.insert(bin.dst.v, reg_with_loc, dst_interval);
}


void interval_prop_domain_t::do_load(const Mem& b, const Reg& target_reg,
        std::optional<ptr_or_mapfd_t> basereg_type, std::optional<ptr_or_mapfd_t> targetreg_type,
        location_t loc) {
    if (!basereg_type) {
        m_registers_interval_values -= target_reg.v;
        return;
    }

    auto basereg_ptr_or_mapfd_type = basereg_type.value();
    int offset = b.access.offset;
    int width = b.access.width;

    auto reg_with_loc = reg_with_loc_t(target_reg.v, loc);
    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_or_mapfd_type)) {
        auto p_with_off = std::get<ptr_with_off_t>(basereg_ptr_or_mapfd_type);
        auto offset_singleton = p_with_off.get_offset().singleton();
        if (!offset_singleton) {
            m_registers_interval_values -= target_reg.v;
            std::cout << "doing a load with unknown offset\n";
            return;
        }
        auto to_load = (uint64_t)offset_singleton.value() + (uint64_t)offset;

        if (p_with_off.get_region() == crab::region_t::T_STACK) {
            auto it = m_stack_slots_interval_values.find(to_load);
            if (!it) {
                if (m_stack_slots_interval_values.all_numeric(to_load, width)) {
                    m_registers_interval_values.insert(target_reg.v, reg_with_loc,
                            interval_t::top());
                    return;
                }
                m_registers_interval_values -= target_reg.v;
                return;
            }
            m_registers_interval_values.insert(target_reg.v, reg_with_loc, it.value().first);
            return;
        }
    }
    if (!targetreg_type) {  // we are loading from ctx, packet or shared
        m_registers_interval_values.insert(target_reg.v, reg_with_loc, interval_t::top());
    }
    else {
        m_registers_interval_values -= target_reg.v;
    }
}

void interval_prop_domain_t::do_mem_store(const Mem& b, const Reg& target_reg,
        std::optional<ptr_or_mapfd_t> basereg_type) {
    int offset = b.access.offset;
    int width = b.access.width;

    if (!basereg_type) {
        return;
    }
    auto basereg_ptr_or_mapfd_type = basereg_type.value();
    auto targetreg_type = m_registers_interval_values.find(target_reg.v);
    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_or_mapfd_type)) {
        auto basereg_ptr_with_off_type = std::get<ptr_with_off_t>(basereg_ptr_or_mapfd_type);
        auto offset_singleton = basereg_ptr_with_off_type.get_offset().singleton();
        if (!offset_singleton) {
            std::cout << "doing a store with unknown offset\n";
            return;
        }
        auto store_at = (uint64_t)offset_singleton.value() + (uint64_t)offset;
        if (basereg_ptr_with_off_type.get_region() == crab::region_t::T_STACK) {
            auto overlapping_cells
                = m_stack_slots_interval_values.find_overlapping_cells(store_at, width);
            m_stack_slots_interval_values.remove_overlap(overlapping_cells, store_at, width);

            // if targetreg_type is empty, we are storing a pointer
            if (!targetreg_type) return;

            auto type_to_store = targetreg_type.value();
            m_stack_slots_interval_values.store(store_at, type_to_store, width);
        }
    }
    else {}
}

std::optional<interval_cells_t> interval_prop_domain_t::find_in_stack(uint64_t key) const {
    return m_stack_slots_interval_values.find(key);
}

void interval_prop_domain_t::adjust_bb_for_types(location_t loc) {
    m_registers_interval_values.adjust_bb_for_registers(loc);
}

void interval_prop_domain_t::print_all_register_types() const {
    m_registers_interval_values.print_all_register_types();
}

std::vector<uint64_t> interval_prop_domain_t::get_stack_keys() const {
    return m_stack_slots_interval_values.get_keys();
}

bool interval_prop_domain_t::all_numeric_in_stack(uint64_t start_loc, int width) const {
    return m_stack_slots_interval_values.all_numeric(start_loc, width);
}
