// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "crab/offset_domain.hpp"

namespace std {
    template <>
    struct hash<crab::reg_with_loc_t> {
        size_t operator()(const crab::reg_with_loc_t& reg) const { return reg.hash(); }
    };
}

bool dist_t::operator==(const dist_t& d) const {
    return (m_dist == d.m_dist && m_slack == d.m_slack);
}

void dist_t::write(std::ostream& o) const {
    if (m_slack != -1)
        o << "s" << m_slack << "+";
    if (is_meta_pointer())
        o << "meta";
    else if (is_forward_pointer()) {
        o << "begin+" << m_dist;
    }
    else if (is_backward_pointer()) {
        o << "end-" << (-1)*m_dist-4099;
    }
}

bool dist_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_slack == -1 && m_dist.is_top());
}

bool dist_t::is_bottom() const {
    return m_is_bottom;
}

void dist_t::set_to_top() {
    m_slack = -1;
    m_dist = interval_t::top();
    m_is_bottom = false;
}

void dist_t::set_to_bottom() {
    m_is_bottom = true;
}

bool dist_t::is_meta_pointer() const {
    return (m_dist.lb() >= -4098 && m_dist.ub() < 0);
}
bool dist_t::is_forward_pointer() const {
    return (m_dist.lb() >= 0);
}
bool dist_t::is_backward_pointer() const {
    return (m_dist.ub() < 4098);
}

std::ostream& operator<<(std::ostream& o, const dist_t& d) {
    d.write(o);
    return o;
}

bool inequality_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_slack == -1 && m_value.is_top());
}

bool inequality_t::is_bottom() const {
    return m_is_bottom;
}

void inequality_t::set_to_top() {
    m_value = interval_t::top();
    m_slack = -1;
    m_is_bottom = false;
}

void inequality_t::set_to_bottom() {
    m_is_bottom = true;
}

bool forward_and_backward_eq_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_forw.is_top() && m_backw.is_top());
}

bool forward_and_backward_eq_t::is_bottom() const {
    return m_is_bottom;
}

void forward_and_backward_eq_t::set_to_top() {
    m_forw.set_to_top();
    m_backw.set_to_top();
    m_is_bottom = false;
}

void forward_and_backward_eq_t::set_to_bottom() {
    m_is_bottom = true;
}

void registers_state_t::insert(register_t reg, const reg_with_loc_t& reg_with_loc,
        const dist_t& dist) {
    (*m_offset_env)[reg_with_loc] = dist;
    m_cur_def[reg] = std::make_shared<reg_with_loc_t>(reg_with_loc);
}

std::optional<dist_t> registers_state_t::find(reg_with_loc_t reg) const {
    auto it = m_offset_env->find(reg);
    if (it == m_offset_env->end()) return {};
    return it->second;
}

std::optional<dist_t> registers_state_t::find(register_t key) const {
    if (m_cur_def[key] == nullptr) return {};
    const reg_with_loc_t& reg = *(m_cur_def[key]);
    return find(reg);
}

void registers_state_t::set_to_top() {
    m_cur_def = live_registers_t{nullptr};
    m_is_bottom = false;
}

void registers_state_t::set_to_bottom() {
    m_cur_def = live_registers_t{nullptr};
    m_is_bottom = true;
}

bool registers_state_t::is_top() const {
    if (m_is_bottom) return false;
    if (m_offset_env == nullptr) return true;
    for (auto &it : m_cur_def) {
        if (it != nullptr) return false;
    }
    return true;
}

bool registers_state_t::is_bottom() const {
    return m_is_bottom;
}

void registers_state_t::operator-=(register_t to_forget) {
    if (is_bottom()) {
        return;
    }
    m_cur_def[to_forget] = nullptr;
}

registers_state_t registers_state_t::operator|(const registers_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    live_registers_t out_vars;
    location_t loc = location_t(std::make_pair(label_t(-2, -2), 0));

    for (size_t i = 0; i < m_cur_def.size(); i++) {
        if (m_cur_def[i] == nullptr || other.m_cur_def[i] == nullptr) continue;
        auto it1 = find(*(m_cur_def[i]));
        auto it2 = other.find(*(other.m_cur_def[i]));
        if (it1 && it2) {
            dist_t dist1 = it1.value(), dist2 = it2.value();
            auto reg = reg_with_loc_t((register_t)i, loc);
            if (dist1.m_slack != dist2.m_slack) continue;
            auto dist_joined = dist_t(std::move(dist1.m_dist | dist2.m_dist), dist1.m_slack);
            out_vars[i] = std::make_shared<reg_with_loc_t>(reg);
            (*m_offset_env)[reg] = dist_joined;
        }
    }
    return registers_state_t(std::move(out_vars), m_offset_env, false);
}

void registers_state_t::adjust_bb_for_registers(location_t loc) {
    location_t old_loc = location_t(std::make_pair(label_t(-2, -2), 0));
    for (size_t i = 0; i < m_cur_def.size(); i++) {
        auto new_reg = reg_with_loc_t((register_t)i, loc);
        auto old_reg = reg_with_loc_t((register_t)i, old_loc);

        auto it = find((register_t)i);
        if (!it) continue;

        if (*m_cur_def[i] == old_reg)
            m_offset_env->erase(old_reg);

        m_cur_def[i] = std::make_shared<reg_with_loc_t>(new_reg);
        (*m_offset_env)[new_reg] = it.value();
    }
}

void registers_state_t::print_all_register_types() const {
    std::cout << "\toffset types: {\n";
    for (auto const& kv : *m_offset_env) {
        std::cout << "\t\t" << kv.first << " : " << kv.second << "\n";
    }
    std::cout << "\t}\n";
}

void stack_state_t::set_to_top() {
    m_slot_dists.clear();
    m_is_bottom = false;
}

void stack_state_t::set_to_bottom() {
    m_slot_dists.clear();
    m_is_bottom = true;
}

bool stack_state_t::is_top() const {
    if (m_is_bottom) return false;
    return m_slot_dists.empty();
}

bool stack_state_t::is_bottom() const {
    return m_is_bottom;
}

stack_state_t stack_state_t::top() {
    return stack_state_t(false);
}

std::optional<dist_t> stack_state_t::find(int key) const {
    auto it = m_slot_dists.find(key);
    if (it == m_slot_dists.end()) return {};
    return it->second;
}

void stack_state_t::store(int key, dist_t d) {
    m_slot_dists[key] = d;
}

void stack_state_t::operator-=(int to_erase) {
    if (is_bottom()) {
        return;
    }
    m_slot_dists.erase(to_erase);
}

stack_state_t stack_state_t::operator|(const stack_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    stack_slot_dists_t out_stack_dists;
    for (auto const&kv: m_slot_dists) {
        auto it = other.m_slot_dists.find(kv.first);
        if (it != m_slot_dists.end() && kv.second == it->second)
            out_stack_dists.insert(kv);
    }
    return stack_state_t(std::move(out_stack_dists), false);
}

bool extra_constraints_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_meta_and_begin.is_top() && m_begin_and_end.is_top());
}

bool extra_constraints_t::is_bottom() const {
    return m_is_bottom;
}

void extra_constraints_t::set_to_top() {
    m_meta_and_begin.set_to_top();
    m_begin_and_end.set_to_top();
    m_is_bottom = false;
}

void extra_constraints_t::set_to_bottom() {
    m_is_bottom = true;
}

void extra_constraints_t::add_meta_and_begin_constraint(forward_and_backward_eq_t&& eq,
        inequality_t&& ineq) {
    m_meta_and_begin = packet_constraint_t(std::move(eq), std::move(ineq), false);
}

void extra_constraints_t::add_begin_and_end_constraint(forward_and_backward_eq_t&& eq,
        inequality_t&& ineq) {
    m_begin_and_end = packet_constraint_t(std::move(eq), std::move(ineq), false);
}
/*
void extra_constraints_t::normalize() {
    weight_t dist_forw = m_eq.m_forw.m_dist - m_eq.m_backw.m_dist - 4099;
    weight_t dist_backw = -4099;
    slack_var_t s = m_eq.m_forw.m_slack;
    dist_forw += m_ineq.m_value;
    weight_t ineq_val = 0;
    rop_t ineq_rel = m_ineq.m_rel;

    m_eq = forward_and_backward_eq_t(dist_t(dist_forw, s), dist_t(dist_backw));
    m_ineq = inequality_t(s, ineq_rel, ineq_val);
}
*/

packet_constraint_t packet_constraint_t::operator|(const packet_constraint_t& other) const {
    //normalize();
    //other.normalize();

    weight_t dist1 = m_eq.m_forw.m_dist;
    weight_t dist2 = other.m_eq.m_forw.m_dist;
    slack_var_t s = m_eq.m_forw.m_slack;

    dist_t f = dist_t(dist1 | dist2, s);
    dist_t b = dist_t(weight_t(number_t(-4099)));

    forward_and_backward_eq_t out_eq(f, b);
    inequality_t out_ineq(s, m_ineq.m_rel, weight_t(number_t(0)));

    return packet_constraint_t(std::move(out_eq), std::move(out_ineq), false);
        // have to handle case for different slack vars
}

void packet_constraint_t::set_to_top() {
    m_eq.set_to_top();
    m_ineq.set_to_top();
    m_is_bottom = false;
}

void packet_constraint_t::set_to_bottom() {
    m_is_bottom = true;
}

bool packet_constraint_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_eq.is_top() && m_ineq.is_top());
}

bool packet_constraint_t::is_bottom() const {
    return m_is_bottom;
}

std::optional<bound_t> packet_constraint_t::get_limit() const {
    // TODO: normalize constraint, if required
    auto number_opt = m_eq.m_forw.m_dist.singleton();
    if (number_opt) return bound_t(number_opt.value());
    return {};
}

extra_constraints_t extra_constraints_t::operator|(const extra_constraints_t& other) const {
    auto meta_and_begin = m_meta_and_begin | other.m_meta_and_begin;
    auto begin_and_end = m_begin_and_end | other.m_begin_and_end;
    return extra_constraints_t(std::move(meta_and_begin), std::move(begin_and_end), false);
}

std::optional<bound_t> extra_constraints_t::get_end_limit() const {
    return m_begin_and_end.get_limit();
}

std::optional<bound_t> extra_constraints_t::get_meta_limit() const {
    return m_meta_and_begin.get_limit();
}

ctx_t::ctx_t(const ebpf_context_descriptor_t* desc) {
    if (desc->data != -1) {
        m_dists[desc->data] = dist_t(weight_t(number_t(0)));
    }
    if (desc->end != -1) {
        m_dists[desc->end] = dist_t(weight_t(number_t(-4099)));
    }
    if (desc->meta != -1) {
        m_dists[desc->meta] = dist_t(weight_t(number_t(-1)));
    }
    m_size = desc->size;
}

int ctx_t::get_size() const {
    return m_size;
}

std::optional<dist_t> ctx_t::find(int key) const {
    auto it = m_dists.find(key);
    if (it == m_dists.end()) return {};
    return it->second;
}

offset_domain_t offset_domain_t::setup_entry() {
    std::shared_ptr<ctx_t> ctx = std::make_shared<ctx_t>(global_program_info.type.context_descriptor);
    std::shared_ptr<global_offset_env_t> all_types = std::make_shared<global_offset_env_t>();
    registers_state_t regs(all_types);

    offset_domain_t off_d(std::move(regs), stack_state_t::top(), ctx);
    return off_d;
}

offset_domain_t offset_domain_t::bottom() {
    offset_domain_t off;
    off.set_to_bottom();
    return off;
}

void offset_domain_t::set_to_top() {
    m_reg_state.set_to_top();
    m_stack_state.set_to_top();
    m_extra_constraints.set_to_top();
}

void offset_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

bool offset_domain_t::is_bottom() const {
    return m_is_bottom;
}

bool offset_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_reg_state.is_top() && m_stack_state.is_top() && m_extra_constraints.is_top());
}

// inclusion
bool offset_domain_t::operator<=(const offset_domain_t& other) const { return true; }

// join
void offset_domain_t::operator|=(const offset_domain_t& abs) {
    offset_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void offset_domain_t::operator|=(offset_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

offset_domain_t offset_domain_t::operator|(const offset_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return offset_domain_t(m_reg_state | other.m_reg_state, m_stack_state | other.m_stack_state, m_extra_constraints | other.m_extra_constraints, m_ctx_dists, std::max(m_slack, other.m_slack));
}

offset_domain_t offset_domain_t::operator|(offset_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return offset_domain_t(m_reg_state | std::move(other.m_reg_state),
            m_stack_state | std::move(other.m_stack_state),
            m_extra_constraints | std::move(other.m_extra_constraints),
            m_ctx_dists, std::max(m_slack, other.m_slack));
}

// meet
offset_domain_t offset_domain_t::operator&(const offset_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

// widening
offset_domain_t offset_domain_t::widen(const offset_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

// narrowing
offset_domain_t offset_domain_t::narrow(const offset_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

//forget
void offset_domain_t::operator-=(variable_t var) {}

void offset_domain_t::write(std::ostream& os) const {}

std::string offset_domain_t::domain_name() const {
    return "offset_domain";
}

int offset_domain_t::get_instruction_count_upper_bound() {
    /* WARNING: The operation is not implemented yet.*/
    return 0;
}

string_invariant offset_domain_t::to_set() { return string_invariant{}; }

void offset_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    m_reg_state -= u.dst.v;
}

void offset_domain_t::operator()(const Packet &u, location_t loc, int print) {
    register_t r0_reg{R0_RETURN_VALUE};
    m_reg_state -= r0_reg;
}

void offset_domain_t::operator()(const Call &u, location_t loc, int print) {
    register_t r0_reg{R0_RETURN_VALUE};
    m_reg_state -= r0_reg;
}

void offset_domain_t::operator()(const Assume &b, location_t loc, int print) {
    Condition cond = b.cond;
    if (cond.op == Condition::Op::LE) {
        if (std::holds_alternative<Reg>(cond.right)) {
            auto right_reg = std::get<Reg>(cond.right).v;
            auto dist_left = m_reg_state.find(cond.left.v);
            auto dist_right = m_reg_state.find(right_reg);
            if (!dist_left && !dist_right) {
                return;
            }
            else if (!dist_left || !dist_right) {
                // this should not happen, comparison between a packet pointer and either
                // other region's pointers or numbers; possibly raise type error
                //exit(1);
                std::cout << "type_error: one of the pointers being compared isn't packet pointer\n";
                return;
            }
            dist_t left_reg_dist = dist_left.value();
            dist_t right_reg_dist = dist_right.value();
            slack_var_t s = m_slack++;
            dist_t f = dist_t(left_reg_dist.m_dist, s);
            dist_t b = dist_t(right_reg_dist.m_dist, slack_var_t{-1});
            auto eq = forward_and_backward_eq_t(f, b);
            auto ineq = inequality_t(s, rop_t::R_GE, weight_t(number_t(0)));
            if (f.is_meta_pointer() && b.is_forward_pointer()) {
                m_extra_constraints.add_meta_and_begin_constraint(std::move(eq), std::move(ineq));
            }
            else if (f.is_forward_pointer() && b.is_backward_pointer()) {
                m_extra_constraints.add_begin_and_end_constraint(std::move(eq), std::move(ineq));
            }
        }
    }
    else {}     //we do not need to deal with other cases
}

bool is_packet_pointer(std::optional<ptr_or_mapfd_t>& type) {
    if (!type) {    // not a pointer
        return false;
    }
    auto ptr_or_mapfd_type = type.value();
    if (std::holds_alternative<ptr_no_off_t>(ptr_or_mapfd_type)
        && std::get<ptr_no_off_t>(ptr_or_mapfd_type).get_region() == crab::region_t::T_PACKET) {
        return true;
    }
    return false;
}

bool is_stack_pointer(std::optional<ptr_or_mapfd_t>& type) {
    if (!type) {    // not a pointer
        return false;
    }
    auto ptr_or_mapfd_type = type.value();
    if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd_type)
        && std::get<ptr_with_off_t>(ptr_or_mapfd_type).get_region() == crab::region_t::T_STACK) {
        return true;
    }
    return false;
}

void offset_domain_t::do_bin(const Bin &bin, std::optional<interval_t> src_const_value,
        std::optional<ptr_or_mapfd_t> src_type, std::optional<ptr_or_mapfd_t> dst_type,
        location_t loc) {
    if (is_bottom()) return;

    auto reg_with_loc = reg_with_loc_t(bin.dst.v, loc);
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        switch (bin.op)
        {
            // ra = rb;
            case Bin::Op::MOV: {
                if (!is_packet_pointer(src_type)) {
                    m_reg_state -= bin.dst.v;
                    return;
                }
                auto it = m_reg_state.find(src.v);
                if (!it) {
                    std::cout << "type_error: src is a packet_pointer and no offset info found\n";
                    //exit(1);
                    return;
                }
                m_reg_state.insert(bin.dst.v, reg_with_loc, it.value());
                //std::cout << "offset: " << (*m_reg_state.get(bin.dst.v)).m_dist << "\n";
                break;
            }
            // ra += rb
            case Bin::Op::ADD: {
                if (!is_packet_pointer(dst_type)) {
                    m_reg_state -= bin.dst.v;
                    return;
                }
                auto it = m_reg_state.find(bin.dst.v);
                if (!it) {
                    std::cout << "type_error: dst is a packet_pointer and no offset info found\n";
                    //exit(1);
                    return;
                }
                auto dst_dist = it.value();
                if (src_const_value) {
                    weight_t updated_dist;
                    if (dst_dist.m_dist.lb() >= number_t(0)) {
                        updated_dist = dst_dist.m_dist + src_const_value.value();
                    }
                    else if (dst_dist.m_dist.lb() >= number_t(-4098)) {
                        // TODO: special handling of meta pointer required
                        updated_dist = dst_dist.m_dist - src_const_value.value();
                    }
                    else {
                        updated_dist = dst_dist.m_dist - src_const_value.value();
                    }
                    m_reg_state.insert(bin.dst.v, reg_with_loc, dist_t(updated_dist));
                }
                else {
                    m_reg_state -= bin.dst.v;
                }
                break;
            }

            default: {
                m_reg_state -= bin.dst.v;
                break;
            }
        }
    }
    else {
        int imm = static_cast<int>(std::get<Imm>(bin.v).v);
        auto it = m_reg_state.find(bin.dst.v);
        switch (bin.op)
        {
            case Bin::Op::ADD: {
                if (!is_packet_pointer(dst_type)) {
                    m_reg_state -= bin.dst.v;
                    return;
                }
                if (!it) {
                    std::cout << "type_error: dst is a packet_pointer and no offset info found\n";
                    //exit(1);
                    return;
                }
                auto dst_dist = it.value();

                weight_t updated_dist;
                if (dst_dist.m_dist.lb() >= number_t(0)) {
                    updated_dist = dst_dist.m_dist + number_t(imm);
                }
                else if (dst_dist.m_dist.lb() >= number_t(-4098)) {
                    // TODO: special handling of meta pointer required
                    updated_dist = dst_dist.m_dist - number_t(imm);
                }
                else {
                    updated_dist = dst_dist.m_dist - number_t(imm);
                }
                m_reg_state.insert(bin.dst.v, reg_with_loc, dist_t(updated_dist));
                break;
            }

            default: {
                m_reg_state -= bin.dst.v;
                break;
            }
        }
    }
}

bool offset_domain_t::check_packet_access(const Reg& r, int width) const {
    auto it = m_reg_state.find(r.v);
    auto end_limit = m_extra_constraints.get_end_limit();
    auto meta_limit = m_extra_constraints.get_meta_limit();
    if (it && meta_limit && end_limit) {
        dist_t dist = it.value();
        // TODO: handle meta and end pointers separately
        if (dist.m_dist.lb() >= meta_limit.value()
                && dist.m_dist.lb()+number_t(width) <= end_limit.value()) return true;
    }
    return false;
}

void offset_domain_t::check_valid_access(const ValidAccess& s,
        std::optional<ptr_or_mapfd_t>& reg_type) const {
    if (std::holds_alternative<Imm>(s.width)) {
        int w = std::get<Imm>(s.width).v;
        if (w == 0 || !reg_type) return;

        //m_extra_constraints.normalize();
        auto reg_ptr_or_mapfd_type = reg_type.value();
        if (std::holds_alternative<ptr_with_off_t>(reg_ptr_or_mapfd_type)) {
            auto reg_with_off_ptr_type = std::get<ptr_with_off_t>(reg_ptr_or_mapfd_type);
            int offset = reg_with_off_ptr_type.get_offset();
            int offset_to_check = offset+s.offset;
            if (reg_with_off_ptr_type.get_region() == crab::region_t::T_STACK) {
                if (offset_to_check >= STACK_BEGIN && offset_to_check+w <= EBPF_STACK_SIZE) return;
            }
            else {
                if (offset_to_check >= CTX_BEGIN && offset_to_check+w <= m_ctx_dists->get_size())
                    return;
            }
        }
        else if (std::holds_alternative<ptr_no_off_t>(reg_ptr_or_mapfd_type)) {
            auto reg_no_off_ptr_type = std::get<ptr_no_off_t>(reg_ptr_or_mapfd_type);
            if (reg_no_off_ptr_type.get_region() == crab::region_t::T_PACKET) {
                if (check_packet_access(s.reg, w)) return;
            }
            else {
                return;
            }
        }
        else {}
    }
    else {
        return;
    }
    std::cout << "valid access assert fail\n";
    //exit(1);
}

void offset_domain_t::do_mem_store(const Mem& b, const Reg& target_reg,
        std::optional<ptr_or_mapfd_t>& basereg_type,
        std::optional<ptr_or_mapfd_t>& targetreg_type) {
    int offset = b.access.offset;

    if (is_stack_pointer(basereg_type)) {
        auto basereg_with_off = std::get<ptr_with_off_t>(basereg_type.value());
        int store_at = basereg_with_off.get_offset() + offset;
        if (is_packet_pointer(targetreg_type)) {
            auto it = m_reg_state.find(target_reg.v);
            if (!it) {
                std::cout << "type_error: register is a packet_pointer and no offset info found\n";
                return;
            }
            m_stack_state.store(store_at, it.value());
        }
        else {
            m_stack_state -= store_at;
        }
    }
    else {}  // in the rest cases, we do not store
}

void offset_domain_t::do_load(const Mem& b, const Reg& target_reg,
        std::optional<ptr_or_mapfd_t>& basereg_type, location_t loc) {
    if (!basereg_type) {
        m_reg_state -= target_reg.v;
        return;
    }
    auto basereg_ptr_type = basereg_type.value();
    int offset = b.access.offset;
    
    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_type)) {
        auto p_with_off = std::get<ptr_with_off_t>(basereg_ptr_type);
        int to_load = p_with_off.get_offset() + offset;

        if (p_with_off.get_region() == crab::region_t::T_CTX) {
            auto it = m_ctx_dists->find(to_load);
            if (!it) {
                m_reg_state -= target_reg.v;
                return;
            }
            dist_t d = it.value();
            auto reg = reg_with_loc_t(target_reg.v, loc);
            m_reg_state.insert(target_reg.v, reg, dist_t(d));
        }
        else if (p_with_off.get_region() == crab::region_t::T_STACK) {
            auto it = m_stack_state.find(to_load);

            if (!it) {
                m_reg_state -= target_reg.v;
                return;
            }
            dist_t d = it.value();
            auto reg = reg_with_loc_t(target_reg.v, loc);
            m_reg_state.insert(target_reg.v, reg, dist_t(d));
        }
    }
    else {  // we are loading from packet or shared, or we have mapfd
        m_reg_state -= target_reg.v;
    }
}

std::optional<dist_t> offset_domain_t::find_offset_at_loc(const reg_with_loc_t reg) const {
    return m_reg_state.find(reg);
}

std::optional<dist_t> offset_domain_t::find_in_ctx(int key) const {
    return m_ctx_dists->find(key);
}

std::optional<dist_t> offset_domain_t::find_in_stack(int key) const {
    return m_stack_state.find(key);
}

std::optional<dist_t> offset_domain_t::find_offset_info(register_t reg) const {
    return m_reg_state.find(reg);
}

void offset_domain_t::adjust_bb_for_types(location_t loc) {
    m_reg_state.adjust_bb_for_registers(loc);
}

void offset_domain_t::print_all_register_types() const {
    m_reg_state.print_all_register_types();
}
