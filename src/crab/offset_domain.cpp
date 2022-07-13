// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "crab/offset_domain.hpp"

#define min(a, b) (a < b ? a : b)

bool dist_t::operator==(const dist_t& d) const {
    return (m_dist == d.m_dist && m_slack == d.m_slack);
}

void registers_state_t::set_to_top() {
    m_reg_dists = register_dists_t{nullptr};
    m_is_bottom = false;
}

void registers_state_t::set_to_bottom() {
    m_reg_dists = register_dists_t{nullptr};
    m_is_bottom = true;
}

bool registers_state_t::is_top() const {
    if (m_is_bottom) return false;
    for (auto &it : m_reg_dists) {
        if (it != nullptr) return false;
    }
    return true;
}

bool registers_state_t::is_bottom() const {
    return m_is_bottom;
}

registers_state_t registers_state_t::operator|(const registers_state_t& other) const {
    std::cout << "registers join\n";
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    register_dists_t out_reg_dists;
    for (size_t i = 0; i < m_reg_dists.size(); i++) {
        if (m_reg_dists[i] == other.m_reg_dists[i]) {
            out_reg_dists[i] = m_reg_dists[i];
        }
    }
    return registers_state_t(std::move(out_reg_dists), false);
}

void stack_state_t::set_to_top() {
    m_stack_slot_dists.clear();
    m_is_bottom = false;
}

void stack_state_t::set_to_bottom() {
    m_stack_slot_dists.clear();
    m_is_bottom = true;
}

bool stack_state_t::is_top() const {
    if (m_is_bottom) return false;
    return m_stack_slot_dists.empty();
}

bool stack_state_t::is_bottom() const {
    return m_is_bottom;
}

stack_state_t stack_state_t::operator|(const stack_state_t& other) const {
    std::cout << "stack join\n";
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    stack_slot_dists_t out_stack_dists;
    for (auto const&kv: m_stack_slot_dists) {
        auto it = other.m_stack_slot_dists.find(kv.first);
        if (it != m_stack_slot_dists.end() && kv.second == it->second)
            out_stack_dists.insert(kv);
    }
    return stack_state_t(std::move(out_stack_dists), false);
}

void extra_constraints_t::set_to_top() {
    m_eq = forward_and_backward_eq_t();
    m_ineq = inequality_t();
}

void extra_constraints_t::set_to_bottom() {
    m_is_bottom = true;
}

bool extra_constraints_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_eq.m_forw.m_slack == boost::none && m_ineq.m_slack == boost::none);
}

bool extra_constraints_t::is_bottom() const {
    return m_is_bottom;
}

extra_constraints_t extra_constraints_t::operator|(const extra_constraints_t& other) const {
    std::cout << "extra constraints join\n";
    weight_t dist1 = m_eq.m_forw.m_dist - m_eq.m_backw.m_dist - 1;
    std::cout << "after first dist calc\n";
    weight_t dist2 = other.m_eq.m_forw.m_dist - other.m_eq.m_backw.m_dist - 1;
    std::cout << "weights calculation\n";

    dist1 += m_ineq.m_value;
    dist2 += other.m_ineq.m_value;
    std::cout << "weights calculation 2\n";

//    if (m_eq.m_forw.m_slack != boost::none && other.m_eq.m_forw.m_slack != boost::none) {
        slack_var_t s = m_eq.m_forw.m_slack;

        dist_t f = dist_t(min(dist1, dist2), s);
        dist_t b = dist_t(-1);
    std::cout << "calculated dists\n";

        forward_and_backward_eq_t out_eq(f, b);
    std::cout << "calculated fw and bw eq\n";
        inequality_t out_ineq(s, m_ineq.m_rel, 0);

        std::cout << "done with extra constraints\n";
        return extra_constraints_t(std::move(out_eq), std::move(out_ineq), false);
        // have to handle case for different slack vars
//    }
}

ctx_t::ctx_t(const ebpf_context_descriptor_t* desc) {
    if (desc->data != -1)
        m_dists[desc->data] = dist_t(0);
    if (desc->end != -1)
        m_dists[desc->end] = dist_t(-1);
    //if (desc->meta != -1)
        //m_offsets[desc->meta] = node_t();
}

offset_domain_t offset_domain_t::setup_entry() {
    std::shared_ptr<ctx_t> ctx = std::make_shared<ctx_t>(global_program_info.type.context_descriptor);

    offset_domain_t off_d(ctx);
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
    std::cout << "joining in offset_domain 1\n";
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    std::cout << "trivial checks done\n";
    return offset_domain_t(m_reg_state | other.m_reg_state, m_stack_state | other.m_stack_state, m_extra_constraints | other.m_extra_constraints, m_ctx_dists);
}

offset_domain_t offset_domain_t::operator|(offset_domain_t&& other) const {
    std::cout << "joining in offset_domain 2\n";
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return offset_domain_t(m_reg_state | std::move(other.m_reg_state), m_stack_state | std::move(other.m_stack_state), m_extra_constraints | std::move(other.m_extra_constraints), m_ctx_dists);
}

// meet
offset_domain_t offset_domain_t::operator&(const offset_domain_t& other) const { return other; }

// widening
offset_domain_t offset_domain_t::widen(const offset_domain_t& other) const { return other; }

// narrowing
offset_domain_t offset_domain_t::narrow(const offset_domain_t& other) const { return other; }

//forget
void offset_domain_t::operator-=(variable_t var) {}

void offset_domain_t::write(std::ostream& os) const {}

std::string offset_domain_t::domain_name() const {
    return "offset_domain";
}

int offset_domain_t::get_instruction_count_upper_bound() { return 0; }

string_invariant offset_domain_t::to_set() { return string_invariant{}; }

void offset_domain_t::set_require_check(check_require_func_t f) {}

void offset_domain_t::operator()(const Assume &b, location_t loc, int print) {
}

void offset_domain_t::operator()(const Bin &bin, location_t loc, int print) {
    if (is_bottom()) return;
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        switch (bin.op)
        {
            case Bin::Op::MOV: {
                // not necessary to check for nullptr, as it src reg is nullptr, the same will be copied to dst reg
                if (m_reg_state.m_reg_dists[src.v] != nullptr) {
                    m_reg_state.m_reg_dists[bin.dst.v] = m_reg_state.m_reg_dists[src.v];
                    std::cout << "after move, the distance is: " << m_reg_state.m_reg_dists[bin.dst.v]->m_dist << ", and slack var: " << m_reg_state.m_reg_dists[bin.dst.v]->m_slack << "\n";
                }
                else {
                    m_reg_state.m_reg_dists[bin.dst.v] = nullptr;
                }
                break;
            }

            default: {
                m_reg_state.m_reg_dists[bin.dst.v] = nullptr;
                break;
            }
        }
    }
    else {
        int imm = static_cast<int>(std::get<Imm>(bin.v).v);
        auto dst_reg_dist = m_reg_state.m_reg_dists[bin.dst.v];
        switch (bin.op)
        {
            case Bin::Op::ADD: {
                if (dst_reg_dist == nullptr) {
                    m_reg_state.m_reg_dists[bin.dst.v] = nullptr;
                    return;
                }
                int updated_dist = dst_reg_dist->m_dist+imm;
                m_reg_state.m_reg_dists[bin.dst.v] = std::make_shared<dist_t>(updated_dist, boost::none);
                std::cout << "after adding to pointer, the distance is: " << m_reg_state.m_reg_dists[bin.dst.v]->m_dist << ", and slack var: " << m_reg_state.m_reg_dists[bin.dst.v]->m_slack << "\n";
                break;
            }

            default: {
                m_reg_state.m_reg_dists[bin.dst.v] = nullptr;
                break;
            }
        }
    }
}

void offset_domain_t::operator()(const Undefined &, location_t loc, int print) {}

void offset_domain_t::operator()(const Un &, location_t loc, int print) {}

void offset_domain_t::operator()(const LoadMapFd &, location_t loc, int print) {}

void offset_domain_t::operator()(const Call &, location_t loc, int print) {}

void offset_domain_t::operator()(const Exit &, location_t loc, int print) {}

void offset_domain_t::operator()(const Jmp &, location_t loc, int print) {}

void offset_domain_t::operator()(const Packet &, location_t loc, int print) {}

void offset_domain_t::operator()(const LockAdd &, location_t loc, int print) {}

void offset_domain_t::operator()(const Assert &, location_t loc, int print) {}

void offset_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    for (const Instruction& statement : bb) {
        location_t loc = boost::none;
        std::visit([this, loc, print](const auto& v) { std::apply(*this, std::make_tuple(v, loc, print)); }, statement);
    }
}

void offset_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, ptr_t& basereg_type) {
    std::cout << "baseptr type is: ";
    if (std::holds_alternative<ptr_with_off_t>(basereg_type)) {
        auto t = std::get<ptr_with_off_t>(basereg_type);
        std::cout << t;
    }
    else {
        auto t = std::get<ptr_no_off_t>(basereg_type);
        std::cout << t;
    }
    std::cout << "\n";
    int offset = b.access.offset;
    if (std::holds_alternative<ptr_with_off_t>(basereg_type)) {
        auto basereg_with_off = std::get<ptr_with_off_t>(basereg_type);
        int store_at = basereg_with_off.get_offset() + offset;
        m_stack_state.m_stack_slot_dists[store_at] = *m_reg_state.m_reg_dists[target_reg.v];
    }
}

void offset_domain_t::do_load(const Mem& b, const Reg& target_reg, ptr_t& p) {
    std::cout << "ptr type is: ";
    if (std::holds_alternative<ptr_with_off_t>(p)) {
        auto t = std::get<ptr_with_off_t>(p);
        std::cout << t;
    }
    else {
        auto t = std::get<ptr_no_off_t>(p);
        std::cout << t;
    }
    std::cout << "\n";
    
    int offset = b.access.offset;
    
    if (std::holds_alternative<ptr_with_off_t>(p)) {
        auto p_with_off = std::get<ptr_with_off_t>(p);
        int to_load = p_with_off.get_offset() + offset;
        dist_t d;
        if (p_with_off.get_region() == crab::region::T_CTX) {
            auto it = m_ctx_dists->m_dists.find(to_load);
            if (it != m_ctx_dists->m_dists.end()) {
                d = it->second;
                m_reg_state.m_reg_dists[target_reg.v] = std::make_shared<dist_t>(d);
        std::cout << "after load, the distance is: " << m_reg_state.m_reg_dists[target_reg.v]->m_dist << ", and slack var: " << m_reg_state.m_reg_dists[target_reg.v]->m_slack << "\n";
            }
            else {
                m_reg_state.m_reg_dists[target_reg.v] = nullptr;
            }
        }
        else if (p_with_off.get_region() == crab::region::T_STACK) {
            auto it = m_stack_state.m_stack_slot_dists.find(to_load);
            if (it != m_stack_state.m_stack_slot_dists.end()) {
                d = it->second;
                m_reg_state.m_reg_dists[target_reg.v] = std::make_shared<dist_t>(d);
        std::cout << "after load, the distance is: " << m_reg_state.m_reg_dists[target_reg.v]->m_dist << ", and slack var: " << m_reg_state.m_reg_dists[target_reg.v]->m_slack << "\n";
            }
            else {
                m_reg_state.m_reg_dists[target_reg.v] = nullptr;
            }
        }
    }
    else {
        std::cout << "we are loading from packet/shared, which should give numbers\n";
    }
}

void offset_domain_t::operator()(const Mem &b, location_t loc, int print) {
}
