// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/constant_prop_domain.hpp"

bool registers_cp_state_t::is_bottom() const {
    return m_is_bottom;
}

bool registers_cp_state_t::is_top() const {
    if (m_is_bottom) return false;
    for (auto it : m_const_values) {
        if (it != nullptr) return false;
    }
    return true;
}

void registers_cp_state_t::set_to_top() {
    m_const_values = const_values_registers_t{nullptr};
    m_is_bottom = false;
}

void registers_cp_state_t::set_to_bottom() {
    m_is_bottom = true;
}

std::shared_ptr<int> registers_cp_state_t::get(register_t reg) const {
    return m_const_values[reg];
}

void registers_cp_state_t::set(register_t reg, std::shared_ptr<int> cv) {
    m_const_values[reg] = cv;
}

void registers_cp_state_t::operator-=(register_t to_forget) {
    set(to_forget, nullptr);
}

registers_cp_state_t registers_cp_state_t::operator|(const registers_cp_state_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    const_values_registers_t const_values_joined;
    for (size_t i = 0; i < m_const_values.size(); i++) {
        if (m_const_values[i] == other.m_const_values[i]) {
            const_values_joined[i] = m_const_values[i];
        }
    }
    return registers_cp_state_t(std::move(const_values_joined));
}

void registers_cp_state_t::print_all_consts() {
    std::cout << "\nprinting all constant values: \n";
    for (size_t i = 0; i < m_const_values.size(); i++) {
        if (m_const_values[i]) {
            std::cout << "r" << i << " = " << *m_const_values[i] << "\n";
        }
    }
    std::cout << "==============================\n\n";
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
    return abs;
}

constant_prop_domain_t constant_prop_domain_t::widen(const constant_prop_domain_t& abs) const {
    return abs;
}

constant_prop_domain_t constant_prop_domain_t::narrow(const constant_prop_domain_t& other) const {
    return other;
}

void constant_prop_domain_t::write(std::ostream& os) const {}

std::string constant_prop_domain_t::domain_name() const {
    return "constant_prop_domain";
}

int constant_prop_domain_t::get_instruction_count_upper_bound() {
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
    constant_prop_domain_t typ;
    return typ;
}

void constant_prop_domain_t::do_bin(const Bin& bin) {
    auto dstV = m_registers_const_values.get(bin.dst.v);
    std::shared_ptr<int> updatedDstV = nullptr;

    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        auto srcV = m_registers_const_values.get(src.v);

        if (!srcV) {
            m_registers_const_values -= bin.dst.v;
            return;
        }

        switch (bin.op)
        {
            // ra = rb;
            case Bin::Op::MOV: {
                updatedDstV = srcV;
                break;
            }
            // ra += rb
            case Bin::Op::ADD: {
                // both ra and rb are numbers, so handle here
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) + (*srcV));
                }
                break;
            }
            // ra -= rb
            case Bin::Op::SUB: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) - (*srcV));
                }
                break;
            }
            // ra *= rb
            case Bin::Op::MUL: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) * (*srcV));
                }
                break;
            }
            // ra /= rb
            case Bin::Op::DIV: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) / (*srcV));
                }
                break;
            }
            // ra %= rb
            case Bin::Op::MOD: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) % (*srcV));
                }
                break;
            }
            // ra |= rb
            case Bin::Op::OR: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) | (*srcV));
                }
                break;
            }
            // ra &= rb
            case Bin::Op::AND: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) & (*srcV));
                }
                break;
            }
            // ra <<= rb
            case Bin::Op::LSH: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) << (*srcV));
                }
                break;
            }
            // ra >>= rb
            case Bin::Op::RSH: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) >> (*srcV));
                }
                break;
            }
            // ra >>>= rb
            case Bin::Op::ARSH: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((int64_t)(*dstV) >> (*srcV));
                }
                break;
            }
            // ra ^= rb
            case Bin::Op::XOR: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) ^ (*srcV));
                }
                break;
            }
        }
        //std::cout << "value of vb: " << *srcV << "\n";
    }
    else {
        int imm = static_cast<int>(std::get<Imm>(bin.v).v);
        switch (bin.op)
        {
            // ra = c, where c is a constant
            case Bin::Op::MOV: {
                updatedDstV = std::make_shared<int>(imm);
                break;
            }
            // ra += c, where c is a constant
            case Bin::Op::ADD: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) + imm);
                }
                break;
            }
            // ra -= c
            case Bin::Op::SUB: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) - imm);
                }
                break;
            }
            // ra *= c
            case Bin::Op::MUL: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) * imm);
                }
                break;
            }
            // ra /= c
            case Bin::Op::DIV: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) / imm);
                }
                break;
            }
            // ra %= c
            case Bin::Op::MOD: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) % imm);
                }
                break;
            }
            // ra |= c
            case Bin::Op::OR: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) | imm);
                }
                break;
            }
            // ra &= c
            case Bin::Op::AND: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) & imm);
                }
                break;
            }
            // ra <<= c
            case Bin::Op::LSH: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) << imm);
                }
                break;
            }
            // ra >>= c
            case Bin::Op::RSH: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) >> imm);
                }
                break;
            }
            // ra >>>= c
            case Bin::Op::ARSH: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((int64_t)(*dstV) >> imm);
                }
                break;
            }
            // ra ^= c
            case Bin::Op::XOR: {
                if (dstV) {
                    updatedDstV = std::make_shared<int>((*dstV) ^ imm);
                }
                break;
            }
         }
    }
    m_registers_const_values.set(bin.dst.v, updatedDstV);
    //if (updatedDstV)
    //    std::cout << "new value of va: " << *updatedDstV << "\n";
}

void constant_prop_domain_t::operator()(const Bin& bin, location_t loc, int print) {
    if (is_bottom()) return;
    do_bin(bin);
}

void constant_prop_domain_t::do_load(const Mem& b, const Reg& target_reg, std::optional<ptr_t> basereg_type) {
    if (!basereg_type) {
        m_registers_const_values -= target_reg.v;
        return;
    }

    ptr_t basereg_ptr_type = basereg_type.value();
    int offset = b.access.offset;

    if (std::holds_alternative<ptr_with_off_t>(basereg_ptr_type)) {
        auto p_with_off = std::get<ptr_with_off_t>(basereg_ptr_type);
        int to_load = p_with_off.get_offset() + offset;

        if (p_with_off.get_region() == crab::region::T_STACK) {
            auto it = m_stack_slots_const_values.find(to_load);
            if (!it) {
                m_registers_const_values -= target_reg.v;
                return;
            }
            m_registers_const_values.set(target_reg.v, std::make_shared<int>(it.value()));
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
            auto it = m_registers_const_values.get(target_reg.v);
            if (it) {
                m_stack_slots_const_values.store(store_at, *it);
            }
        }
    }
    else {}
}

void constant_prop_domain_t::operator()(const Mem& b, location_t loc, int print) {
    if (is_bottom()) return;

    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), {});
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
