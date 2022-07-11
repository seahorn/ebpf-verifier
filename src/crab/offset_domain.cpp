#include "crab/offset_domain.hpp"

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
    m_extra_constraints->set_to_top();
}

void offset_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

bool offset_domain_t::is_bottom() const {
    return m_is_bottom;
}

bool offset_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_reg_state.is_top() && m_stack_state.is_top() && m_extra_constraints->is_top());
}

// inclusion
bool offset_domain_t::operator<=(const offset_domain_t& other) const { return true; }

// join
void offset_domain_t::operator|=(const offset_domain_t& abs) {}

void offset_domain_t::operator|=(offset_domain_t&& abs) {}

offset_domain_t offset_domain_t::operator|(const offset_domain_t& other) const { return other; }

offset_domain_t offset_domain_t::operator|(offset_domain_t&& abs) const { return abs; }

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

void offset_domain_t::operator()(const Assume &, location_t loc, int print) {}

void offset_domain_t::operator()(const Bin &, location_t loc, int print) {}

void offset_domain_t::operator()(const Undefined &, location_t loc, int print) {}

void offset_domain_t::operator()(const Un &, location_t loc, int print) {}

void offset_domain_t::operator()(const LoadMapFd &, location_t loc, int print) {}

void offset_domain_t::operator()(const Call &, location_t loc, int print) {}

void offset_domain_t::operator()(const Exit &, location_t loc, int print) {}

void offset_domain_t::operator()(const Jmp &, location_t loc, int print) {}

void offset_domain_t::operator()(const Packet &, location_t loc, int print) {}

void offset_domain_t::operator()(const LockAdd &, location_t loc, int print) {}

void offset_domain_t::operator()(const Assert &, location_t loc, int print) {}

void offset_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {}

void offset_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t, int print) {}

void offset_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc, int print) {
    int offset = b.access.offset;
    Reg basereg = b.access.basereg;
}

void offset_domain_t::operator()(const Mem &b, location_t loc, int print) {
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), loc, print);
        } else {
            do_mem_store(b, std::get<Reg>(b.value), loc, print);
        }
    }
}
