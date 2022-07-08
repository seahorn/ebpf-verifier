#include "crab/offset_domain.hpp"

//ctx_offsets_t::ctx_offsets_t(const ebpf_context_descriptor_t* desc) {
//    if (desc->data != -1)
//        m_offsets[desc->data] = node_t(0);
//    if (desc->end != -1)
//        m_offsets[desc->end] = node_t(1);
//    //if (desc->meta != -1)
//        //m_offsets[desc->meta] = node_t();
//}

offset_domain_t offset_domain_t::setup_entry() {
    //std::shared_ptr<ctx_offsets_t> ctx = std::make_shared<ctx_offsets_t>(global_program_info.type.context_descriptor);
    //m_offset_graph_t graph(global_program_info.type.context_descriptor);

    //offset_domain_t off_d(ctx, graph);
    offset_domain_t off_d;
    return off_d;
}

offset_domain_t offset_domain_t::bottom() { offset_domain_t t; return t; }
void offset_domain_t::set_to_top() {}
void offset_domain_t::set_to_bottom() {}
bool offset_domain_t::is_bottom() const { return m_is_bottom; }
bool offset_domain_t::is_top() const { return false; }
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
std::string offset_domain_t::domain_name() const { return "offset_domain"; }
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
