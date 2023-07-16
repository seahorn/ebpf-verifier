// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "crab/region_domain.hpp"

namespace crab {

ctx_t::ctx_t(const ebpf_context_descriptor_t* desc)
{
    if (desc->data >= 0) {
        m_packet_ptrs[desc->data] = crab::ptr_no_off_t(crab::region_t::T_PACKET);
    }
    if (desc->end >= 0) {
        m_packet_ptrs[desc->end] = crab::ptr_no_off_t(crab::region_t::T_PACKET);
    }
    if (desc->meta >= 0) {
        m_packet_ptrs[desc->meta] = crab::ptr_no_off_t(crab::region_t::T_PACKET);
    }
    if (desc->size >= 0) {
        size = desc->size;
    }
}

std::vector<uint64_t> ctx_t::get_keys() const {
    std::vector<uint64_t> keys;
    keys.reserve(size);

    for (auto const&kv : m_packet_ptrs) {
        keys.push_back(kv.first);
    }
    return keys;
}

std::optional<ptr_no_off_t> ctx_t::find(uint64_t key) const {
    auto it = m_packet_ptrs.find(key);
    if (it == m_packet_ptrs.end()) return {};
    return it->second;
}

register_types_t register_types_t::operator|(const register_types_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    live_registers_t out_vars;

    // a hack to store region information at the start of a joined basic block
    // in join, we do not know the label of the bb, hence we store the information
    // at a bb that is not used anywhere else in the program, and later when we know
    // the bb label, we can fix
    location_t loc = location_t(std::make_pair(label_t(-2, -2), 0));

    for (size_t i = 0; i < m_cur_def.size(); i++) {
        if (m_cur_def[i] == nullptr || other.m_cur_def[i] == nullptr) continue;
        auto maybe_ptr1 = find(*(m_cur_def[i]));
        auto maybe_ptr2 = other.find(*(other.m_cur_def[i]));
        if (maybe_ptr1 && maybe_ptr2) {
            ptr_or_mapfd_t ptr_or_mapfd1 = maybe_ptr1.value(), ptr_or_mapfd2 = maybe_ptr2.value();
            auto reg = reg_with_loc_t((register_t)i, loc);
            if (ptr_or_mapfd1 == ptr_or_mapfd2) {
                out_vars[i] = m_cur_def[i];
            }
            else { 
                auto shared_reg = std::make_shared<reg_with_loc_t>(reg);
                if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd1)
                            && std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd2)) {
                    ptr_with_off_t ptr_with_off1 = std::get<ptr_with_off_t>(ptr_or_mapfd1);
                    ptr_with_off_t ptr_with_off2 = std::get<ptr_with_off_t>(ptr_or_mapfd2);
                    if (ptr_with_off1.get_region() == ptr_with_off2.get_region()) {
                        out_vars[i] = shared_reg;
                        (*m_region_env)[reg] = std::move(ptr_with_off1 | ptr_with_off2);
                    }
                }
                else if (std::holds_alternative<mapfd_t>(ptr_or_mapfd1)
                        && std::holds_alternative<mapfd_t>(ptr_or_mapfd2)) {
                    mapfd_t mapfd1 = std::get<mapfd_t>(ptr_or_mapfd1);
                    mapfd_t mapfd2 = std::get<mapfd_t>(ptr_or_mapfd2);
                    out_vars[i] = shared_reg;
                    (*m_region_env)[reg] = std::move(mapfd1 | mapfd2);
                }
            }
        }
    }
    return register_types_t(std::move(out_vars), m_region_env, false);
}

void register_types_t::operator-=(register_t var) {
    if (is_bottom()) {
        return;
    }
    m_cur_def[var] = nullptr;
}

void register_types_t::set_to_bottom() {
    m_is_bottom = true;
}

void register_types_t::set_to_top() {
    m_cur_def = live_registers_t{nullptr};
    m_is_bottom = false;
}

bool register_types_t::is_bottom() const { return m_is_bottom; }

bool register_types_t::is_top() const {
    if (m_is_bottom) { return false; }
    if (m_region_env == nullptr) return true;
    for (auto &it : m_cur_def) {
        if (it != nullptr) return false;
    }
    return true;
}

void register_types_t::insert(register_t reg, const reg_with_loc_t& reg_with_loc,
        const ptr_or_mapfd_t& type) {
    (*m_region_env)[reg_with_loc] = type;
    m_cur_def[reg] = std::make_shared<reg_with_loc_t>(reg_with_loc);
}

void register_types_t::print_all_register_types() const {
    std::cout << "\tregion types: {\n";
    for (auto const& kv : *m_region_env) {
        std::cout << "\t\t" << kv.first << " : ";
        print_ptr_or_mapfd_type(std::cout, kv.second);
        std::cout << "\n";
    }
    std::cout << "\t}\n";
}

std::optional<ptr_or_mapfd_t> register_types_t::find(reg_with_loc_t reg) const {
    auto it = m_region_env->find(reg);
    if (it == m_region_env->end()) return {};
    return it->second;
}

std::optional<ptr_or_mapfd_t> register_types_t::find(register_t key) const {
    if (m_cur_def[key] == nullptr) return {};
    const reg_with_loc_t& reg = *(m_cur_def[key]);
    return find(reg);
}

void register_types_t::adjust_bb_for_registers(location_t loc) {
    location_t old_loc = location_t(std::make_pair(label_t(-2, -2), 0));
    for (size_t i = 0; i < m_cur_def.size(); i++) {
        auto new_reg = reg_with_loc_t((register_t)i, loc);
        auto old_reg = reg_with_loc_t((register_t)i, old_loc);

        auto it = find((register_t)i);
        if (!it) continue;

        if (*m_cur_def[i] == old_reg) {
            m_region_env->erase(old_reg);
        }

        m_cur_def[i] = std::make_shared<reg_with_loc_t>(new_reg);
        (*m_region_env)[new_reg] = it.value();

    }
}

stack_t stack_t::operator|(const stack_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    ptr_or_mapfd_types_t out_ptrs;
    for (auto const&kv: m_ptrs) {
        auto maybe_ptr_or_mapfd_cells = other.find(kv.first);
        if (maybe_ptr_or_mapfd_cells) {
            auto ptr_or_mapfd_cells1 = kv.second;
            auto ptr_or_mapfd_cells2 = *maybe_ptr_or_mapfd_cells;
            auto ptr_or_mapfd1 = ptr_or_mapfd_cells1.first;
            auto ptr_or_mapfd2 = ptr_or_mapfd_cells2.first;
            int width1 = ptr_or_mapfd_cells1.second;
            int width2 = ptr_or_mapfd_cells2.second;
            int width_joined = std::max(width1, width2);
            if (ptr_or_mapfd1 == ptr_or_mapfd2) {
                out_ptrs[kv.first] = std::make_pair(ptr_or_mapfd1, width_joined);
            }
            else if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd1) &&
                    std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd2)) {
                auto ptr_with_off1 = std::get<ptr_with_off_t>(ptr_or_mapfd1);
                auto ptr_with_off2 = std::get<ptr_with_off_t>(ptr_or_mapfd2);
                if (ptr_with_off1.get_region() == ptr_with_off2.get_region()) {
                    out_ptrs[kv.first]
                        = std::make_pair(ptr_with_off1 | ptr_with_off2, width_joined);
                }
            }
            else if (std::holds_alternative<mapfd_t>(ptr_or_mapfd1) &&
                    std::holds_alternative<mapfd_t>(ptr_or_mapfd2)) {
                auto mapfd1 = std::get<mapfd_t>(ptr_or_mapfd1);
                auto mapfd2 = std::get<mapfd_t>(ptr_or_mapfd2);
                out_ptrs[kv.first] = std::make_pair(mapfd1 | mapfd2, width_joined);
            }
        }
    }
    return stack_t(std::move(out_ptrs), false);
}

void stack_t::operator-=(uint64_t key) {
    auto it = find(key);
    if (it)
        m_ptrs.erase(key);
}

void stack_t::operator-=(const std::vector<uint64_t>& keys) {
    for (auto &key : keys) {
       *this -= key;
    }
}

void stack_t::set_to_bottom() {
    m_ptrs.clear();
    m_is_bottom = true;
}

void stack_t::set_to_top() {
    m_ptrs.clear();
    m_is_bottom = false;
}

stack_t stack_t::bottom() { return stack_t(true); }

stack_t stack_t::top() { return stack_t(false); }

bool stack_t::is_bottom() const { return m_is_bottom; }

bool stack_t::is_top() const {
    if (m_is_bottom)
        return false;
    return m_ptrs.empty();
}

void stack_t::store(uint64_t key, ptr_or_mapfd_t value, int width) {
    m_ptrs[key] = std::make_pair(value, width);
}

size_t stack_t::size() const {
    return m_ptrs.size();
}

std::vector<uint64_t> stack_t::get_keys() const {
    std::vector<uint64_t> keys;
    keys.reserve(size());

    for (auto const&kv : m_ptrs) {
        keys.push_back(kv.first);
    }
    return keys;
}


std::optional<ptr_or_mapfd_cells_t> stack_t::find(uint64_t key) const {
    auto it = m_ptrs.find(key);
    if (it == m_ptrs.end()) return {};
    return it->second;
}

std::vector<uint64_t> stack_t::find_overlapping_cells(uint64_t start, int width) const {
    std::vector<uint64_t> overlapping_cells;
    auto it = m_ptrs.begin();
    while (it != m_ptrs.end() && it->first < start) {
        it++;
    }
    if (it != m_ptrs.begin()) {
        it--;
        auto key = it->first;
        auto width_key = it->second.second;
        if (key < start && key+width_key > start) overlapping_cells.push_back(key);
    }

    for (; it != m_ptrs.end(); it++) {
        auto key = it->first;
        if (key >= start && key < start+width) overlapping_cells.push_back(key);
        if (key >= start+width) break;
    }
    return overlapping_cells;
}

std::optional<ptr_or_mapfd_t> region_domain_t::find_ptr_or_mapfd_type(register_t reg) const {
    return m_registers.find(reg);
}

bool region_domain_t::is_bottom() const {
    if (m_is_bottom) return true;
    return (m_stack.is_bottom() || m_registers.is_bottom());
}

bool region_domain_t::is_top() const {
    if (m_is_bottom) return false;
    return (m_stack.is_top() && m_registers.is_top());
}

region_domain_t region_domain_t::bottom() {
    region_domain_t typ;
    typ.set_to_bottom();
    return typ;
}

void region_domain_t::set_to_bottom() {
    m_is_bottom = true;
}

void region_domain_t::set_to_top() {
    m_stack.set_to_top();
    m_registers.set_to_top();
}

std::optional<ptr_or_mapfd_t> region_domain_t::find_ptr_or_mapfd_at_loc(const reg_with_loc_t& reg) const {
    return m_registers.find(reg);
}

size_t region_domain_t::ctx_size() const {
    return m_ctx->get_size();
}

std::vector<uint64_t> region_domain_t::get_ctx_keys() const {
    return m_ctx->get_keys();
}

std::vector<uint64_t> region_domain_t::get_stack_keys() const {
    return m_stack.get_keys();
}

std::optional<ptr_no_off_t> region_domain_t::find_in_ctx(uint64_t key) const {
    return m_ctx->find(key);
}

std::optional<ptr_or_mapfd_cells_t> region_domain_t::find_in_stack(uint64_t key) const {
    return m_stack.find(key);
}

bool region_domain_t::operator<=(const region_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return true;
}

void region_domain_t::operator|=(const region_domain_t& abs) {
    region_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void region_domain_t::operator|=(region_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

region_domain_t region_domain_t::operator|(const region_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return region_domain_t(m_registers | other.m_registers, m_stack | other.m_stack, other.m_ctx);
}

region_domain_t region_domain_t::operator|(region_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return region_domain_t(m_registers | std::move(other.m_registers), m_stack | std::move(other.m_stack), other.m_ctx);
}

region_domain_t region_domain_t::operator&(const region_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

region_domain_t region_domain_t::widen(const region_domain_t& abs) const {
    /* WARNING: The operation is not implemented yet.*/
    return abs;
}

region_domain_t region_domain_t::narrow(const region_domain_t& other) const {
    /* WARNING: The operation is not implemented yet.*/
    return other;
}

std::string region_domain_t::domain_name() const {
    return "region_domain";
}

crab::bound_t region_domain_t::get_instruction_count_upper_bound() {
    /* WARNING: The operation is not implemented yet.*/
    return crab::bound_t{number_t{0}};
}

string_invariant region_domain_t::to_set() {
    return string_invariant{};
}

void region_domain_t::operator()(const Undefined &u, location_t loc, int print) {}

void region_domain_t::operator()(const Exit &u, location_t loc, int print) {}

void region_domain_t::operator()(const Jmp &u, location_t loc, int print) {}

void region_domain_t::operator()(const LockAdd& u, location_t loc, int print) {}

void region_domain_t::operator()(const Assume& u, location_t loc, int print) {
    // nothing to do here
}

void region_domain_t::operator()(const Assert& u, location_t loc, int print) {
    // nothing to do here
}

void region_domain_t::operator()(const Comparable& u, location_t loc, int print) {
    // nothing to do here
}

void region_domain_t::operator()(const ValidMapKeyValue& u, location_t loc, int print) {
    // nothing to do here
}

void region_domain_t::operator()(const ZeroCtxOffset& u, location_t loc, int print) {
    auto maybe_ptr_or_mapfd = m_registers.find(u.reg.v);
    if (is_ctx_ptr(maybe_ptr_or_mapfd)) {
        auto ctx_ptr = std::get<ptr_with_off_t>(*maybe_ptr_or_mapfd);
        if (ctx_ptr.get_offset() == interval_t{crab::number_t{0}}) return;
    }
    //std::cout << "type error: Zero Offset assertion fail\n";
    m_errors.push_back("Zero Ctx Offset assertion fail");
}

void region_domain_t::operator()(const basic_block_t& bb, bool check_termination, int print) {
    // nothing to do here
}

void region_domain_t::operator()(const Un& u, location_t loc, int print) {
    // nothing to do here
}

void region_domain_t::operator()(const ValidDivisor& u, location_t loc, int print) {
    /* WARNING: The operation is not implemented yet.*/
}

void region_domain_t::operator()(const ValidSize& u, location_t loc, int print) {
    /* WARNING: The operation is not implemented yet.*/
}

// Get the start and end of the range of possible map fd values.
// In the future, it would be cleaner to use a set rather than an interval
// for map fds.
bool region_domain_t::get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const {
    auto maybe_type = m_registers.find(map_fd_reg.v);
    if (!is_mapfd_type(maybe_type)) return false;
    auto mapfd_type = std::get<mapfd_t>(*maybe_type);
    const interval_t& mapfd_interval = mapfd_type.get_mapfd();
    auto lb = mapfd_interval.lb().number();
    auto ub = mapfd_interval.ub().number();
    if (!lb || !lb->fits_sint32() || !ub || !ub->fits_sint32())
        return false;
    *start_fd = (int32_t)lb.value();
    *end_fd = (int32_t)ub.value();

    // Cap the maximum range we'll check.
    const int max_range = 32;
    return (*mapfd_interval.finite_size() < max_range);
}

// All maps in the range must have the same type for us to use it.
std::optional<uint32_t> region_domain_t::get_map_type(const Reg& map_fd_reg) const {
    int32_t start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return std::optional<uint32_t>();

    std::optional<uint32_t> type;
    for (int32_t map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd);
        if (map == nullptr)
            return std::optional<uint32_t>();
        if (!type.has_value())
            type = map->type;
        else if (map->type != *type)
            return std::optional<uint32_t>();
    }
    return type;
}

// All maps in the range must have the same inner map fd for us to use it.
std::optional<uint32_t> region_domain_t::get_map_inner_map_fd(const Reg& map_fd_reg) const {
    int32_t start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return std::optional<uint32_t>();

    std::optional<uint32_t> inner_map_fd;
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd);
        if (map == nullptr)
            return std::optional<uint32_t>();
        if (!inner_map_fd.has_value())
            inner_map_fd = map->inner_map_fd;
        else if (map->type != *inner_map_fd)
            return std::optional<uint32_t>();
    }
    return inner_map_fd;
}

// We can deal with a range of value sizes.
interval_t region_domain_t::get_map_value_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return interval_t::top();

    interval_t result = crab::interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd))
            result = result | crab::interval_t(number_t(map->value_size));
        else
            return interval_t::top();
    }
    return result;
}

void region_domain_t::do_load_mapfd(const register_t& dst_reg, int mapfd, location_t loc) {
    auto reg_with_loc = reg_with_loc_t(dst_reg, loc);
    const auto& platform = global_program_info->platform;
    const EbpfMapDescriptor& desc = platform->get_map_descriptor(mapfd);
    const EbpfMapValueType& map_value_type = platform->get_map_type(desc.type).value_type;
    auto mapfd_interval = interval_t{number_t{mapfd}};
    auto type = mapfd_t(mapfd_interval, map_value_type);
    m_registers.insert(dst_reg, reg_with_loc, type);
}

void region_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    do_load_mapfd((register_t)u.dst.v, u.mapfd, loc);
}

void region_domain_t::operator()(const Call& u, location_t loc, int print) {
    std::optional<Reg> maybe_fd_reg{};
    for (ArgSingle param : u.singles) {
        if (param.kind == ArgSingle::Kind::MAP_FD) maybe_fd_reg = param.reg;
        break;
    }
    register_t r0_reg{R0_RETURN_VALUE};
    auto r0 = reg_with_loc_t(r0_reg, loc);
    if (u.is_map_lookup) {
        if (maybe_fd_reg) {
            if (auto map_type = get_map_type(*maybe_fd_reg)) {
                if (global_program_info->platform->get_map_type(*map_type).value_type
                        == EbpfMapValueType::MAP) {
                    if (auto inner_map_fd = get_map_inner_map_fd(*maybe_fd_reg)) {
                        do_load_mapfd(r0_reg, (int)*inner_map_fd, loc);
                        goto out;
                    }
                } else {
                    auto type = ptr_with_off_t(crab::region_t::T_SHARED, interval_t{number_t{0}},
                            get_map_value_size(*maybe_fd_reg));
                    m_registers.insert(r0_reg, r0, type);
                }
            }
        }
        else {
            auto type = ptr_with_off_t(
                 crab::region_t::T_SHARED, interval_t{number_t{0}}, crab::interval_t::top());
            m_registers.insert(r0_reg, r0, type);
        }
    }
    else {
        m_registers -= r0_reg;
    }
out:
    if (u.reallocate_packet) {
        // forget packet pointers
    }
}

void region_domain_t::operator()(const Packet &u, location_t loc, int print) {
    m_registers -= register_t{R0_RETURN_VALUE};
}

void region_domain_t::operator()(const Addable &u, location_t loc, int print) {

    auto maybe_ptr_type1 = m_registers.find(u.ptr.v);
    auto maybe_ptr_type2 = m_registers.find(u.num.v);
    // a -> b <-> !a || b
    if (!maybe_ptr_type1 || !maybe_ptr_type2) {
        return;
    }
    //std::cout << "type error: Addable assertion fail\n";
    m_errors.push_back("Addable assertion fail");
}

void region_domain_t::operator()(const ValidAccess &s, location_t loc, int print) {
    bool is_comparison_check = s.width == (Value)Imm{0};
    if (std::holds_alternative<Reg>(s.width)) return;
    int width = std::get<Imm>(s.width).v;

    auto maybe_ptr_or_mapfd_type = m_registers.find(s.reg.v);
    if (maybe_ptr_or_mapfd_type) {
        auto reg_ptr_or_mapfd_type = *maybe_ptr_or_mapfd_type;
        if (std::holds_alternative<ptr_with_off_t>(reg_ptr_or_mapfd_type)) {
            auto reg_with_off_ptr_type = std::get<ptr_with_off_t>(reg_ptr_or_mapfd_type);
            auto offset = reg_with_off_ptr_type.get_offset();
            auto offset_to_check = offset+interval_t{s.offset};
            auto offset_lb = offset_to_check.lb();
            auto offset_plus_width_ub = offset_to_check.ub()+crab::bound_t{width};
            if (reg_with_off_ptr_type.get_region() == crab::region_t::T_STACK) {
                if (crab::bound_t{STACK_BEGIN} <= offset_lb
                        && offset_plus_width_ub <= crab::bound_t{EBPF_STACK_SIZE})
                    return;
            }
            else if (reg_with_off_ptr_type.get_region() == crab::region_t::T_CTX) {
                if (crab::bound_t{CTX_BEGIN} <= offset_lb
                        && offset_plus_width_ub <= crab::bound_t{ctx_size()})
                    return;
            }
            else { // shared
                if (crab::bound_t{SHARED_BEGIN} <= offset_lb &&
                        offset_plus_width_ub <= reg_with_off_ptr_type.get_region_size().lb()) return;
                // TODO: check null access
                //return;
            }
        }
        else if (std::holds_alternative<ptr_no_off_t>(reg_ptr_or_mapfd_type)) {
            // We do not handle packet ptr access in region domain
            return;
        }
        else {
            // mapfd
            if (is_comparison_check) return;
            //std::cout << "type error: FDs cannot be dereferenced directly\n";
            m_errors.push_back("FDs cannot be dereferenced directly");
        }
        //std::cout << "type error: valid access assert fail\n";
        m_errors.push_back("valid access assert fail");
    }
}

void region_domain_t::operator()(const ValidStore& u, location_t loc, int print) {

    bool is_stack_p = is_stack_ptr(m_registers.find(u.val.v));
    auto maybe_ptr_type2 = m_registers.find(u.val.v);

    if (is_stack_p || !maybe_ptr_type2) {
        return;
    }
    //std::cout << "type error: Valid store assertion fail\n";
    m_errors.push_back("Valid store assertion fail");
}

region_domain_t&& region_domain_t::setup_entry() {

    std::shared_ptr<ctx_t> ctx = std::make_shared<ctx_t>(global_program_info.get().type.context_descriptor);
    std::shared_ptr<global_region_env_t> all_types = std::make_shared<global_region_env_t>();

    register_types_t typ(all_types);

    auto r1 = reg_with_loc_t(R1_ARG, std::make_pair(label_t::entry, static_cast<unsigned int>(0)));
    auto r10 = reg_with_loc_t(R10_STACK_POINTER, std::make_pair(label_t::entry, static_cast<unsigned int>(0)));

    typ.insert(R1_ARG, r1, ptr_with_off_t(crab::region_t::T_CTX, interval_t{number_t{0}}));
    typ.insert(R10_STACK_POINTER, r10,
            ptr_with_off_t(crab::region_t::T_STACK, interval_t{number_t{512}}));

    static region_domain_t inv(std::move(typ), crab::stack_t::top(), ctx);
    return std::move(inv);
}

void region_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
    auto ptr_or_mapfd_opt = m_registers.find(s.reg.v);
    if (ptr_or_mapfd_opt) {
        // it is a pointer or mapfd
        auto ptr_or_mapfd_type = ptr_or_mapfd_opt.value();
        if (std::holds_alternative<mapfd_t>(ptr_or_mapfd_type)) {
            auto map_fd = std::get<mapfd_t>(ptr_or_mapfd_type);
            if (map_fd.has_type_map_programs()) {
                if (s.types == TypeGroup::map_fd_programs) return;
            } else {
                if (s.types == TypeGroup::map_fd) return;
            }
        }
        else {
            if (s.types == TypeGroup::pointer || s.types == TypeGroup::ptr_or_num) return;
            if (s.types == TypeGroup::non_map_fd) return;
            if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd_type)) {
                ptr_with_off_t ptr_with_off = std::get<ptr_with_off_t>(ptr_or_mapfd_type);
                if (ptr_with_off.get_region() == crab::region_t::T_CTX) {
                    if (s.types == TypeGroup::singleton_ptr) return;
                    if (s.types == TypeGroup::ctx) return;
                }
                else {
                    if (s.types == TypeGroup::mem || s.types == TypeGroup::mem_or_num) return;
                    if (ptr_with_off.get_region() == crab::region_t::T_SHARED) {
                        if (s.types == TypeGroup::shared) return;
                    }
                    else {
                        if (s.types == TypeGroup::singleton_ptr) return;
                        if (s.types == TypeGroup::stack || s.types == TypeGroup::stack_or_packet)
                            return;
                    }
                }
            }
            else if (std::holds_alternative<ptr_no_off_t>(ptr_or_mapfd_type)) {
                if (s.types == TypeGroup::singleton_ptr) return;
                if (s.types == TypeGroup::mem || s.types == TypeGroup::mem_or_num) return;
                if (s.types == TypeGroup::packet || s.types == TypeGroup::stack_or_packet) return;
            }
        }
    }
    else {
        // if we don't know the type, we assume it is a number
        if (s.types == TypeGroup::number || s.types == TypeGroup::ptr_or_num
                || s.types == TypeGroup::non_map_fd || s.types == TypeGroup::ptr_or_num
                || s.types == TypeGroup::mem_or_num)
            return;
    }
    //std::cout << "type error: type constraint assert fail\n";
    m_errors.push_back("type constraint assert fail");
}

void region_domain_t::update_ptr_or_mapfd(ptr_or_mapfd_t&& ptr_or_mapfd, const interval_t&& change,
        const reg_with_loc_t& reg_with_loc, uint8_t reg) {
    if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd)) {
        auto ptr_or_mapfd_with_off = std::get<ptr_with_off_t>(ptr_or_mapfd);
        auto offset = ptr_or_mapfd_with_off.get_offset();
        auto updated_offset = change == interval_t::top() ? offset : offset + change;
        ptr_or_mapfd_with_off.set_offset(updated_offset);
        m_registers.insert(reg, reg_with_loc, ptr_or_mapfd_with_off);
    }
    else if (std::holds_alternative<ptr_no_off_t>(ptr_or_mapfd)) {
        m_registers.insert(reg, reg_with_loc, ptr_or_mapfd);
    }
    else {
        //std::cout << "type error: mapfd register cannot be incremented/decremented\n";
        m_errors.push_back("mapfd register cannot be incremented/decremented");
        m_registers -= reg;
    }
}

void region_domain_t::operator()(const Bin& b, location_t loc, int print) {
    // nothing to do here
}

interval_t region_domain_t::do_bin(const Bin& bin,
        const std::optional<interval_t>& src_interval_opt,
        const std::optional<ptr_or_mapfd_t>& src_ptr_or_mapfd_opt,
        const std::optional<ptr_or_mapfd_t>& dst_ptr_or_mapfd_opt, location_t loc) {

    using Op = Bin::Op;
    // if we are doing a move, where src is a number and dst is not set, nothing to do
    if (src_interval_opt && !dst_ptr_or_mapfd_opt && bin.op == Op::MOV)
        return interval_t::bottom();

    ptr_or_mapfd_t src_ptr_or_mapfd, dst_ptr_or_mapfd;
    interval_t src_interval;
    if (src_ptr_or_mapfd_opt) src_ptr_or_mapfd = std::move(src_ptr_or_mapfd_opt.value());
    if (dst_ptr_or_mapfd_opt) dst_ptr_or_mapfd = std::move(dst_ptr_or_mapfd_opt.value());
    if (src_interval_opt) src_interval = std::move(src_interval_opt.value());

    auto reg = reg_with_loc_t(bin.dst.v, loc);
    interval_t to_return = interval_t::bottom();

    switch (bin.op)
    {
        // ra = b, where b is a pointer/mapfd, a numerical register, or a constant;
        case Op::MOV: {
            // b is a pointer/mapfd
            if (src_ptr_or_mapfd_opt)
                m_registers.insert(bin.dst.v, reg, src_ptr_or_mapfd);
            // b is a numerical register, or constant
            else if (dst_ptr_or_mapfd_opt) {
                m_registers -= bin.dst.v;
            }
            break;
        }
        // ra += b, where ra is a pointer/mapfd, or a numerical register,
        // b is a pointer/mapfd, a numerical register, or a constant;
        case Op::ADD: {
            // adding pointer to another
            if (src_ptr_or_mapfd_opt && dst_ptr_or_mapfd_opt) {
                if (is_stack_ptr(dst_ptr_or_mapfd))
                    m_stack.set_to_top();
                else {
                    // TODO: handle other cases properly
                    //std::cout << "type error: addition of two pointers\n";
                    m_errors.push_back("addition of two pointers");
                }
                m_registers -= bin.dst.v;
            }
            // ra is a pointer/mapfd
            // b is a numerical register, or a constant
            else if (dst_ptr_or_mapfd_opt && src_interval_opt) {
                update_ptr_or_mapfd(std::move(dst_ptr_or_mapfd), std::move(src_interval),
                        reg, bin.dst.v);
            }
            // b is a pointer/mapfd
            // ra is a numerical register
            else if (src_ptr_or_mapfd_opt && !dst_ptr_or_mapfd_opt) {
                update_ptr_or_mapfd(std::move(src_ptr_or_mapfd), interval_t::top(),
                        reg, bin.dst.v);
            }
            break;
        }
        // ra -= b, where ra is a pointer/mapfd
        // b is a pointer/mapfd, numerical register, or a constant;
        case Op::SUB: {
            // b is a pointer/mapfd
            if (dst_ptr_or_mapfd_opt && src_ptr_or_mapfd_opt) {
                if (std::holds_alternative<mapfd_t>(dst_ptr_or_mapfd) &&
                        std::holds_alternative<mapfd_t>(src_ptr_or_mapfd)) {
                    //std::cout << "type error: mapfd registers subtraction not defined\n";
                    m_errors.push_back("mapfd registers subtraction not defined");
                }
                else if (same_region(dst_ptr_or_mapfd, src_ptr_or_mapfd)) {
                    if (std::holds_alternative<ptr_with_off_t>(dst_ptr_or_mapfd) &&
                            std::holds_alternative<ptr_with_off_t>(src_ptr_or_mapfd)) {
                        auto dst_ptr_with_off = std::get<ptr_with_off_t>(dst_ptr_or_mapfd);
                        auto src_ptr_with_off = std::get<ptr_with_off_t>(src_ptr_or_mapfd);
                        to_return = dst_ptr_with_off.get_offset() - src_ptr_with_off.get_offset();
                    }
                }
                else {
                    //std::cout << "type error: subtraction between pointers of different region\n";
                    m_errors.push_back("subtraction between pointers of different region");
                }
                m_registers -= bin.dst.v;
            }
            // b is a numerical register, or a constant
            else if (dst_ptr_or_mapfd_opt && src_interval_opt) {
                update_ptr_or_mapfd(std::move(dst_ptr_or_mapfd), -std::move(src_interval),
                        reg, bin.dst.v);
            }
            break;
        }
        default: break;
    }
    return to_return;
}

void region_domain_t::do_load(const Mem& b, const Reg& target_reg, bool unknown_ptr,
        location_t loc) {

    if (unknown_ptr) {
        m_registers -= target_reg.v;
        return;
    }

    int width = b.access.width;
    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto ptr_or_mapfd_opt = m_registers.find(basereg.v);
    bool is_stack_p = is_stack_ptr(ptr_or_mapfd_opt);
    bool is_ctx_p = is_ctx_ptr(ptr_or_mapfd_opt);
    if (!is_ctx_p && !is_stack_p) {
        // loading from either packet or shared region or mapfd does not happen in region domain
        m_registers -= target_reg.v;
        return;
    }

    auto type_with_off = std::get<ptr_with_off_t>(*ptr_or_mapfd_opt);
    auto p_offset = type_with_off.get_offset();
    auto offset_singleton = p_offset.singleton();

    if (is_stack_p) {
        if (!offset_singleton) {
            for (auto const& k : m_stack.get_keys()) {
                auto start = p_offset.lb();
                auto end = p_offset.ub()+number_t{offset+width-1};
                interval_t range{start, end};
                if (range[number_t{(int)k}]) {
                    //std::cout << "stack load at unknown offset, and offset range contains pointers\n";
                    m_errors.push_back("stack load at unknown offset, and offset range contains pointers");
                    break;
                }
            }
            m_registers -= target_reg.v;
        }
        else {
            if (width != 1 && width != 2 && width != 4 && width != 8) {
                m_registers -= target_reg.v;
                return;
            }
            auto ptr_offset = offset_singleton.value();
            auto load_at = (uint64_t)(ptr_offset + offset);

            auto loaded = m_stack.find(load_at);
            if (!loaded) {
                // no field at loaded offset in stack
                m_registers -= target_reg.v;
                return;
            }

            auto reg = reg_with_loc_t(target_reg.v, loc);
            m_registers.insert(target_reg.v, reg, (*loaded).first);
        }
    }
    else {
        if (!offset_singleton) {
            for (auto const& k : m_ctx->get_keys()) {
                auto start = p_offset.lb();
                auto end = p_offset.ub()+crab::bound_t{offset+width-1};
                interval_t range{start, end};
                if (range[number_t{(int)k}]) {
                    //std::cout << "ctx load at unknown offset, and offset range contains pointers\n";
                    m_errors.push_back("ctx load at unknown offset, and offset range contains pointers");
                    break;
                }
            }
            m_registers -= target_reg.v;
        }
        else {
            auto ptr_offset = offset_singleton.value();
            auto load_at = (uint64_t)(ptr_offset + offset);

            auto loaded = m_ctx->find(load_at);
            if (!loaded) {
                // no field at loaded offset in ctx
                m_registers -= target_reg.v;
                return;
            }

            auto reg = reg_with_loc_t(target_reg.v, loc);
            m_registers.insert(target_reg.v, reg, *loaded);
        }
    }
}

void region_domain_t::operator()(const Mem& m, location_t loc, int print) {
    // nothing to do here
}

void region_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc) {

    int offset = b.access.offset;
    Reg basereg = b.access.basereg;
    int width = b.access.width;

    auto maybe_basereg_type = m_registers.find(basereg.v);
    auto basereg_type = maybe_basereg_type.value();
    auto targetreg_type = m_registers.find(target_reg.v);

    bool is_ctx_p = is_ctx_ptr(maybe_basereg_type);
    bool is_shared_p = is_shared_ptr(maybe_basereg_type);
    bool is_packet_p = is_packet_ptr(maybe_basereg_type);
    bool is_mapfd = is_mapfd_type(maybe_basereg_type);

    if (is_mapfd) {
        m_errors.push_back("storing into a mapfd register is not defined");
        return;
    }
    if (is_shared_p || is_packet_p || is_ctx_p) {
        if (targetreg_type) {
            m_errors.push_back("storing a pointer into a shared, packet or ctx pointer");
            return;
        }
        else {
            // storing a number into a region does not affect the region
            return;
        }
    }

    // if the code reaches here, we are storing into a stack pointer
    auto basereg_type_with_off = std::get<ptr_with_off_t>(basereg_type);
    auto offset_singleton = basereg_type_with_off.get_offset().singleton();
    if (!offset_singleton) {
        //std::cout << "type error: storing to a pointer with unknown offset\n";
        m_errors.push_back("storing to a pointer with unknown offset");
        return;
    }
    auto store_at = (uint64_t)offset+(uint64_t)offset_singleton.value();
    auto overlapping_cells = m_stack.find_overlapping_cells(store_at, width);
    m_stack -= overlapping_cells;

    // if targetreg_type is empty, we are storing a number
    if (!targetreg_type) return;
    m_stack.store(store_at, *targetreg_type, width);
}

void region_domain_t::adjust_bb_for_types(location_t loc) {
    m_registers.adjust_bb_for_registers(loc);
}

void region_domain_t::print_all_register_types() const {
    m_registers.print_all_register_types();
}

} // namespace crab
