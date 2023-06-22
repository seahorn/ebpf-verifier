// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "crab/region_domain.hpp"

using crab::___print___;
using crab::ptr_t;
using crab::mapfd_t;
using crab::ptr_or_mapfd_t;
using crab::ptr_with_off_t;
using crab::ptr_no_off_t;
using crab::ctx_t;
using crab::global_region_env_t;
using crab::reg_with_loc_t;
using crab::live_registers_t;
using crab::register_types_t;
using crab::map_key_size_t;
using crab::map_value_size_t;
using crab::ptr_or_mapfd_cells_t;

namespace std {
    template <>
    struct hash<crab::reg_with_loc_t> {
        size_t operator()(const crab::reg_with_loc_t& reg) const { return reg.hash(); }
    };

    // does not seem to work for me
    /*
    template <>
    struct equal_to<crab::ptr_t> {
        constexpr bool operator()(const crab::ptr_t& p1, const crab::ptr_t& p2) const {
            if (p1.index() != p2.index()) return false;
            if (std::holds_alternative<crab::ptr_no_off_t>(p1)) {
                auto ptr_no_off1 = std::get<crab::ptr_no_off_t>(p1);
                auto ptr_no_off2 = std::get<crab::ptr_no_off_t>(p2);
                return (ptr_no_off1.get_region() == ptr_no_off2.get_region());
            }
            else {
                auto ptr_with_off1 = std::get<crab::ptr_with_off_t>(p1);
                auto ptr_with_off2 = std::get<crab::ptr_with_off_t>(p2);
                return (ptr_with_off1.get_region() == ptr_with_off2.get_region() && ptr_with_off1.get_offset() == ptr_with_off2.get_offset());
            }
        }
    };
    */

    static ptr_t get_ptr(const ptr_or_mapfd_t& t) {
    return std::visit( overloaded
               {
                   []( const ptr_with_off_t& x ){ return ptr_t{x};},
                   []( const ptr_no_off_t& x ){ return ptr_t{x};},
                   []( auto& ) { return ptr_t{};}
                }, t
            );
    }
}


namespace crab {

inline std::string get_reg_ptr(const region_t& r) {
    switch (r) {
        case region_t::T_CTX:
            return "ctx_p";
        case region_t::T_STACK:
            return "stack_p";
        case region_t::T_PACKET:
            return "packet_p";
        default:
            return "shared_p";
    }
}

static bool same_region(const ptr_t& ptr1, const ptr_t& ptr2) {
    return ((std::holds_alternative<ptr_with_off_t>(ptr1)
                && std::holds_alternative<ptr_with_off_t>(ptr2))
            || (std::holds_alternative<ptr_no_off_t>(ptr1)
                && std::holds_alternative<ptr_no_off_t>(ptr2)));
}

static void print_ptr_type(const ptr_t& ptr) {
    if (std::holds_alternative<ptr_with_off_t>(ptr)) {
        ptr_with_off_t ptr_with_off = std::get<ptr_with_off_t>(ptr);
        std::cout << ptr_with_off;
    }
    else {
        ptr_no_off_t ptr_no_off = std::get<ptr_no_off_t>(ptr);
        std::cout << ptr_no_off;
    }
}

static void print_ptr_or_mapfd_type(const ptr_or_mapfd_t& ptr_or_mapfd) {
    if (std::holds_alternative<mapfd_t>(ptr_or_mapfd)) {
        std::cout << std::get<mapfd_t>(ptr_or_mapfd);
    }
    else {
        auto ptr = get_ptr(ptr_or_mapfd);
        print_ptr_type(ptr);
    }
}

inline std::ostream& operator<<(std::ostream& o, const region_t& t) {
    o << static_cast<std::underlying_type<region_t>::type>(t);
    return o;
}

bool operator==(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
    return (p1.get_region() == p2.get_region() && p1.get_offset() == p2.get_offset()
            && p1.get_region_size() == p2.get_region_size());
}

bool operator!=(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
    return !(p1 == p2);
}

void ptr_with_off_t::write(std::ostream& o) const {
    o << get_reg_ptr(m_r) << "<" << m_offset;
    if (m_region_size.lb() >= bound_t(0)) o << "," << m_region_size;
    o << ">";
}

std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p) {
    p.write(o);
    return o;
}

interval_t ptr_with_off_t::get_region_size() const { return m_region_size; }

void ptr_with_off_t::set_offset(interval_t off) { m_offset = off; }

void ptr_with_off_t::set_region_size(interval_t region_sz) { m_region_size = region_sz; }

void ptr_with_off_t::set_region(region_t r) { m_r = r; }

ptr_with_off_t ptr_with_off_t::operator|(const ptr_with_off_t& other) const {
    return ptr_with_off_t(m_r, m_offset | other.m_offset, m_region_size | other.m_region_size);
}

bool operator==(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
    return (p1.get_region() == p2.get_region());
}

bool operator!=(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
    return !(p1 == p2);
}

void ptr_no_off_t::write(std::ostream& o) const {
    o << get_reg_ptr(get_region());
}

std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p) {
    p.write(o);
    return o;
}

void ptr_no_off_t::set_region(region_t r) { m_r = r; }

bool operator==(const mapfd_t& m1, const mapfd_t& m2) {
    return (m1.get_value_type() == m2.get_value_type());
}

std::ostream& operator<<(std::ostream& o, const mapfd_t& m) {
    m.write(o);
    return o;
}

bool mapfd_t::has_type_map_programs() const {
    return (m_value_type == EbpfMapValueType::PROGRAM);
}

void mapfd_t::write(std::ostream& o) const {
    if (has_type_map_programs()) {
        o << "map_fd_programs";
    }
    else {
        o << "map_fd";
    }
}

void reg_with_loc_t::write(std::ostream& o) const {
    o << "r" << static_cast<unsigned int>(m_reg) << "@" << m_loc->second << " in " << m_loc->first << " ";
}

std::ostream& operator<<(std::ostream& o, const reg_with_loc_t& reg) {
    reg.write(o);
    return o;
}

bool reg_with_loc_t::operator==(const reg_with_loc_t& other) const {
    return (m_reg == other.m_reg && m_loc == other.m_loc);
}

std::size_t reg_with_loc_t::hash() const {
    // Similar to boost::hash_combine
    using std::hash;

    std::size_t seed = hash<register_t>()(m_reg);
    seed ^= hash<int>()(m_loc->first.from) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= hash<int>()(m_loc->first.to) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= hash<int>()(m_loc->second) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

    return seed;
}

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
}

size_t ctx_t::size() const {
    return m_packet_ptrs.size();
}

std::vector<uint64_t> ctx_t::get_keys() const {
    std::vector<uint64_t> keys;
    keys.reserve(size());

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
        auto it1 = find(*(m_cur_def[i]));
        auto it2 = other.find(*(other.m_cur_def[i]));
        if (it1 && it2) {
            ptr_or_mapfd_t ptr_or_mapfd1 = it1.value(), ptr_or_mapfd2 = it2.value();
            auto reg = reg_with_loc_t((register_t)i, loc);
            if (ptr_or_mapfd1 == ptr_or_mapfd2) {
                out_vars[i] = m_cur_def[i];
            }
            else if (!std::holds_alternative<mapfd_t>(ptr_or_mapfd1)
                    && !std::holds_alternative<mapfd_t>(ptr_or_mapfd2)) {
                auto ptr1 = get_ptr(ptr_or_mapfd1);
                auto ptr2 = get_ptr(ptr_or_mapfd2);
                if (std::holds_alternative<ptr_with_off_t>(ptr1)
                        && std::holds_alternative<ptr_with_off_t>(ptr2)) {
                    ptr_with_off_t ptr_with_off1 = std::get<ptr_with_off_t>(ptr1);
                    ptr_with_off_t ptr_with_off2 = std::get<ptr_with_off_t>(ptr2);
                    if (ptr_with_off1.get_region() == ptr_with_off2.get_region()) {
                        out_vars[i] = std::make_shared<reg_with_loc_t>(reg);
                        (*m_region_env)[reg] = std::move(ptr_with_off1 | ptr_with_off2);
                    }
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
    for (auto it : m_cur_def) {
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
        print_ptr_or_mapfd_type(kv.second);
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
            auto ptr_or_mapfd_cells2 = maybe_ptr_or_mapfd_cells.value();
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
    return m_ctx->size();
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

int region_domain_t::get_instruction_count_upper_bound() {
    /* WARNING: The operation is not implemented yet.*/
    return 0;
}

string_invariant region_domain_t::to_set() {
    return string_invariant{};
}

void region_domain_t::operator()(const LoadMapFd &u, location_t loc, int print) {
    auto reg = u.dst.v;
    auto reg_with_loc = reg_with_loc_t(reg, loc);
    const EbpfMapDescriptor& desc = global_program_info.platform->get_map_descriptor(u.mapfd);
    const EbpfMapValueType& map_value_type = global_program_info.platform->
        get_map_type(desc.type).value_type;
    map_key_size_t map_key_size = desc.key_size;
    map_value_size_t map_value_size = desc.value_size;
    auto type = mapfd_t(u.mapfd, map_value_type, map_key_size, map_value_size);
    m_registers.insert(reg, reg_with_loc, type);
}

void region_domain_t::operator()(const Call &u, location_t loc, int print) {
    std::optional<Reg> maybe_fd_reg{};
    for (ArgSingle param : u.singles) {
        if (param.kind == ArgSingle::Kind::MAP_FD) maybe_fd_reg = param.reg;
        break;
    }
    register_t r0_reg{R0_RETURN_VALUE};
    auto r0 = reg_with_loc_t(r0_reg, loc);
    if (u.is_map_lookup) {
        if (!maybe_fd_reg) {
            m_registers -= r0_reg;
            return;
        }
        auto ptr_or_mapfd = m_registers.find(maybe_fd_reg->v);
        if (!ptr_or_mapfd || !std::holds_alternative<mapfd_t>(ptr_or_mapfd.value())) {
            m_registers -= r0_reg;
            return;
        }
        auto mapfd = std::get<mapfd_t>(ptr_or_mapfd.value());
        auto map_desc = global_program_info.platform->get_map_descriptor(mapfd.get_mapfd());
        if (mapfd.get_value_type() == EbpfMapValueType::MAP) {
            const EbpfMapDescriptor& inner_map_desc = global_program_info.platform->
                get_map_descriptor(map_desc.inner_map_fd);
            const EbpfMapValueType& inner_map_value_type = global_program_info.platform->
                get_map_type(inner_map_desc.type).value_type;
            map_key_size_t inner_map_key_size = inner_map_desc.key_size;
            map_value_size_t inner_map_value_size = inner_map_desc.value_size;
            auto type = mapfd_t(map_desc.inner_map_fd, inner_map_value_type,
                    inner_map_key_size, inner_map_value_size);
            m_registers.insert(r0_reg, r0, type);
        }
        else {
            auto type = ptr_with_off_t(crab::region_t::T_SHARED, interval_t(number_t(0)),
                    interval_t(number_t(mapfd.get_value_size())));
            m_registers.insert(r0_reg, r0, type);
        }
    }
    else {
        m_registers -= r0_reg;
    }
}

void region_domain_t::operator()(const Packet & u, location_t loc, int print) {
    m_registers -= register_t{R0_RETURN_VALUE};
}

void region_domain_t::operator()(const Addable& u, location_t loc, int print) {

    auto maybe_ptr_type1 = m_registers.find(u.ptr.v);
    auto maybe_ptr_type2 = m_registers.find(u.num.v);
    // a -> b <-> !a || b
    if (!maybe_ptr_type1 || !maybe_ptr_type2) {
        return;
    }
    std::cout << "Addable assertion fail\n";
}

void region_domain_t::operator()(const ValidStore& u, location_t loc, int print) {

    bool is_stack_p = is_stack_pointer(u.mem.v);
    auto maybe_ptr_type2 = m_registers.find(u.val.v);

    if (is_stack_p || !maybe_ptr_type2) {
        return;
    }
    std::cout << "Valid store assertion fail\n";
}

region_domain_t region_domain_t::setup_entry() {

    std::shared_ptr<ctx_t> ctx = std::make_shared<ctx_t>(global_program_info.type.context_descriptor);
    std::shared_ptr<global_region_env_t> all_types = std::make_shared<global_region_env_t>();

    register_types_t typ(all_types);

    auto r1 = reg_with_loc_t(R1_ARG, std::make_pair(label_t::entry, static_cast<unsigned int>(0)));
    auto r10 = reg_with_loc_t(R10_STACK_POINTER, std::make_pair(label_t::entry, static_cast<unsigned int>(0)));

    typ.insert(R1_ARG, r1, ptr_with_off_t(crab::region_t::T_CTX, interval_t(number_t(0))));
    typ.insert(R10_STACK_POINTER, r10, ptr_with_off_t(crab::region_t::T_STACK, interval_t(number_t(512))));

    region_domain_t inv(std::move(typ), crab::stack_t::top(), ctx);
    return inv;
}

void region_domain_t::report_type_error(std::string s, location_t loc) {
    std::cout << "type_error at line " << loc->second << " in bb " << loc->first << "\n";
    std::cout << s;
    error_location = loc;
    set_to_bottom();
}

void region_domain_t::operator()(const TypeConstraint& s, location_t loc, int print) {
    auto it = find_ptr_or_mapfd_type(s.reg.v);
    if (it) {
        // it is a pointer or mapfd
        ptr_or_mapfd_t ptr_or_mapfd_type = it.value();
        if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd_type)) {
            if (s.types == TypeGroup::non_map_fd) return;
            if (s.types == TypeGroup::pointer || s.types == TypeGroup::ptr_or_num) return;
            ptr_with_off_t ptr_with_off = std::get<ptr_with_off_t>(ptr_or_mapfd_type);
            if (ptr_with_off.get_region() == crab::region_t::T_CTX) {
                if (s.types == TypeGroup::ctx) return;
            }
            else if (ptr_with_off.get_region() == crab::region_t::T_SHARED) {
                if (s.types == TypeGroup::shared || s.types == TypeGroup::mem
                        || s.types == TypeGroup::mem_or_num) return;
            }
            else {
                if (s.types == TypeGroup::stack || s.types == TypeGroup::mem
                        || s.types == TypeGroup::stack_or_packet
                        || s.types == TypeGroup::mem_or_num) {
                    return;
                }
            }
        }
        else if (std::holds_alternative<ptr_no_off_t>(ptr_or_mapfd_type)) {
            if (s.types == TypeGroup::non_map_fd) return;
            if (s.types == TypeGroup::pointer || s.types == TypeGroup::ptr_or_num) return;
            if (s.types == TypeGroup::packet || s.types == TypeGroup::mem
                    || s.types == TypeGroup::mem_or_num) return;
        }
        else {
            auto map_fd = std::get<mapfd_t>(ptr_or_mapfd_type);
            if (map_fd.has_type_map_programs()) {
                if (s.types == TypeGroup::map_fd_programs) return;
            } else {
                if (s.types == TypeGroup::map_fd) return;
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
    std::cout << "type constraint assert fail: " << s << "\n";
    //exit(1);
}

void region_domain_t::update_ptr_or_mapfd(ptr_or_mapfd_t&& ptr_or_mapfd, const interval_t&& change,
        Bin::Op op, const reg_with_loc_t& reg_with_loc, uint8_t reg) {
    if (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd)) {
        auto ptr_or_mapfd_with_off = std::get<ptr_with_off_t>(ptr_or_mapfd);
        auto offset = ptr_or_mapfd_with_off.get_offset();
        auto updated_offset = op == Bin::Op::ADD ? offset + change : offset - change;
        ptr_or_mapfd_with_off.set_offset(updated_offset);
        m_registers.insert(reg, reg_with_loc, ptr_or_mapfd_with_off);
    }
    else if (std::holds_alternative<ptr_no_off_t>(ptr_or_mapfd)) {
        m_registers.insert(reg, reg_with_loc, ptr_or_mapfd);
    }
    else {
        std::cout << "type error: mapfd register cannot be incremented/decremented\n";
        m_registers -= reg;
    }
}

interval_t region_domain_t::do_bin(const Bin& bin,
        const std::optional<interval_t>& src_interval_opt,
        const std::optional<interval_t>& dst_interval_opt,
        const std::optional<ptr_or_mapfd_t>& src_ptr_or_mapfd_opt,
        const std::optional<ptr_or_mapfd_t>& dst_ptr_or_mapfd_opt, location_t loc) {

    using Op = Bin::Op;
    // if both src and dst are numbers, nothing to do in region domain
    // if we are doing a move, where src is a number and dst is not set, nothing to do
    if ((dst_interval_opt && src_interval_opt)
            || (src_interval_opt && !dst_ptr_or_mapfd_opt && bin.op == Op::MOV))
        return interval_t::bottom();

    ptr_or_mapfd_t src_ptr_or_mapfd, dst_ptr_or_mapfd;
    interval_t src_interval, dst_interval;
    if (src_ptr_or_mapfd_opt) src_ptr_or_mapfd = std::move(src_ptr_or_mapfd_opt.value());
    if (dst_ptr_or_mapfd_opt) dst_ptr_or_mapfd = std::move(dst_ptr_or_mapfd_opt.value());
    if (src_interval_opt) src_interval = std::move(src_interval_opt.value());
    if (dst_interval_opt) dst_interval = std::move(dst_interval_opt.value());

    auto reg = reg_with_loc_t(bin.dst.v, loc);

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
                if (is_stack_pointer(bin.dst.v))
                    m_stack.set_to_top();
                else {
                    // TODO: handle other cases properly
                    std::cout << "type error: addition of two pointers\n";
                }
                m_registers -= bin.dst.v;
            }
            // ra is a pointer/mapfd
            // b is a numerical register, or a constant
            else if (dst_ptr_or_mapfd_opt && src_interval_opt) {
                update_ptr_or_mapfd(std::move(dst_ptr_or_mapfd), std::move(src_interval),
                        bin.op, reg, bin.dst.v);
            }
            // b is a pointer/mapfd
            // ra is a numerical register
            else if (src_ptr_or_mapfd_opt && dst_interval_opt) {
                update_ptr_or_mapfd(std::move(src_ptr_or_mapfd), std::move(dst_interval),
                        bin.op, reg, bin.dst.v);
            }
            // this should not occur
            else assert(false);
            break;
        }
        // ra -= b, where ra is a pointer/mapfd
        // b is a pointer/mapfd, numerical register, or a constant;
        case Op::SUB: {
            // b is a pointer/mapfd
            if (dst_ptr_or_mapfd_opt && src_ptr_or_mapfd_opt) {
                if (std::holds_alternative<mapfd_t>(dst_ptr_or_mapfd) &&
                        std::holds_alternative<mapfd_t>(src_ptr_or_mapfd)) {
                    std::cout << "type error: mapfd registers subtraction not defined\n";
                }
                else if (std::holds_alternative<ptr_with_off_t>(dst_ptr_or_mapfd) &&
                        std::holds_alternative<ptr_with_off_t>(src_ptr_or_mapfd)) {
                    auto dst_ptr_or_mapfd_with_off = std::get<ptr_with_off_t>(dst_ptr_or_mapfd);
                    auto src_ptr_or_mapfd_with_off = std::get<ptr_with_off_t>(src_ptr_or_mapfd);
                    if (dst_ptr_or_mapfd_with_off.get_region()
                            == src_ptr_or_mapfd_with_off.get_region()) {
                        m_registers -= bin.dst.v;
                        return (dst_ptr_or_mapfd_with_off.get_offset() -
                            src_ptr_or_mapfd_with_off.get_offset());
                    }
                    else
                        std::cout <<
                            "type error: subtraction between pointers of different region\n";
                }
                else if (!same_region(get_ptr(dst_ptr_or_mapfd), get_ptr(src_ptr_or_mapfd))) {
                    std::cout << "type error: subtraction between pointers of different region\n";
                }
                m_registers -= bin.dst.v;
            }
            // b is a numerical register, or a constant
            else if (dst_ptr_or_mapfd_opt && src_interval_opt) {
                update_ptr_or_mapfd(std::move(dst_ptr_or_mapfd), std::move(src_interval),
                        bin.op, reg, bin.dst.v);
            }
            break;
        }
        default: {
            m_registers -= bin.dst.v;
            break;
        }
    }
    return interval_t::bottom();
}

void region_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc) {

    int width = b.access.width;
    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto it = m_registers.find(basereg.v);
    if (!it) {
        std::string s = std::to_string(static_cast<unsigned int>(basereg.v));
        std::string desc = std::string("\tloading from an unknown pointer, or from number - r") + s + "\n";
        //report_type_error(desc, loc);
        std::cout << desc;
        m_registers -= target_reg.v;
        return;
    }
    auto type_basereg = it.value();

    if (!std::holds_alternative<ptr_with_off_t>(type_basereg)
            || std::get<ptr_with_off_t>(type_basereg).get_region() == crab::region_t::T_SHARED) {
        // loading from either packet, shared region or mapfd does not happen in region domain
        m_registers -= target_reg.v;
        return;
    }

    auto type_with_off = std::get<ptr_with_off_t>(type_basereg);
    auto p_offset = type_with_off.get_offset();
    auto offset_singleton = p_offset.singleton();

    switch (type_with_off.get_region()) {
        case crab::region_t::T_STACK: {
            if (!offset_singleton) {
                for (auto const& k : m_stack.get_keys()) {
                    auto start = p_offset.lb();
                    auto end = p_offset.ub()+bound_t(offset+width);
                    if (bound_t((int)k) >= start && bound_t((int)k) < end) {
                        std::cout <<
                            "stack load at unknown offset, and offset range contains pointers\n";
                        break;
                    }
                }
                m_registers -= target_reg.v;
            }
            else {
                auto ptr_offset = offset_singleton.value();
                auto load_at = (uint64_t)(ptr_offset + offset);

                auto it = m_stack.find(load_at);

                if (!it) {
                    // no field at loaded offset in stack
                    m_registers -= target_reg.v;
                    return;
                }
                auto type_loaded = it.value();

                auto reg = reg_with_loc_t(target_reg.v, loc);
                m_registers.insert(target_reg.v, reg, type_loaded.first);
            }
            break;
        }
        case crab::region_t::T_CTX: {

            if (!offset_singleton) {
                for (auto const& k : m_ctx->get_keys()) {
                    auto start = p_offset.lb();
                    auto end = p_offset.ub()+bound_t(offset+width);
                    if (bound_t((int)k) >= start && bound_t((int)k) < end) {
                        std::cout <<
                            "ctx load at unknown offset, and offset range contains pointers\n";
                        break;
                    }
                }
                m_registers -= target_reg.v;
            }
            else {
                auto ptr_offset = offset_singleton.value();
                auto load_at = (uint64_t)(ptr_offset + offset);
                auto it = m_ctx->find(load_at);

                if (!it) {
                    // no field at loaded offset in ctx
                    m_registers -= target_reg.v;
                    return;
                }
                ptr_no_off_t type_loaded = it.value();

                auto reg = reg_with_loc_t(target_reg.v, loc);
                m_registers.insert(target_reg.v, reg, type_loaded);
            }
            break;
        }

        default: {
            assert(false);
        }
    }
}

void region_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc) {

    int offset = b.access.offset;
    Reg basereg = b.access.basereg;
    int width = b.access.width;

    // TODO: move generic checks to type domain
    auto maybe_basereg_type = m_registers.find(basereg.v);
    if (!maybe_basereg_type) {
        std::string s = std::to_string(static_cast<unsigned int>(basereg.v));
        std::string desc = std::string("\tstoring at an unknown pointer, or from number - r") + s + "\n";
        //report_type_error(desc, loc);
        std::cout << desc;
        return;
    }
    auto basereg_type = maybe_basereg_type.value();
    auto targetreg_type = m_registers.find(target_reg.v);

    if (std::holds_alternative<ptr_with_off_t>(basereg_type)) {
        // base register is either CTX_P, STACK_P or SHARED_P
        auto basereg_type_with_off = std::get<ptr_with_off_t>(basereg_type);

        if (basereg_type_with_off.get_region() == crab::region_t::T_STACK) {
            auto offset_singleton = basereg_type_with_off.get_offset().singleton();
            if (!offset_singleton) {
                std::cout << "type error: storing to a pointer with unknown offset\n";
                return;
            }
            auto store_at = (uint64_t)offset+(uint64_t)offset_singleton.value();
            // type of basereg is STACK_P
            auto overlapping_cells = m_stack.find_overlapping_cells(store_at, width);
            m_stack -= overlapping_cells;

            // if targetreg_type is empty, we are storing a number
            if (!targetreg_type) return;

            auto type_to_store = targetreg_type.value();
            m_stack.store(store_at, type_to_store, width);
        }
        else if (basereg_type_with_off.get_region() == crab::region_t::T_CTX) {
            // type of basereg is CTX_P
            if (targetreg_type) {
                std::string s = std::to_string(static_cast<unsigned int>(target_reg.v));
                std::string desc = std::string("\twe cannot store a pointer, r") + s + ", into ctx\n";
                // report_type_error(desc, loc);
                std::cout << desc;
                return;
            }
        }
        else {
            // type of basereg is SHARED_P
            if (targetreg_type) std::cout << "\twe cannot store a pointer into shared\n";
        }
    }
    else if (std::holds_alternative<ptr_no_off_t>(basereg_type)) {
        // base register type is a PACKET_P
        if (targetreg_type) {
            std::string s = std::to_string(static_cast<unsigned int>(target_reg.v));
            std::string desc = std::string("\twe cannot store a pointer, r") + s + ", into packet\n";
            //report_type_error(desc, loc);
            std::cout << desc;
            return;
        }
    }
    else {
        std::cout << "\twe cannot store a pointer into a mapfd\n";
        return;
    }
}


bool region_domain_t::is_stack_pointer(register_t reg) const {
    auto type = m_registers.find(reg);
    if (!type) {    // not a pointer
        return false;
    }
    auto ptr_or_mapfd_type = type.value();
    return (std::holds_alternative<ptr_with_off_t>(ptr_or_mapfd_type) &&
            std::get<ptr_with_off_t>(ptr_or_mapfd_type).get_region() == crab::region_t::T_STACK);
}

void region_domain_t::adjust_bb_for_types(location_t loc) {
    m_registers.adjust_bb_for_registers(loc);
}

void region_domain_t::print_all_register_types() const {
    m_registers.print_all_register_types();
}
