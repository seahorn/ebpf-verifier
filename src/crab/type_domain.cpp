// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <unordered_map>

#include "crab/type_domain.hpp"

using crab::___print___;
using crab::ptr_t;
using crab::ptr_with_off_t;
using crab::ptr_no_off_t;
using crab::ctx_t;
using crab::global_type_env_t;
using crab::reg_with_loc_t;
using crab::live_registers_t;
using crab::register_types_t;

static std::string size(int w) { return std::string("u") + std::to_string(w * 8); }


namespace std {
    template <>
    struct hash<crab::reg_with_loc_t> {
        size_t operator()(const crab::reg_with_loc_t& reg) const { return reg.hash(); }
    };

    // does not seem to work for me
    template <>
    struct equal_to<crab::ptr_t> {
        constexpr bool operator()(const crab::ptr_t& p1, const crab::ptr_t& p2) const {
            if (p1.index() != p2.index()) return false;
            if (std::holds_alternative<crab::ptr_no_off_t>(p1)) {
                auto ptr_no_off1 = std::get<crab::ptr_no_off_t>(p1);
                auto ptr_no_off2 = std::get<crab::ptr_no_off_t>(p2);
                return (ptr_no_off1.r == ptr_no_off2.r);
            }
            else {
                auto ptr_with_off1 = std::get<crab::ptr_with_off_t>(p1);
                auto ptr_with_off2 = std::get<crab::ptr_with_off_t>(p2);
                return (ptr_with_off1.r == ptr_with_off2.r && ptr_with_off1.offset == ptr_with_off2.offset);
            }
        }
    };
}


void print_ptr_type(const ptr_t& p) {
    if (std::holds_alternative<ptr_with_off_t>(p)) {
        auto t = std::get<ptr_with_off_t>(p);
        std::cout << t;
    }
    else {
        auto t = std::get<ptr_no_off_t>(p);
        std::cout << t;
    }
}

void print_type(register_t r, const ptr_t& p) {
    std::cout << "r" << static_cast<unsigned int>(r) << " : ";
    print_ptr_type(p);
}

void print_annotated(Mem const& b, const ptr_t& p, std::ostream& os_) {
    if (b.is_load) {
        os_ << "  ";
        print_type(std::get<Reg>(b.value).v, p);
        os_ << " = ";
    }
    std::string sign = b.access.offset < 0 ? " - " : " + ";
    int offset = std::abs(b.access.offset);
    os_ << "*(" << size(b.access.width) << " *)";
    os_ << "(" << b.access.basereg << sign << offset << ")\n";
}

void print_annotated(Call const& call, const ptr_t& p, std::ostream& os_) {
    os_ << "  ";
    print_type(0, p);
    os_ << " = " << call.name << ":" << call.func << "(...)\n";
}

namespace crab {

inline std::string get_reg_ptr(const region& r) {
    switch (r) {
        case region::T_CTX:
            return "ctx_p";
        case region::T_STACK:
            return "stack_p";
        case region::T_PACKET:
            return "packet_p";
        default:
            return "shared_p";
    }
}

inline std::ostream& operator<<(std::ostream& o, const region& t) {
    o << static_cast<std::underlying_type<region>::type>(t);
    return o;
}

bool operator==(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
    return (p1.r == p2.r && p1.offset == p2.offset);
}

bool operator!=(const ptr_with_off_t& p1, const ptr_with_off_t& p2) {
    return !(p1 == p2);
}

std::ostream& operator<<(std::ostream& o, const ptr_with_off_t& p) {
    o << get_reg_ptr(p.r) << "<" << p.offset << ">";
    return o;
}

bool operator==(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
    return (p1.r == p2.r);
}

bool operator!=(const ptr_no_off_t& p1, const ptr_no_off_t& p2) {
    return !(p1 == p2);
}

std::ostream& operator<<(std::ostream& o, const ptr_no_off_t& p) {
    return o << get_reg_ptr(p.r);
}

std::ostream& operator<<(std::ostream& o, const reg_with_loc_t& reg) {
    o << "r" << static_cast<unsigned int>(reg.r) << "@" << reg.loc->second << " in " << reg.loc->first << " ";
    return o;
}

bool reg_with_loc_t::operator==(const reg_with_loc_t& other) const {
    return (r == other.r && loc == other.loc);
}

std::size_t reg_with_loc_t::hash() const {
    // Similar to boost::hash_combine
    using std::hash;

    std::size_t seed = hash<register_t>()(r);
    seed ^= hash<int>()(loc->first.from) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= hash<int>()(loc->first.to) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= hash<int>()(loc->second) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

    return seed;
}

std::ostream& operator<<(std::ostream& o, const stack_t& st) {
    o << "Stack: ";
    if (st.is_bottom())
        o << "_|_\n";
    else {
        o << "{";
        for (auto s : st.m_ptrs) {
            o << s.first << ": ";
            print_ptr_type(s.second);
            o << ", ";
        }
        o << "}";
    }
    return o;
}

std::ostream& operator<<(std::ostream& o, const ctx_t& _ctx) {

    o << "type of context: " << (_ctx.m_packet_ptrs.empty() ? "_|_" : "") << "\n";
    for (const auto& it : _ctx.m_packet_ptrs) {
        o << "  stores at " << it.first << ": " << it.second << "\n";
    }
    return o;
}

ctx_t::ctx_t(const ebpf_context_descriptor_t* desc)
{
    if (desc->data != -1)
        m_packet_ptrs[desc->data] = crab::ptr_no_off_t(crab::region::T_PACKET);
    if (desc->end != -1)
        m_packet_ptrs[desc->end] = crab::ptr_no_off_t(crab::region::T_PACKET);
}

std::optional<ptr_no_off_t> ctx_t::find(int key) const {
    auto it = m_packet_ptrs.find(key);
    if (it == m_packet_ptrs.end()) return {};
    return it->second;
}


std::ostream& operator<<(std::ostream& o, const register_types_t& typ) {
    if (typ.is_bottom())
        o << "_|_\n";
    else {
        for (const auto& v : *(typ.m_all_types)) {
            o << v.first << ": ";
            print_ptr_type(v.second);
            o << "\n";
        }
    }
    return o;
}

register_types_t register_types_t::operator|(const register_types_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    live_registers_t out_vars;
    for (size_t i = 0; i < m_vars.size(); i++) {
        if (m_vars[i] == nullptr || other.m_vars[i] == nullptr) continue;
        auto it1 = find(*(m_vars[i]));
        auto it2 = other.find(*(other.m_vars[i]));
        if (it1 && it2 && it1.value() == it2.value()) {
            out_vars[i] = m_vars[i];
        }
    }

    return register_types_t(std::move(out_vars), m_all_types, false);
}

void register_types_t::operator-=(register_t var) {
    if (is_bottom()) {
        return;
    }
    m_vars[var] = nullptr;
}

void register_types_t::set_to_bottom() {
    m_vars = live_registers_t{nullptr};
    m_is_bottom = true;
}

void register_types_t::set_to_top() {
    m_vars = live_registers_t{nullptr};
    m_is_bottom = false;
}

bool register_types_t::is_bottom() const { return m_is_bottom; }

bool register_types_t::is_top() const {
    if (m_is_bottom) { return false; }
    if (m_all_types == nullptr) return true;
    for (auto it : m_vars) {
        if (it != nullptr) return false;
    }
    return true;
}

void register_types_t::insert(register_t reg, const reg_with_loc_t& reg_with_loc, const ptr_t& type) {
    (*m_all_types)[reg_with_loc] = type;
    m_vars[reg] = std::make_shared<reg_with_loc_t>(reg_with_loc);
}

std::optional<ptr_t> register_types_t::find(reg_with_loc_t reg) const {
    auto it = m_all_types->find(reg);
    if (it == m_all_types->end()) return {};
    return it->second;
}

std::optional<ptr_t> register_types_t::find(register_t key) const {
    if (m_vars[key] == nullptr) return {};
    const reg_with_loc_t& reg = *(m_vars[key]);
    return find(reg);
}

stack_t stack_t::operator|(const stack_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    } else if (other.is_bottom() || is_top()) {
        return *this;
    }
    offset_to_ptr_t out_ptrs;
    for (auto const&kv: m_ptrs) {
        auto it = other.find(kv.first);
        if (it && kv.second == it.value())
            out_ptrs.insert(kv);
    }
    return stack_t(std::move(out_ptrs), false);
}

void stack_t::operator-=(int key) {
    auto it = find(key);
    if (it)
        m_ptrs.erase(key);
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

void stack_t::insert(int key, ptr_t value) {
    m_ptrs[key] = value;
}

std::optional<ptr_t> stack_t::find(int key) const {
    auto it = m_ptrs.find(key);
    if (it == m_ptrs.end()) return {};
    return it->second;
}

}

bool type_domain_t::is_bottom() const {
    return (m_stack.is_bottom() || m_types.is_bottom());
}

bool type_domain_t::is_top() const {
    return (m_stack.is_top() && m_types.is_top());
}

type_domain_t type_domain_t::bottom() {
    type_domain_t typ;
    typ.set_to_bottom();
    return typ;
}

void type_domain_t::set_to_bottom() {
    m_types.set_to_bottom();
}

void type_domain_t::set_to_top() {
    m_stack.set_to_top();
    m_types.set_to_top();
}

bool type_domain_t::operator<=(const type_domain_t& abs) const {
    return true;
}

void type_domain_t::operator|=(const type_domain_t& abs) {
    type_domain_t tmp{abs};
    operator|=(std::move(tmp));
}

void type_domain_t::operator|=(type_domain_t&& abs) {
    if (is_bottom()) {
        *this = abs;
        return;
    }
    *this = *this | std::move(abs);
}

type_domain_t type_domain_t::operator|(const type_domain_t& other) const {
    if (is_bottom() || other.is_top()) {
        return other;
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_types | other.m_types, m_stack | other.m_stack, other.m_ctx);
}

type_domain_t type_domain_t::operator|(type_domain_t&& other) const {
    if (is_bottom() || other.is_top()) {
        return std::move(other);
    }
    else if (other.is_bottom() || is_top()) {
        return *this;
    }
    return type_domain_t(m_types | std::move(other.m_types), m_stack | std::move(other.m_stack), other.m_ctx);
}

type_domain_t type_domain_t::operator&(const type_domain_t& abs) const {
    return abs;
}

type_domain_t type_domain_t::widen(const type_domain_t& abs) const {
    return abs;
}

type_domain_t type_domain_t::narrow(const type_domain_t& other) const {
    return other;
}

void type_domain_t::write(std::ostream& os) const { 
    os << m_types;
    os << m_stack << "\n";
}

std::string type_domain_t::domain_name() const {
    return "type_domain";
}

crab::bound_t type_domain_t::get_instruction_count_upper_bound() {
    return crab::bound_t(crab::number_t(0));
}

string_invariant type_domain_t::to_set() {
    return string_invariant{};
}

void type_domain_t::operator()(const Undefined & u, location_t loc) {
    std::cout << "  " << u << ";\n";
}
void type_domain_t::operator()(const Un &u, location_t loc) {
    std::cout << "  " << u << ";\n";
}
void type_domain_t::operator()(const LoadMapFd &u, location_t loc) {
    std::cout << "  " << u << ";\n";
    m_types -= u.dst.v;
}
void type_domain_t::operator()(const Call &u, location_t loc) {
    register_t r0_reg{R0_RETURN_VALUE};
    if (u.is_map_lookup) {
        auto r0 = reg_with_loc_t(r0_reg, loc);
        auto type = ptr_no_off_t(crab::region::T_SHARED);
        m_types.insert(r0_reg, r0, type);
        print_annotated(u, type, std::cout);
    }
    else {
        m_types -= r0_reg;
        std::cout << "  " << u << ";\n";
    }
}
void type_domain_t::operator()(const Exit &u, location_t loc) {
    std::cout << "  " << u << ";\n";
}
void type_domain_t::operator()(const Jmp &u, location_t loc) {
    std::cout << "  " << u << ";\n";
}
void type_domain_t::operator()(const Packet & u, location_t loc) {
    std::cout << "  " << u << ";\n";
    //CRAB_ERROR("type_error: loading from packet region not allowed");
    m_types -= register_t{0};
}
void type_domain_t::operator()(const LockAdd &u, location_t loc) {
    std::cout << "  " << u << ";\n";
}
void type_domain_t::operator()(const Assume &u, location_t loc) {
    std::cout << "  " << u << ";\n";
}
void type_domain_t::operator()(const Assert &u, location_t loc) {
    std::cout << "  " << u << ";\n";
}

void print_info() {
    std::cout << "\nhow to interpret:\n";
    std::cout << "  packet_p = packet pointer\n";
    std::cout << "  shared_p = shared pointer\n";
    std::cout << "  stack_p<n> = stack pointer at offset n\n";
    std::cout << "  ctx_p<n> = context pointer at offset n\n";
    std::cout << "  'context = _|_' means context contains no elements stored\n";
    std::cout << "  when invoked with print invariants option\n";
    std::cout << "      'r@n in bb : p_type' means register 'r' in basic block 'bb' at offset 'n' has type 'p_type'\n\n";
    std::cout << "**************************************************************\n\n";
}

type_domain_t type_domain_t::setup_entry() {

    print_info();

    std::shared_ptr<ctx_t> ctx = std::make_shared<ctx_t>(global_program_info.get().type.context_descriptor);
    std::shared_ptr<global_type_env_t> all_types = std::make_shared<global_type_env_t>();

    std::cout << *ctx << "\n";

    live_registers_t vars;
    register_types_t typ(std::move(vars), all_types);

    auto r1 = reg_with_loc_t(R1_ARG, std::make_pair(label_t::entry, static_cast<unsigned int>(0)));
    auto r10 = reg_with_loc_t(R10_STACK_POINTER, std::make_pair(label_t::entry, static_cast<unsigned int>(0)));

    typ.insert(R1_ARG, r1, ptr_with_off_t(crab::region::T_CTX, 0));
    typ.insert(R10_STACK_POINTER, r10, ptr_with_off_t(crab::region::T_STACK, 512));

    std::cout << "Initial register types:\n";
    auto it = typ.find(R1_ARG);
    if (it) {
        std::cout << "  ";
        print_type(R1_ARG, it.value());
        std::cout << "\n";
    }
    auto it2 = typ.find(R10_STACK_POINTER);
    if (it2) {
        std::cout << "  ";
        print_type(R10_STACK_POINTER, it2.value());
        std::cout << "\n";
    }
    std::cout << "\n";

    type_domain_t inv(std::move(typ), crab::stack_t::top(), ctx);
    return inv;
}

void type_domain_t::operator()(const Bin& bin, location_t loc) {
    if (std::holds_alternative<Reg>(bin.v)) {
        Reg src = std::get<Reg>(bin.v);
        switch (bin.op)
        {
            case Bin::Op::MOV: {
                auto it = m_types.find(src.v);
                if (!it) {
                    //std::cout << "  " << bin << "\n";
                    //CRAB_ERROR("type error: assigning an unknown pointer or a number - r", (int)src.v);
                    m_types -= bin.dst.v;
                    break;
                }

                auto reg = reg_with_loc_t(bin.dst.v, loc);
                m_types.insert(bin.dst.v, reg, it.value());
                break;
            }

            default:
                m_types -= bin.dst.v;
                break;
        }
    }
    else {
        m_types -= bin.dst.v;
    }
    std::cout << "  " << bin << ";\n";
}

void type_domain_t::do_load(const Mem& b, const Reg& target_reg, location_t loc) {

    int offset = b.access.offset;
    Reg basereg = b.access.basereg;

    auto it = m_types.find(basereg.v);
    if (!it) {
        std::cout << "  " << b << "\n";
        CRAB_ERROR("type_error: loading from an unknown pointer, or from number - r", (int)basereg.v);
    }
    ptr_t type_basereg = it.value();

    if (std::holds_alternative<ptr_no_off_t>(type_basereg)) {
        std::cout << "  " << b << "\n";
        //CRAB_ERROR("type_error: loading from either packet or shared region not allowed - r", (int)basereg.v);
        m_types -= target_reg.v;
        return;
    }

    ptr_with_off_t type_with_off = std::get<ptr_with_off_t>(type_basereg);
    int load_at = offset+type_with_off.offset;

    switch (type_with_off.r) {
        case crab::region::T_STACK: {

            auto it = m_stack.find(load_at);

            if (!it) {
                std::cout << "  " << b << "\n";
                //CRAB_ERROR("type_error: no field at loaded offset ", load_at, " in stack");
                m_types -= target_reg.v;
                return;
            }
            ptr_t type_loaded = it.value();

            if (std::holds_alternative<ptr_with_off_t>(type_loaded)) {
                ptr_with_off_t type_loaded_with_off = std::get<ptr_with_off_t>(type_loaded);
                auto reg = reg_with_loc_t(target_reg.v, loc);
                m_types.insert(target_reg.v, reg, type_loaded_with_off);
                print_annotated(b, type_loaded_with_off, std::cout);
            }
            else {
                ptr_no_off_t type_loaded_no_off = std::get<ptr_no_off_t>(type_loaded);
                auto reg = reg_with_loc_t(target_reg.v, loc);
                m_types.insert(target_reg.v, reg, type_loaded_no_off);
                print_annotated(b, type_loaded_no_off, std::cout);
            }

            break;
        }
        case crab::region::T_CTX: {

            auto it = m_ctx->find(load_at);

            if (!it) {
                std::cout << "  " << b << "\n";
                //CRAB_ERROR("type_error: no field at loaded offset ", load_at, " in context");
                m_types -= target_reg.v;
                return;
            }
            ptr_no_off_t type_loaded = it.value();

            auto reg = reg_with_loc_t(target_reg.v, loc);
            m_types.insert(target_reg.v, reg, type_loaded);
            print_annotated(b, type_loaded, std::cout);
            break;
        }

        default: {
            assert(false);
        }
    }
}

void type_domain_t::do_mem_store(const Mem& b, const Reg& target_reg, location_t loc) {

    std::cout << "  " << b << ";\n";
    int offset = b.access.offset;
    Reg basereg = b.access.basereg;
    int width = b.access.width;

    auto it = m_types.find(basereg.v);
    if (!it) {
        CRAB_ERROR("type_error: storing at an unknown pointer, or from number - r", (int)basereg.v);
    }
    ptr_t type_basereg = it.value();

    auto it2 = m_types.find(target_reg.v);

    if (std::holds_alternative<ptr_with_off_t>(type_basereg)) {
        // we know base register is either CTX_P or STACK_P
        ptr_with_off_t type_basereg_with_off = std::get<ptr_with_off_t>(type_basereg);

        int store_at = offset+type_basereg_with_off.offset;
        if (type_basereg_with_off.r == crab::region::T_STACK) {
            // type of basereg is STACK_P
            if (!it2) {
                //CRAB_ERROR("type_error: storing either a number or an unknown pointer - r", (int)target_reg.v);
                m_stack -= store_at;
                return;
            }
            else {
                auto type_to_store = it2.value();
                if (std::holds_alternative<ptr_with_off_t>(type_to_store) &&
                        std::get<ptr_with_off_t>(type_to_store).r == crab::region::T_STACK) {
                    CRAB_ERROR("type_error: we cannot store stack pointer, r", (int)target_reg.v, ", into stack");
                }
                else {
                    for (auto i = store_at; i < store_at+width; i++) {
                        auto it3 = m_stack.find(i);
                        if (it3) {
                            CRAB_ERROR("type_error: type being stored into stack at ", store_at, " is overlapping with already stored\
                            at", i);
                        }
                    }
                    auto it4 = m_stack.find(store_at);
                    if (it4) {
                        auto type_in_stack = it4.value();
                        if (type_to_store != type_in_stack) {
                            CRAB_ERROR("type_error: type being stored at offset ", store_at, " is not the same as stored already in stack");
                        }
                    }
                    else {
                        m_stack.insert(store_at, type_to_store);
                    }
                }
            }
        }
        else if (type_basereg_with_off.r == crab::region::T_CTX) {
            // type of basereg is CTX_P
            if (it2) {
                CRAB_ERROR("type_error: we cannot store pointer, r", (int)target_reg.v, ", into ctx");
            }
        }
        else
            assert(false);
    }
    else {
        // base register type is either PACKET_P or SHARED_P
        if (it2) {
            CRAB_ERROR("type_error: we cannot store pointer, r", (int)target_reg.v, ", into packet or shared");
        }
    }
}

void type_domain_t::operator()(const Mem& b, location_t loc) {

    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value), loc);
        } else {
            do_mem_store(b, std::get<Reg>(b.value), loc);
        }
    } else {
        CRAB_ERROR("Either loading to a number (not allowed) or storing a number (not allowed yet) - ", std::get<Imm>(b.value).v);
    }
}

void type_domain_t::operator()(const basic_block_t& bb, bool check_termination) {
    uint32_t curr_pos = 0;
    auto label = bb.label();
    std::cout << label << ":\n";
    for (const Instruction& statement : bb) {
        location_t loc = location_t(std::make_pair(label, ++curr_pos));
        std::visit([this, loc](const auto& v) { std::apply(*this, std::make_pair(v, loc)); }, statement);
    }
    auto [it, et] = bb.next_blocks();
    if (it != et) {
        std::cout << "  "
        << "goto ";
        for (; it != et;) {
            std::cout << *it;
            ++it;
            if (it == et) {
                std::cout << ";";
            } else {
                std::cout << ",";
            }
        }
    }
    std::cout << "\n\n";
}

void type_domain_t::set_require_check(check_require_func_t f) {}
