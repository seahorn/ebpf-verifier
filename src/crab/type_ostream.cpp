// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "crab/type_ostream.hpp"

void print_ptr_type(const crab::ptr_t& ptr) {
    if (std::holds_alternative<crab::ptr_with_off_t>(ptr)) {
        crab::ptr_with_off_t ptr_with_off = std::get<crab::ptr_with_off_t>(ptr);
        std::cout << ptr_with_off;
    }
    else {
        crab::ptr_no_off_t ptr_no_off = std::get<crab::ptr_no_off_t>(ptr);
        std::cout << ptr_no_off;
    }
}

void print_ptr_or_mapfd_type(const crab::ptr_or_mapfd_t& ptr_or_mapfd) {
    if (std::holds_alternative<crab::mapfd_t>(ptr_or_mapfd)) {
        std::cout << std::get<crab::mapfd_t>(ptr_or_mapfd);
    }
    else {
        auto ptr = get_ptr(ptr_or_mapfd);
        print_ptr_type(ptr);
    }
}

void print_register(Reg r, std::optional<crab::ptr_or_mapfd_t>& p) {
    std::cout << r << " : ";
    if (p) {
        print_ptr_or_mapfd_type(p.value());
    }
}

inline std::string size_(int w) { return std::string("u") + std::to_string(w * 8); }

void print_annotated(std::ostream& o, const Call& call, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(Reg{(uint8_t)R0_RETURN_VALUE}, p);
    o << " = " << call.name << ":" << call.func << "(...)\n";
}

void print_annotated(std::ostream& o, const Bin& b, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(b.dst, p);
    o << " " << b.op << "= " << b.v << "\n";
}

void print_annotated(std::ostream& o, const LoadMapFd& u, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(u.dst, p);
    o << " = map_fd " << u.mapfd << "\n";
}

void print_annotated(std::ostream& o, const Mem& b, std::optional<crab::ptr_or_mapfd_t>& p) {
    o << "  ";
    print_register(std::get<Reg>(b.value), p);
    o << " = ";
    std::string sign = b.access.offset < 0 ? " - " : " + ";
    int offset = std::abs(b.access.offset);
    o << "*(" << size_(b.access.width) << " *)";
    o << "(" << b.access.basereg << sign << offset << ")\n";
}

