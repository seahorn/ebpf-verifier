// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "string_constraints.hpp"
#include "asm_syntax.hpp"
#include "asm_ostream.hpp"
#include "crab/common.hpp"

void print_ptr_or_mapfd_type(const crab::ptr_or_mapfd_t&);
void print_ptr_type(const crab::ptr_t& ptr);
void print_register(Reg r, std::optional<crab::ptr_or_mapfd_t>& p);
void print_annotated(std::ostream& o, const Call& call, std::optional<crab::ptr_or_mapfd_t>& p);
void print_annotated(std::ostream& o, const Bin& b, std::optional<crab::ptr_or_mapfd_t>& p);
void print_annotated(std::ostream& o, const LoadMapFd& u, std::optional<crab::ptr_or_mapfd_t>& p);
void print_annotated(std::ostream& o, const Mem& b, std::optional<crab::ptr_or_mapfd_t>& p);
