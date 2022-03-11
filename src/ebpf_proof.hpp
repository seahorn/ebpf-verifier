// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab_verifier.hpp"
#include "crab/type_domain.hpp"

using types_table_t = std::map<label_t, type_domain_t>;

using offset_to_ptr_t = std::unordered_map<int, crab::ptr_no_off_t>;

struct ctx_t {
    offset_to_ptr_t packet_ptrs;

    ctx_t(const ebpf_context_descriptor_t* desc)
    {
        packet_ptrs.insert(std::make_pair(desc->data, crab::ptr_no_off_t(crab::region::T_PACKET)));
        packet_ptrs.insert(std::make_pair(desc->end, crab::ptr_no_off_t(crab::region::T_PACKET)));
    }
};

type_domain_t join_all_prevs(const label_t& label);

// - prog is a prevail representation of the eBPF program
// - results contains the Crab CFG together with the inferred invariants
//
// Return true if proof is generated.
//
// TODO: we need to return also a proof object. We could take prog is
// a non-const reference and add the types (i.e., our proof) as debug
// symbols or metadata. However, note that InstructionSeq is a prevail
// thing. Ultimately, we want to annotate eBPF bytecode with types.
bool ebpf_generate_proof(std::ostream& s, const InstructionSeq& prog, const program_info& info,
                         const ebpf_verifier_options_t* options, const crab_results& results);
