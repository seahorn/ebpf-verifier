// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab_verifier.hpp"
#include "crab/type_domain.hpp"

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
