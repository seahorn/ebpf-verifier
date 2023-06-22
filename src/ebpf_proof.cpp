// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "ebpf_proof.hpp"

bool ebpf_generate_proof(std::ostream& s, const InstructionSeq& prog, const program_info& info,
                         const ebpf_verifier_options_t* options, const crab_results& results) {

    if (!results.pass_verify()) {
        // If the program is not correct then we cannot generate a proof
        std::cout << "Proof generation not implemented\n";
        return false;
    }

    /*
      The goal is to translate results.pre_invariants and
      results.post_invariants into types from our type system. For that,
      we will need first to define all the C++ types/classes needed for
      defining our type system (for pointer, checked_pointer, etc), and
      then the conversion.

      A type checker is not part of the proof but we should also
      implement it so that we can be sure that our types are correct.
     */

    return false;
}
