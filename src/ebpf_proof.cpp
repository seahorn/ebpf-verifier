// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "ebpf_proof.hpp"

type_domain_t get_post(const label_t& node, types_table_t& t)
{
    auto it = t.find(node);
    if (it != t.end()) {
        std::cout << "type information is not available for basic block\n";
        exit(0);
    }
    return it->second;
}

type_domain_t join_all_prevs(const label_t& node, types_table_t& t, const cfg_t& cfg) {
    type_domain_t type;
    for (const label_t& prev : cfg.prev_nodes(node)) {
        // rather than join, it just assigns the type domain of previous basic block; should work for no branch examples
        type = get_post(prev, t);
    }
    return type;
}

bool ebpf_generate_proof(std::ostream& s, const InstructionSeq& prog, const program_info& info,
                         const ebpf_verifier_options_t* options, const crab_results& results) {

    ctx_t ctx(info.type.context_descriptor);

    types_table_t types_table;

    if (!results.pass_verify()) {
        // If the program is not correct then we cannot generate a proof
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

    type_domain_t type = type_domain_t::setup_entry(ctx.packet_ptrs);

    auto labels = results.cfg.labels();
    for (auto& label : labels)
    {
        if (label != results.cfg.entry_label()) {
            type = join_all_prevs(label, types_table, results.cfg);
        }
        auto& bb = results.cfg.get_node(label);
        type(bb);

        types_table.insert(std::make_pair(label, type));
    }

    return false;
}
