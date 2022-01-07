// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab/fwd_analyzer.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

#include <set>
#include <map>

// Toy database to store invariants.
// Temporary moved here but it's better to hide it again in crab_verifier.cpp
struct checks_db final {
    std::map<label_t, std::vector<std::string>> m_db;
    int total_warnings{};
    int total_unreachable{};
    int max_instruction_count{};
    std::set<label_t> maybe_nonterminating;

    void add(const label_t& label, const std::string& msg) {
        m_db[label].emplace_back(msg);
    }

    void add_warning(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_warnings++;
    }

    void add_unreachable(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_unreachable++;
    }

    void add_nontermination(const label_t& label) {
        maybe_nonterminating.insert(label);
        total_warnings++;
    }

    checks_db() = default;
};

struct crab_results {
  crab::cfg_t cfg;
  crab::invariant_table_t pre_invariants;
  crab::invariant_table_t post_invariants;
  checks_db db;

  crab_results(cfg_t &&_cfg,
	       crab::invariant_table_t &&pre, crab::invariant_table_t &&post,
	       checks_db &&_db)
    : cfg(std::move(_cfg)),
      pre_invariants(std::move(pre)),
      post_invariants(std::move(post)),
      db(std::move(_db)) {}
  
  bool pass_verify() const {
    return db.total_warnings == 0;
  }
};

bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, const program_info& info, const ebpf_verifier_options_t* options,
    ebpf_verifier_stats_t* stats);

crab_results ebpf_verify_program(
    std::ostream& s,
    const InstructionSeq& prog,
    const program_info& info,
    const ebpf_verifier_options_t* options,
    ebpf_verifier_stats_t* stats);

using string_invariant_map = std::map<crab::label_t, string_invariant>;

std::tuple<string_invariant, bool> ebpf_analyze_program_for_test(std::ostream& os, const InstructionSeq& prog,
                                                                 const string_invariant& entry_invariant,
                                                                 const program_info& info,
                                                                 const ebpf_verifier_options_t& options);

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void ebpf_verifier_clear_thread_local_state();
