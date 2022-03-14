// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "crab/type_domain.hpp"
#include "ebpf_proof.hpp"

using namespace crab;


type_domain_t get_post(const label_t& node, types_table_t& t)
{
    auto it = t.find(node);
    if (it == t.end()) {
        CRAB_ERROR("type information is not available for basic block");
    }
    return it->second;
}


type_domain_t get_prev(const label_t& node, types_table_t& t, const cfg_t& cfg) {
    type_domain_t type;
    auto rng = cfg.prev_nodes(node);
    return get_post(*(rng.begin()), t);
}


TEST_CASE("check-types", "[types]") {
    cfg_t cfg;
    types_table_t types_table;

    //for (int i = 1; i <= 3; i++) {
        cfg.insert(label_t(1));
    //}

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    entry.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block1.insert(Mem{.access = Deref{.width=4, .basereg=Reg{6}, .offset=0}, .value = Reg{2}, .is_load = true});
    block1.insert(Mem{.access = Deref{.width=4, .basereg=Reg{6}, .offset=4}, .value = Reg{3}, .is_load = true});
    exit.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{3}, .is_load = false});

    entry >> block1;
    block1 >> exit;

    ebpf_context_descriptor_t context_descriptor{0, 0, 4, -1};
    ctx_t ctx(&context_descriptor);
    type_domain_t type = type_domain_t::setup_entry(ctx.packet_ptrs);

    auto labels = cfg.labels();
    for (auto& label : labels)
    {
        if (label != cfg.entry_label()) {
            type = get_prev(label, types_table, cfg);
        }
        auto& bb = cfg.get_node(label);
        type(bb);

        types_table.insert(std::make_pair(label, type));
    }
    REQUIRE(true);
}
