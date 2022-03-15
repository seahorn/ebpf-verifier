// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "crab/type_domain.cpp"
#include "ebpf_proof.hpp"

using namespace crab;

using types_table_t = std::map<label_t, type_domain_t>;

type_domain_t get_post(const label_t& node, types_table_t& t)
{
    auto it = t.find(node);
    if (it == t.end()) {
        CRAB_ERROR("type information is not available for basic block");
    }
    return it->second;
}


type_domain_t get_prev(const label_t& node, types_table_t& t, const cfg_t& cfg) {
    auto rng = cfg.prev_nodes(node);
    return get_post(*(rng.begin()), t);
}


TEST_CASE("check-types", "[types]") {
    cfg_t cfg;
    types_table_t types_table;

    for (int i = 1; i <= 2; i++) {
        cfg.insert(label_t(i));
    }

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    entry.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block1.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block1.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{3}, .is_load = false});

    entry >> block1;
    block1 >> block2;
    block2 >> exit;

    std::cout << cfg << "\n";

    std::shared_ptr<types_t> types = std::make_shared<types_t>();
    update(types, reg_with_loc_t(R1_ARG, label_t::entry, -1), ptr_with_off_t(crab::region::T_CTX, 0));
    update(types, reg_with_loc_t(R10_STACK_POINTER, label_t::entry, -1), ptr_with_off_t(crab::region::T_STACK, 512));

    ebpf_context_descriptor_t context_descriptor{0, 0, 4, -1};
    std::shared_ptr<ctx_t> ctx = std::make_shared<ctx_t>(&context_descriptor);

    type_domain_t type = type_domain_t::setup_entry(ctx, types);

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
