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


type_domain_t join_all_prevs(const label_t& node, types_table_t& t, const cfg_t& cfg) {
    type_domain_t res = type_domain_t::bottom();
    for (const label_t& prev : cfg.prev_nodes(node)) {
        res = res | get_post(prev, t);
    }
    return res;
}

// no branches - no type error
void test1(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block2 >> block3;
    block3 >> block4;
    block4 >> exit;
}

// branches - no type error
void test2(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// branches - no type error - stack load only on one branch
void test3(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// branches - no type error - one branch does not assign certain registers as other, but they are not needed after join
void test4(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// branches - no error - more than two stores at the same location in stack
void test5(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{2}, .is_load = false});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{3}, .is_load = false});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{2}, .is_load = false});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{3}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{3}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{2}, .is_load = false});
    block3.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{3}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{2}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = true});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// no branches - assigning an unknown pointer or a number
void test6(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{5}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block2 >> block3;
    block3 >> block4;
    block4 >> exit;
}

// no branches - loading from an unknown pointer or a number
void test7(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{5}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{5}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block2 >> block3;
    block3 >> block4;
    block4 >> exit;
}

// branches - load from an unknown pointer after join
void test8(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{10}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{4}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// no branches - load from packet pointer
void test9(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{4}, .offset=0}, .value = Reg{5}, .is_load = true});
    block4.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{5}, .is64 = true});

    entry >> block1;
    block1 >> block2;
    block2 >> block3;
    block3 >> block4;
    block4 >> exit;
}

// branches - no field at loaded offset in stack
void test10(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{6}, .is_load = true});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// no branches - no field at loaded offset in context
void test11(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=8}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block2 >> block3;
    block3 >> block4;
    block4 >> exit;
}

// no branches - storing at an unknown pointer or a number
void test12(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{5}, .offset=-4}, .value = Reg{2}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{5}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block2 >> block3;
    block3 >> block4;
    block4 >> exit;
}

// branches - storing an unknown pointer or a number
void test13(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{7}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// branches - cannot store stack pointers into stack
void test14(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{10}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{10}, .is64 = true});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// branches - cannot store a pointer into a packet
void test15(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{2}, .offset=0}, .value = Reg{1}, .is_load = false});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// branches - cannot store a pointer into context
void test16(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{6}, .offset=0}, .value = Reg{3}, .is_load = false});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// branches - type being stored is not the same as already in stack at specific offset
void test17(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{3}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{2}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{1}, .is_load = false});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// no branches - loading to a number
void test18(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Imm{3}, .is_load = true});
    block2.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Reg{2}, .is64 = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{4}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block2 >> block3;
    block3 >> block4;
    block4 >> exit;
}

// branches - storing a number
void test19(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = false});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Imm{6}, .is_load = false});
    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block2 >> block4;
    block3 >> block4;
    block4 >> exit;
}

// join more than two branches - no type error (stack stores on two of the branches, not all, which should be fine)
void test20(cfg_t& cfg) {

    basic_block_t& entry = cfg.get_node(label_t::entry);
    basic_block_t& block1 = cfg.get_node(label_t(1));
    basic_block_t& block2 = cfg.get_node(label_t(2));
    basic_block_t& block3 = cfg.get_node(label_t(3));
    basic_block_t& block4 = cfg.get_node(label_t(4));
    basic_block_t& block5 = cfg.get_node(label_t(5));
    basic_block_t& block6 = cfg.get_node(label_t(6));
    basic_block_t& block7 = cfg.get_node(label_t(7));
    basic_block_t& exit = cfg.get_node(label_t::exit);

    block1.insert(Bin{.op = Bin::Op::MOV, .dst = Reg{6}, .v = Reg{1}, .is64 = true});

    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block2.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{3}, .is_load = false});

    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});
    block3.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{6}, .is_load = false});

    block5.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block5.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{3}, .is_load = false});

    block4.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=0}, .value = Reg{2}, .is_load = true});

    block6.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{6}, .is_load = false});
    block6.insert(Mem{.access = Deref{.width=4, .basereg=Reg{1}, .offset=4}, .value = Reg{3}, .is_load = true});
    block6.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{3}, .is_load = false});

    block7.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-8}, .value = Reg{7}, .is_load = true});
    block7.insert(Mem{.access = Deref{.width=4, .basereg=Reg{10}, .offset=-4}, .value = Reg{6}, .is_load = true});

    entry >> block1;
    block1 >> block2;
    block1 >> block3;
    block1 >> block4;
    block2 >> block7;
    block3 >> block5;
    block4 >> block6;
    block5 >> block7;
    block6 >> block7;
    block7 >> exit;
}

TEST_CASE("check-types", "[types]") {
    cfg_t cfg;
    types_table_t types_table;

    for (int i = 1; i <= 4; i++) {
        cfg.insert(label_t(i));
    }

    // tests 1-20; test one at a time

    test1(cfg);     // no branches - no type error
    //test2(cfg);     // branches - no type error
    //test3(cfg);     // branches - no type error - stack load only on one branch
    //test4(cfg);     // branches - no type error - one branch does not assign certain registers as other, but they are not needed after join
    //test5(cfg);     // branches - no error - more than two stores at the same location in stack
    //test6(cfg);     // no branches - assigning an unknown pointer or a number
    //test7(cfg);     // no branches - loading from an unknown pointer or a number
    //test8(cfg);     // branches - load from an unknown pointer after join
    //test9(cfg);     // no branches - load from packet pointer
    //test10(cfg);    // branches - no field at loaded offset in stack
    //test11(cfg);    // no branches - no field at loaded offset in context
    //test12(cfg);    // no branches - storing at an unknown pointer or a number
    //test13(cfg);    // branches - storing an unknown pointer or a number
    //test14(cfg);    // branches - cannot store stack pointers into stack
    //test15(cfg);    // branches - cannot store a pointer into a packet
    //test16(cfg);    // branches - cannot store a pointer into contex
    //test17(cfg);    // branches - type being stored is not the same as already in stack at specific offset
    //test18(cfg);    // no branches - loading to a number
    //test19(cfg);    // branches - storing a number

    // for test20, we need extra cfg nodes added below
/*
    for (int i = 5; i <= 7; i++) {
        cfg.insert(label_t(i));
    }
    test20(cfg);    // joining more than two branches - no type error (stack stores on two of the branches, not all, which should be fine)
*/

    std::cout << cfg << "\n";

    type_domain_t type = type_domain_t::setup_entry();

    auto labels = cfg.labels();
    for (auto& label : labels)
    {
        if (label != cfg.entry_label()) {
            type = join_all_prevs(label, types_table, cfg);
        }
        auto& bb = cfg.get_node(label);
        type(bb);

        types_table.insert(std::make_pair(label, type));
    }
    REQUIRE(true);
}
