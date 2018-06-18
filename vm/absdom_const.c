#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include "ubpf_int.h"

#include "ubpf_vm_ai.h"

const struct abs_state abs_bottom = { { 0 }, { 0 } }; // second zero makes unknowns

void 
abs_initialize_state(struct abs_state *state, void* ctx, void* stack)
{
    for (int i = 0; i < 11; i++) {
        state->known[i] = false;
    }
    state->known[1] = true;
    state->reg[1] = (uint64_t)stack;

    state->known[10] = true;
    state->reg[10] = (uint64_t)ctx;
}

struct abs_state
abs_execute_assume(struct abs_state *_state, struct ebpf_inst inst, bool taken)
{
    struct abs_state res = *_state;
    struct abs_state* state = &res;
    // TODO: check feasibility; this might cause problems with pending.
    if ((taken && inst.opcode == EBPF_OP_JEQ_IMM)
    || (!taken && inst.opcode == EBPF_OP_JNE_IMM)) {
        state->known[inst.dst] = true;
        state->reg[inst.dst] = inst.imm;
    }
    if ((taken && inst.opcode == EBPF_OP_JEQ_REG)
    || (!taken && inst.opcode == EBPF_OP_JNE_REG)) {
        state->known[inst.dst] = true;
        state->reg[inst.dst] = state->reg[inst.src];
        // we don't track correlation
    }
    return res;
}

void
abs_join(struct abs_state *state, struct abs_state other)
{  
    for (int r = 1; r < 11; r++) {
        if (!other.known[r] || state->reg[r] != other.known[r])
            state->known[r] = false;
    }
}

static bool
bounds_check(void *addr, int size, void *mem, size_t mem_len, void *stack)
{
    if (mem && (addr >= mem && (addr + size) <= (mem + mem_len))) {
        /* Context access */
        return true;
    } else if (addr >= stack && (addr + size) <= (stack + STACK_SIZE)) {
        /* Stack access */
        return true;
    }
    return false;
}

static int
access_width(uint8_t opcode) {
    switch (opcode) {
    case EBPF_OP_LDXW: return 4;
    case EBPF_OP_LDXH: return 2;
    case EBPF_OP_LDXB: return 1;
    case EBPF_OP_LDXDW: return 8;
    case EBPF_OP_STW: return 4;
    case EBPF_OP_STH: return 2;
    case EBPF_OP_STB: return 1;
    case EBPF_OP_STDW: return 8;
    case EBPF_OP_STXW: return 4;
    case EBPF_OP_STXH: return 2;
    case EBPF_OP_STXB: return 1;
    case EBPF_OP_STXDW: return 8;
    default: return -100;
    }
}

bool
abs_bounds_check(struct abs_state *state, struct ebpf_inst inst) {
    return bounds_check((void *)state->reg[inst.src] + inst.offset, access_width(inst.opcode),
            (void*)state->reg[10], 4096, (void*)state->reg[1]);
}


static uint32_t
u32(uint64_t x)
{
    return x;
}


struct abs_state
abs_execute(struct abs_state *_state, struct ebpf_inst inst)
{
    struct abs_state res = *_state;
    struct abs_state* state = &res;
    if (!(inst.opcode & EBPF_CLS_ALU || inst.opcode & EBPF_CLS_ALU64))
        return res;

    if (inst.opcode & EBPF_SRC_REG && !state->known[inst.src]) {
        state->known[inst.dst] = false;
        return res;
    }

    if (!state->known[inst.dst]
        && inst.opcode != EBPF_OP_MOV64_IMM
        && inst.opcode != EBPF_OP_MOV64_REG
        && inst.opcode != EBPF_OP_MOV_IMM
        && inst.opcode != EBPF_OP_MOV_REG) {
        state->known[inst.dst] = false;
        return res;
    }

    state->known[inst.dst] = true;

    #define reg state->reg
    switch (inst.opcode) {
    case EBPF_OP_ADD_IMM:
        reg[inst.dst] += inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_ADD_REG:
        reg[inst.dst] += reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_SUB_IMM:
        reg[inst.dst] -= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_SUB_REG:
        reg[inst.dst] -= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MUL_IMM:
        reg[inst.dst] *= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MUL_REG:
        reg[inst.dst] *= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_DIV_IMM:
        reg[inst.dst] = u32(reg[inst.dst]) / u32(inst.imm);
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_DIV_REG:
        if (reg[inst.src] == 0) {
            fprintf(stderr, "uBPF error: division by zero\n");
            return res;
        }
        reg[inst.dst] = u32(reg[inst.dst]) / u32(reg[inst.src]);
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_OR_IMM:
        reg[inst.dst] |= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_OR_REG:
        reg[inst.dst] |= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_AND_IMM:
        reg[inst.dst] &= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_AND_REG:
        reg[inst.dst] &= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_LSH_IMM:
        reg[inst.dst] <<= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_LSH_REG:
        reg[inst.dst] <<= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_RSH_IMM:
        reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_RSH_REG:
        reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_NEG:
        reg[inst.dst] = -reg[inst.dst];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOD_IMM:
        reg[inst.dst] = u32(reg[inst.dst]) % u32(inst.imm);
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOD_REG:
        if (reg[inst.src] == 0) {
            fprintf(stderr, "uBPF error: division by zero\n");
            return res;
        }
        reg[inst.dst] = u32(reg[inst.dst]) % u32(reg[inst.src]);
        break;
    case EBPF_OP_XOR_IMM:
        reg[inst.dst] ^= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_XOR_REG:
        reg[inst.dst] ^= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOV_IMM:
        reg[inst.dst] = inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOV_REG:
        reg[inst.dst] = reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_ARSH_IMM:
        reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_ARSH_REG:
        reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
        reg[inst.dst] &= UINT32_MAX;
        break;

    case EBPF_OP_LE:
        if (inst.imm == 16) {
            reg[inst.dst] = htole16(reg[inst.dst]);
        } else if (inst.imm == 32) {
            reg[inst.dst] = htole32(reg[inst.dst]);
        } else if (inst.imm == 64) {
            reg[inst.dst] = htole64(reg[inst.dst]);
        }
        break;
    case EBPF_OP_BE:
        if (inst.imm == 16) {
            reg[inst.dst] = htobe16(reg[inst.dst]);
        } else if (inst.imm == 32) {
            reg[inst.dst] = htobe32(reg[inst.dst]);
        } else if (inst.imm == 64) {
            reg[inst.dst] = htobe64(reg[inst.dst]);
        }
        break;


    case EBPF_OP_ADD64_IMM:
        reg[inst.dst] += inst.imm;
        break;
    case EBPF_OP_ADD64_REG:
        reg[inst.dst] += reg[inst.src];
        break;
    case EBPF_OP_SUB64_IMM:
        reg[inst.dst] -= inst.imm;
        break;
    case EBPF_OP_SUB64_REG:
        reg[inst.dst] -= reg[inst.src];
        break;
    case EBPF_OP_MUL64_IMM:
        reg[inst.dst] *= inst.imm;
        break;
    case EBPF_OP_MUL64_REG:
        reg[inst.dst] *= reg[inst.src];
        break;
    case EBPF_OP_DIV64_IMM:
        reg[inst.dst] /= inst.imm;
        break;
    case EBPF_OP_DIV64_REG:
        if (reg[inst.src] == 0) {
            fprintf(stderr, "uBPF error: division by zero\n");
            return res;
        }
        reg[inst.dst] /= reg[inst.src];
        break;
    case EBPF_OP_OR64_IMM:
        reg[inst.dst] |= inst.imm;
        break;
    case EBPF_OP_OR64_REG:
        reg[inst.dst] |= reg[inst.src];
        break;
    case EBPF_OP_AND64_IMM:
        reg[inst.dst] &= inst.imm;
        break;
    case EBPF_OP_AND64_REG:
        reg[inst.dst] &= reg[inst.src];
        break;
    case EBPF_OP_LSH64_IMM:
        reg[inst.dst] <<= inst.imm;
        break;
    case EBPF_OP_LSH64_REG:
        reg[inst.dst] <<= reg[inst.src];
        break;
    case EBPF_OP_RSH64_IMM:
        reg[inst.dst] >>= inst.imm;
        break;
    case EBPF_OP_RSH64_REG:
        reg[inst.dst] >>= reg[inst.src];
        break;
    case EBPF_OP_NEG64:
        reg[inst.dst] = -reg[inst.dst];
        break;
    case EBPF_OP_MOD64_IMM:
        reg[inst.dst] %= inst.imm;
        break;
    case EBPF_OP_MOD64_REG:
        if (reg[inst.src] == 0) {
            fprintf(stderr, "uBPF error: division by zero\n");
            return res;
        }
        reg[inst.dst] %= reg[inst.src];
        break;
    case EBPF_OP_XOR64_IMM:
        reg[inst.dst] ^= inst.imm;
        break;
    case EBPF_OP_XOR64_REG:
        reg[inst.dst] ^= reg[inst.src];
        break;
    case EBPF_OP_MOV64_IMM:
        reg[inst.dst] = inst.imm;
        break;
    case EBPF_OP_MOV64_REG:
        reg[inst.dst] = reg[inst.src];
        break;
    case EBPF_OP_ARSH64_IMM:
        reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
        break;
    case EBPF_OP_ARSH64_REG:
        reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
        break;
    
    case EBPF_OP_LDDW:
        // TODO: assert false - already transformed
        break;

    default: break;
    }
    #undef reg
    return res;
}
