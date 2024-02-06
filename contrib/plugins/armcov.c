/*
 * Copyright (C) 2024, Nelson Ho <nelson.ho@windriver.com>
 *
 * Generates an instruction log of function calls (bl/blr)
 * and context switch occurrences (writes to ttbr0_el1) on
 * the aarch64.
 *
 * License: GNU GPL, version 2 or later.
 *    See the COPYING file in the top-level directory.
 */

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct CPU {
    /*
     * comma separated record containing the currently tracked
     * instruction and register contents if applicable
     */
    GString *insn_rec;
    /* cpu index */
    int index;
} CPU;

static CPU *cpus;
static int num_cpus;
static GRWLock cpus_lock;
static bool fmt_bin;

/*
 * Get a pointer to the per-vcpu structure
 */
static CPU *get_cpu(int index)
{
    CPU *cpu;

    g_rw_lock_reader_lock(&cpus_lock);

    g_assert(index < num_cpus);
    cpu = &cpus[index];

    g_rw_lock_reader_unlock(&cpus_lock);

    return cpu;
}


/*
 * Get the qemu_plugin_reg_descriptor from reg_list
 * for the register with name matching reg_pat
 */
static void get_reg_desc(GArray *reg_list,
                         GPatternSpec *reg_pat,
                         qemu_plugin_reg_descriptor **desc)
{
    int i;
    if (reg_list && reg_list->len) {
        for (i = 0; i < reg_list->len; i++) {
            *desc = &g_array_index(reg_list, qemu_plugin_reg_descriptor, i);
            if (g_pattern_spec_match_string(reg_pat, (*desc)->name)) {
                // desc is an in/out param
                return;
            }
        }
    }

    *desc = NULL;
}

/*
 * Read the contents of the register described by desc
 * and append its name and contents to the record
 */
static void read_register(unsigned int cpu_index,
                          qemu_plugin_reg_descriptor *desc,
                          GString *record)
{
    GByteArray *reg_buf = g_byte_array_new();
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers(cpu_index);
    int i, regsize;

    g_assert(desc);

    /* append register name to record */
    g_string_append_printf(record, ", %s -> 0x", desc->name);

    /* zero buffer */
    g_byte_array_set_size(reg_buf, 0);

    /* read the register described by desc*/
    regsize = qemu_plugin_read_register(cpu_index, desc->handle, reg_buf);

    /* append register contents to record */
    for (i = regsize-1; i >= 0; i--) {
        g_string_append_printf(record, "%02x", reg_buf->data[i]);
    }
    g_string_append(record, "\n");
    g_byte_array_free(reg_buf, true);
}

/*
 * Callback on instruction to examine registers and print events
 *
 * If last instruction was msr ttbr, check TTBR0_EL1 register
 * and log last instruction. Log next instruction if it is a
 * bl/blr, and check the branch target register if blr.
 */
static void vcpu_insn_exec_cb(unsigned int cpu_index, void *udata)
{
    CPU *cpu = get_cpu(cpu_index);

    /* 
     * Print previous instruction if it was msr ttbr0_el1.
     * Since we are only interested in the value of register
     * ttbr0_el1 after the msr instruction executes, we have to
     * defer the examination of the register contents until the
     * next time this callback is invoked (when we encounter the
     * next msr/bl/blr instruction). We can be sure that the value
     * of ttbr0_el1 has not changed in the meantime, because if it
     * had it would have triggered this callback.
     */
    if (cpu->insn_rec->len && g_strstr_len(cpu->insn_rec->str, -1, "msr")) {
        g_autoptr(GArray) reg_list = qemu_plugin_get_registers(cpu->index);
        GPatternSpec *reg_pat = g_pattern_spec_new("TTBR0_EL1");
        qemu_plugin_reg_descriptor *desc;

        /* get the register descriptor for ttbr0_el1 */
        get_reg_desc(reg_list, reg_pat, &desc);

        if (!desc) {
            fprintf(stderr, "Failed to find register TTBR0_EL1 on cpu %d.\n", cpu->index);
            return;
        }

        read_register(cpu_index, desc, cpu->insn_rec);

        qemu_plugin_outs(cpu->insn_rec->str);
    }

    /* 
     * Store next instruction in insn_rec.
     * This is the instruction that is about to be executed.
     */
    g_string_printf(cpu->insn_rec, "%u, ", cpu_index);
    g_string_append(cpu->insn_rec, (char *)udata);

    /*
     * If the instruction we are about to execute is blr, then print the value
     * of the first register operand to the instruction. We don't need to wait
     * until after the instruction executes because the contents of the register
     * operand are not modified by the instruction (unlike the case of msr ttbr).
     */
    if (cpu->insn_rec->len && g_strstr_len(cpu->insn_rec->str, -1, "blr")) {
        g_autoptr(GArray) reg_list = qemu_plugin_get_registers(cpu->index);
        qemu_plugin_reg_descriptor *desc = NULL;
        /*
         * Parse the disassembly in insn_rec to find the register containing
         * the blr branch target address.
         * This should be the last space-separated token.
         */
        gchar *blr_reg = g_strrstr(cpu->insn_rec->str, " ");
        blr_reg++; //trim leading whitespace
        GPatternSpec *reg_pat = g_pattern_spec_new(blr_reg);

        /* get the descriptor for the register containing the branch target addr */
        get_reg_desc(reg_list, reg_pat, &desc);

        if (!desc) {
            fprintf(stderr, "Failed to find register %s on cpu %d.\n", blr_reg, cpu->index);
            return;
        }

        read_register(cpu_index, desc, cpu->insn_rec);

        qemu_plugin_outs(cpu->insn_rec->str);
    } else if (cpu->insn_rec->len && g_strstr_len(cpu->insn_rec->str, -1, "bl")) {
        /* if instr is bl then print it now */
        g_string_append(cpu->insn_rec, "\n");
        qemu_plugin_outs(cpu->insn_rec->str);
    }
}

/*
 * Callback on each TB translation
 *
 * This function will be run each time a translation block is translated.
 * We search for instructions we are interested in (msr/bl/blr) and register
 * a callback to the instruction execution if necessary.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;
    size_t i, num_instr;

    num_instr = qemu_plugin_tb_n_insns(tb);
    for (i = 0; i < num_instr; i++) {
        char *disas;
        bool skip = true;
        uint64_t vaddr;

        insn = qemu_plugin_tb_get_insn(tb, i);
        disas = qemu_plugin_insn_disas(insn);

        if (g_str_has_prefix(disas, "bl")) {
            // don't skip if bl/blr
            skip = false;
        }

        if (g_str_has_prefix(disas, "msr ttbr0")) {
            skip = false;
        }

        if (skip) {
            /* do nothing if we don't care about this instruction */
        } else {
            uint32_t insn_asm;

            vaddr = qemu_plugin_insn_vaddr(insn);
            insn_asm = *((uint32_t *)qemu_plugin_insn_data(insn));
            char *output = g_strdup_printf("0x%"PRIx64", 0x%"PRIx32", %s",
                                           vaddr, insn_asm, disas);

            /* 
             * register a callback on instruction execution
             * pass output along to the instruction callback to append any
             * cpu register contents before shipping the record
             */
            qemu_plugin_register_vcpu_insn_exec_cb(insn,
                                                   vcpu_insn_exec_cb,
                                                   QEMU_PLUGIN_CB_R_REGS,
                                                   output);
        }

        g_free(disas);
    }
}

/*
 * Initialize a new CPU struct for each vcpu
 *
 * The per-vcpu structure initialized here will hold the trace output
 * that is being constructed for the currently executing instruction.
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    g_rw_lock_writer_lock(&cpus_lock);

    if (vcpu_index >= num_cpus) {
        cpus = g_realloc_n(cpus, vcpu_index + 1, sizeof(*cpus));
        while (vcpu_index >= num_cpus) {
            cpus[num_cpus].index = vcpu_index;
            cpus[num_cpus].insn_rec = g_string_new(NULL);
            num_cpus++;
        }
    }

    g_rw_lock_writer_unlock(&cpus_lock);
}

/*
 * On plugin exit make sure any instruction in insn_rec is printed
 */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    size_t i;
    for (i = 0; i < num_cpus; i++) {
        if (cpus[i].insn_rec->str) {
            g_string_append(cpus[i].insn_rec, "\n");
            qemu_plugin_outs(cpus[i].insn_rec->str);
        }
    }
}

/*
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc,
                                           char **argv)
{
    /*
     * Initialize the dynamic array of CPU structures to track
     * current/last instruction.
     */
    if (info->system_emulation) {
        cpus = g_new(CPU, info->system.max_vcpus);
    }

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "binary") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &fmt_bin)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
                return -1;
            }
            fprintf(stderr, "binary format option not yet supported\n");
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    /* Register vcpu init, TB, and plugin exit callbacks */
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
