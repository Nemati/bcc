#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# vmtool    Calculates vCPU usage for each VM on system periodically
#           and allows a deeper insignt on VM internals
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
#
# Copyright (c) 2017 DORSAL Lab (Polytechnique Montreal) & ShiftLeft Inc.
#
# Author(s):
#   Hani Nemati <hani.nemati@polymtl.ca>
#   Suchakrapani Sharma <suchakra@shiftleft.io>

from __future__ import print_function
from bcc import BPF
import os

# load BPF program
b = BPF(text="""
#include <linux/sched.h>

struct vm_t {
    int ptid;         /* ptid is parent tid */
    int vcpu_pid;     /* tid of vCPU */
    int vcpu_id;      /* id of vCPU */
    long vm_ts;       /* start time vm mode */
    long vm_d;        /* delta time vm mode */
    long vmm_ts;      /* start time vmm mode */
    long vmm_d;       /* delta time vmm mode */
};

BPF_HASH(vm, u32, struct vm_t);

TRACEPOINT_PROBE(kvm, kvm_exit) {
    u32 tid = bpf_get_current_pid_tgid();
    long ts = bpf_ktime_get_ns();
    struct vm_t * vm_instance;
    vm_instance = vm.lookup(&tid);

    if (vm_instance == NULL) {
        return 0;
    }

    vm_instance->vmm_ts = ts;
    vm_instance->vm_d = ts - vm_instance->vm_ts;
    bpf_trace_printk("KVM_EXIT exit_reason : %d:%d\\n", tid, args->exit_reason);
    return 0;
}
TRACEPOINT_PROBE(kvm, kvm_entry) {
    u32 tid = bpf_get_current_pid_tgid();
    struct vm_t * vm_instance;
    vm_instance = vm.lookup(&tid);

    if (vm_instance == NULL) {
        u32 ptid = bpf_get_current_pid_tgid() >> 32;
        struct vm_t vm_tm = {};
        vm_tm.vcpu_id = args->vcpu_id;
        vm_tm.ptid = ptid;
        vm_tm.vm_d = 0;
        vm_tm.vmm_d = 0;
        vm_tm.vm_ts =  bpf_ktime_get_ns();
        vm.update(&tid,&vm_tm);
        return 0;
    }

    long ts = bpf_ktime_get_ns();
    vm_instance->vm_ts = ts ;
    vm_instance->vmm_d = ts - vm_instance->vmm_ts;
    bpf_trace_printk("KVM_ENTRY entry : %d:%d\\n", tid, vm_instance->vcpu_id);
    return 0;
}
TRACEPOINT_PROBE(sched, sched_switch) {
    u32 next_tid = args->next_pid;
    u32 prev_tid = args->prev_pid;
    struct vm_t * vm_instance;
    vm_instance = vm.lookup(&next_tid);

    if (vm_instance == NULL) {
        vm_instance = vm.lookup(&prev_tid);

        if (vm_instance == NULL) {
            return 0;
        }

        long ts = bpf_ktime_get_ns();
        vm_instance->vmm_d = ts - vm_instance->vmm_ts ;
        bpf_trace_printk("Sched_out: %d\\n",prev_tid);
        return 0;
    }

    bpf_trace_printk("Sched_in:%d\\n",next_tid);
    vm_instance->vmm_ts = bpf_ktime_get_ns();
    vm_instance = vm.lookup(&prev_tid);

    if (vm_instance == NULL) {
        return 0;
    }

    bpf_trace_printk("Sched_out%d\\n",prev_tid);
    long ts = bpf_ktime_get_ns();
    vm_instance->vmm_d = ts - vm_instance->vmm_ts;
    return 0;
};
""")

reference_vms = [
    {"id": "node_vm_1", "vcpus": [
        {"id": "vCPU0", "consumption": 35},
        {"id": "vCPU1", "consumption": 42}
    ]},
    {"id": "node_vm_2", "vcpus": [
        {"id": "vCPU0", "consumption": 35},
        {"id": "vCPU1", "consumption": 46},
        {"id": "vCPU2", "consumption": 22}
    ]},
    {"id": "node_vm_3", "vcpus": [
        {"id": "vCPU0", "consumption": 3}
    ]}
]

def print_table(vms):
    print("")
    print("    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("    %-18s %-8s %s" % ("VM", "VCPU", "USE"))
    print("    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    for i, vm in enumerate(vms):
        if i != 0:
            print("    ───────────────────────────────")
        if vm["vcpus"] is {}:
            print("    ERROR: Malformed data")
            print("    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        else:
            vmid = vm["id"]
            for idx, vcpu in enumerate(vm["vcpus"]):
                if idx == 0:
                    print("    %-18s %-8s %s" % (vmid, vcpu["id"], vcpu["consumption"]))
                else:
                    print("    %-18s %-8s %s" % ("", vcpu["id"], vcpu["consumption"]))

    print("    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


os.system('clear')
print_table(reference_vms)

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    # print("%-18.9f %-16s %-6d %-6d %s" % (ts, task, cpu, pid, msg))

