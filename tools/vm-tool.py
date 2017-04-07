#!/usr/bin/env python
#
#
# vm-tool.py
#
# It calculates vCPU usage for each VM See vm-tool.txt
# for usage
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
#
# Copyright (c) 2017 
#
# Author(s):
#   Hani Nemati <hani.nemati@polymtl.ca>
#   Suchakrapani Sharma <suchakra@shiftleft.io>



from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <linux/sched.h>

struct vm_t{
  // ptid is parent tid
  int ptid;
  // tid of vcpu
  int vcpu_pid;
  // id of vCPU
  int vcpu_id;
  // start time vm mode 
  long vm_ts;
  // delta time vm mode
  long vm_d;
  // start time vmm mode 
  long vmm_ts;
  // delta time vmm mode
  long vmm_d; 
};



BPF_HASH(vm, u32, struct vm_t);

TRACEPOINT_PROBE(kvm, kvm_exit) {

	u32 tid = bpf_get_current_pid_tgid();
	long ts = bpf_ktime_get_ns();
	struct vm_t * vm_instance; 
	vm_instance = vm.lookup(&tid); 
	if (vm_instance == NULL){		
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
	if (vm_instance == NULL){
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
	if (vm_instance == NULL){
	    vm_instance = vm.lookup(&prev_tid);
	    if (vm_instance == NULL){
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
	    if (vm_instance == NULL){
		return 0;
	    }	
	bpf_trace_printk("Sched_out%d\\n",prev_tid);
	    long ts = bpf_ktime_get_ns();	
	    vm_instance->vmm_d = ts - vm_instance->vmm_ts ;
	return 0;
}
;
""")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "EVENT"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %-6d %s" % (ts, task, cpu, pid, msg))



	

