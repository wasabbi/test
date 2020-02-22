// too slow..
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdlib.h>

#include "hypercall.h"
#include "sysemu/kvm.h"
#include "qemu-common.h"
#include "race/log.h"
#include "race/utils.h"

int kvm_virtual_memory_rw(CPUState *cpu, target_ulong addr, uint8_t *buf, int len);

QemuMutex qemu_race_mutex;

#define gettid() \
	syscall(SYS_gettid)

#define _NONZERO(v) ({\
        if (!v) \
            panic("zero value\n"); \
        v; \
    })

int phase[4];

int alreadyInserted[4] ={0,0,0,0};

#define CPU_NUM 4
target_ulong addr1 = 0x0;  //go_first
target_ulong addr2 = 0x0;  //go_second
target_ulong addr3 = 0x0;  //go_third

target_ulong addr1_next = 0x0;  //go_first
target_ulong addr2_next = 0x0;  //go_second
target_ulong addr3_next = 0x0;  //go_third

target_ulong manage_bp_addr = 0x5ff11000 + 0x10;//0x5ff111bf;  //manage_bp
uint8_t manage_bp[] = {0x48, 0xb8, 0x64, 0x64, 0x64, 0x64, 0x64, 0x00, 0x00, 0x00};
int manage_bp_size = sizeof(manage_bp) / sizeof(uint8_t);

int scheduling_thread_num = 0; //
int thread_end_num = 0;


void print_insn(uint8_t buf[16], int length){
    char string[256];
    for(int i = 0; i < length; i++){
        sprintf(string+i*3, "%02x ", buf[i]);
    }
    Logf("%s", string);
    //Logf("rip: %llx: cpu: %d cr3: %llx", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);
//    Logf("size: %d", sizeof(target_inst));
}



// some status variables
bool first_insn_exec;
bool second_insn_exec;
bool third_insn_exec;
int debug_count = 0;
int loop_count = 0;
CPUState* cpu_arr[4] = {NULL, NULL, NULL, NULL};
CPUState* CPU_go_first;
CPUState* CPU_go_second;
CPUState* CPU_go_third;

int CPU_go_first_phase = PHASE_1;
int CPU_go_second_phase = PHASE_1;
int CPU_go_third_phase = PHASE_1;


bool _3bps_in_2CPUS;
CPUState* CPU_with_2bp;
CPUState* CPU_with_1bp;
target_ulong addr_fore = 0x0;
target_ulong addr_back = 0x0;
bool fore_inst_ran = false;

void init_per_cpu(CPUState *cpu){
    if(alreadyInserted[cpu->cpu_index] == 0){
        alreadyInserted[cpu->cpu_index] = 1;
        kvm_insert_breakpoint_per_cpu(cpu, manage_bp_addr);
        Logf("insert manage_bp: cpu: %d %llx", (int)cpu->cpu_index, manage_bp_addr);
        cpu_arr[cpu->cpu_index] = cpu;
    }
}

void wait_race(CPUState *cpu) {
    target_ulong paddr;
    int insn_size;
	uint32_t tid __attribute__((unused)) = gettid();
    struct kvm_regs *regs = cpu->regs;
    if (regs == NULL)
        return;

    // schedule threads
    if(cpu->wait_race) {
        qemu_mutex_lock(&qemu_race_mutex);

        if(phase[cpu->cpu_index] == PHASE_UNREACHED){
            phase[cpu->cpu_index] = PHASE_SLEEPING;
            Logf("[%u][CPU%d] triggered its bp (PHASE_UNREACHED -> PHASE_SLEEPING)\n", tid, cpu->cpu_index);
        }
        else if(phase[cpu->cpu_index] == PHASE_SLEEPING){
            if(((phase[0] == PHASE_SLEEPING || phase[0] == PHASE_PASSED) && (phase[1] == PHASE_SLEEPING || phase[1] == PHASE_PASSED) && (phase[2] == PHASE_SLEEPING || phase[2] == PHASE_PASSED))
            || (_3bps_in_2CPUS 
                && (phase[CPU_with_2bp->cpu_index]==PHASE_SLEEPING || phase[CPU_with_2bp->cpu_index]==PHASE_PASSED)
                && (phase[CPU_with_1bp->cpu_index]==PHASE_SLEEPING || phase[CPU_with_1bp->cpu_index]==PHASE_PASSED))){
                if(cpu->go_first){
                    switch(CPU_go_first_phase){
                        case PHASE_1:
                            if(regs->rip != addr1){
                                kvm_cpu_synchronize_state(cpu);
                                Logf("[%u][CPU%d] go_first CPU in %llx cr3: %llx", tid, cpu->cpu_index, regs->rip, X86_CPU(cpu)->env.cr[3]);
                                qemu_mutex_unlock(&qemu_race_mutex);
                                return;
                            }
                            kvm_cpu_synchronize_state(cpu);
                            Logf("[%u][CPU%d] go_first CPU go singlestep from %llx", tid, cpu->cpu_index, addr1);
                            Logf("rip: %llx cpu: %d cr3: %llx\n", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);
                            kvm_remove_breakpoint_per_cpu(cpu, addr1);
                            cpu->singlestep_enabled = 1;
                            kvm_update_guest_debug_per_cpu(cpu, 0);

                            CPU_go_first_phase = PHASE_2;
                            /* race check */
                            /* race check */
                        break;

                        case PHASE_2:
                            addr1_next = regs->rip;
                            if(_3bps_in_2CPUS && cpu == CPU_with_2bp && addr1 == addr_fore){
                                if(addr1_next == addr_back){
                                    cpu->singlestep_enabled = 0;
                                    kvm_update_guest_debug_per_cpu(cpu, 0);
                                    first_insn_exec = 1;
                                    Logf("[%u][CPU%d] go_first CPU resume123\n", tid,cpu->cpu_index);
                                    CPU_go_first_phase = PHASE_END;
                                    break;
                                }
                            }
                            kvm_insert_breakpoint_per_cpu(cpu, addr1_next);
                            cpu->singlestep_enabled = 0;
                            kvm_update_guest_debug_per_cpu(cpu, 0);
                            first_insn_exec = 1;

                            Logf("[%u] go_first after singlestep:", tid);
                            Logf("[%u] [HANDLE BREAKPOINT]", tid);
                            Logf("[%u] \t cpu      :  %d", tid, (int)cpu->cpu_index);
                            Logf("[%u] \t cr3      : %llx", tid, X86_CPU(cpu)->env.cr[3]);
                            Logf("[%u] \t regs.rip       : %llx\n", tid, regs->rip);

                            CPU_go_first_phase = PHASE_3;
                        break;

                        case PHASE_3:
                            loop_count++;
                            if(loop_count % 1000000 == 0){
                                Logf("[%u][CPU%d] 4th Stage: go_first CPU is waiting %d\n", tid, cpu->cpu_index, loop_count);
                            }
                            if(second_insn_exec && third_insn_exec
                            || (_3bps_in_2CPUS && cpu == CPU_with_2bp && addr1 == addr_fore)){
                                Logf("[%u][CPU%d] go_first CPU resume\n", tid, cpu->cpu_index);
                                //Logf("rip: %llx cpu: %d cr3: %llx\n", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);
                                kvm_remove_breakpoint_per_cpu(cpu, addr1_next);

                                if(!(_3bps_in_2CPUS && cpu == CPU_with_2bp && addr1 == addr_fore)){
                                    phase[cpu->cpu_index] = PHASE_PASSED; 
                                    cpu->wait_race = false;
                                }
                                CPU_go_first_phase = PHASE_END;
                            }
                        break;

                        default:
                        break;
                    }
                } 
                if(cpu->go_second){
                    switch(CPU_go_second_phase){
                        case PHASE_1:
                            if(first_insn_exec)
                                CPU_go_second_phase = PHASE_2;
                        break;

                        case PHASE_2:
                            if(regs->rip != addr2){
                                kvm_cpu_synchronize_state(cpu);
                                Logf("[%u][CPU%d] go_second CPU in %llx cr3: %llx", tid, cpu->cpu_index, regs->rip, X86_CPU(cpu)->env.cr[3]);
                                qemu_mutex_unlock(&qemu_race_mutex);
                                return;
                            }
                            kvm_cpu_synchronize_state(cpu);
                            Logf("[%u][CPU%d] go_second CPU go singlestep from %llx", tid, cpu->cpu_index, addr2);
                            Logf("rip: %llx: cpu: %d cr3: %llx\n", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);
                            kvm_remove_breakpoint_per_cpu(cpu, addr2);
                            cpu->singlestep_enabled = 1;
                            kvm_update_guest_debug_per_cpu(cpu, 0);
                            /* race check */
                            /* race check */

                            CPU_go_second_phase = PHASE_3;
                        break;
                        
                        case PHASE_3:
                            addr2_next = regs->rip;
                            if(_3bps_in_2CPUS && cpu == CPU_with_2bp && addr2 == addr_fore){
                                if(addr2_next == addr_back){
                                    cpu->singlestep_enabled = 0;
                                    kvm_update_guest_debug_per_cpu(cpu, 0);
                                    second_insn_exec = 1;
                                    Logf("[%u][CPU%d] go_second CPU resume123\n", tid, cpu->cpu_index);
                                    CPU_go_second_phase = PHASE_END;
                                    break;
                                }
                            }
                            kvm_insert_breakpoint_per_cpu(cpu, addr2_next);
                            cpu->singlestep_enabled = 0;
                            kvm_update_guest_debug_per_cpu(cpu, 0);
                            second_insn_exec = 1;

                            Logf("[%u] go_second after singlestep:", tid);
                            Logf("[%u] [HANDLE BREAKPOINT]", tid);
                            Logf("[%u] \t cpu      :  %d", tid, (int)cpu->cpu_index);
                            Logf("[%u] \t cr3      : %llx", tid, X86_CPU(cpu)->env.cr[3]);
                            Logf("[%u] \t regs.rip       : %llx\n", tid, regs->rip);

                            CPU_go_second_phase = PHASE_4;
                        break;
                        
                        case PHASE_4:
                            loop_count++;
                            if(loop_count % 1000000 == 0){
                                Logf("[%u][CPU%d] 4th Stage: go_second CPU is waiting %d\n", tid, cpu->cpu_index, loop_count);
                            }
                            if(third_insn_exec
                            || (_3bps_in_2CPUS && cpu == CPU_with_2bp && addr2 == addr_fore)){
                                Logf("[%u][CPU%d] go_second CPU resume\n", tid, cpu->cpu_index);
                                //Logf("rip: %llx cpu: %d cr3: %llx\n", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);
                                kvm_remove_breakpoint_per_cpu(cpu, addr2_next);

                                if(!(_3bps_in_2CPUS && cpu == CPU_with_2bp && addr2 == addr_fore)){
                                    cpu->wait_race = false;
                                    phase[cpu->cpu_index] = PHASE_PASSED;
                                }
                                CPU_go_second_phase = PHASE_END;
                            }
                        break;

                        default:
                        break;
                    }
                }
                if(cpu->go_third){
                    switch(CPU_go_third_phase){
                        case PHASE_1:
                            if(second_insn_exec)
                                CPU_go_third_phase = PHASE_2;
                        break;

                        case PHASE_2:
                            if(regs->rip != addr3){
                                Logf("[%u][CPU%d] go_third CPU in %llx", tid, cpu->cpu_index, regs->rip);
                                qemu_mutex_unlock(&qemu_race_mutex);
                                return;
                            }
                            kvm_cpu_synchronize_state(cpu);
                            Logf("[%u][CPU%d] go_third CPU go singlestep from %llx", tid, cpu->cpu_index, addr3);
                            Logf("rip: %llx: cpu: %d cr3: %llx\n", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);
                            kvm_remove_breakpoint_per_cpu(cpu, addr3);
                            cpu->singlestep_enabled = 1;
                            kvm_update_guest_debug_per_cpu(cpu, 0);
                            /* race check */
                            /* race check */

                            CPU_go_third_phase = PHASE_3;
                        break;
                        
                        case PHASE_3:
                            addr3_next = regs->rip;
                            cpu->singlestep_enabled = 0;
                            cpu->wait_race = false;
                            kvm_update_guest_debug_per_cpu(cpu, 0);
                            third_insn_exec = 1;

                            Logf("[%u] go_third after singlestep:", tid);
                            Logf("[%u] [HANDLE BREAKPOINT]", tid);
                            Logf("[%u] \t cpu      :  %d", tid, (int)cpu->cpu_index);
                            Logf("[%u] \t cr3      : %llx", tid, X86_CPU(cpu)->env.cr[3]);
                            Logf("[%u] \t regs.rip       : %llx", tid, regs->rip);

                            Logf("[%u][CPU%d] go_third CPU resume\n", tid, cpu->cpu_index);

                            phase[cpu->cpu_index] = PHASE_PASSED;
                            CPU_go_third_phase = PHASE_END;
                        break;
                        
                        default:
                        break;
                    }
                }
            }
            else{
                loop_count++;
                if(loop_count % 300000 == 0){;
                    Logf("[%u][CPU%d] 1st Stage: CPU%d is waiting %d", tid, cpu->cpu_index,  cpu->cpu_index, loop_count);
                    int i = 0; 
                    for(;i < CPU_NUM; i++){
                        CPUState* cpu_iter = cpu_arr[i];
                        if(cpu_iter != NULL){
                            struct kvm_regs *regs_iter = cpu_iter->regs;
                            if(regs_iter != NULL && regs_iter != 0)
                                Logf("CPU%d: rip: %llx cr3: %llx", i, regs_iter->rip, X86_CPU(cpu_iter)->env.cr[3]);
                            else
                                Logf("CPU%d: rip: ???????? cr3: %llx", i, X86_CPU(cpu_iter)->env.cr[3]);
                        }
                    }
                    /*Logf("SLEEP...");
                    sleep(1);*/
                    Logf("");
                }
            }
        }
        qemu_mutex_unlock(&qemu_race_mutex);
    }
}

bool check_inst(uint8_t *stopped_inst, uint8_t *target_inst, int target_size){
    for(int i = 0; i < target_size; i++){
        if(stopped_inst[i] != target_inst[i])
            return false;
    }
    return true;
}

int kvm_virtual_memory_rw(CPUState *cpu, target_ulong vaddr, uint8_t *buf, int len) {
    int l;
    int ret;
    hwaddr phys_addr;
    target_ulong page;

    //cpu_synchronize_state(cpu);
    kvm_cpu_synchronize_state(cpu);

    while (len > 0) {
        page = vaddr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(cpu, page);
        if (phys_addr == -1) {
            // no physical page mapped
            return -1;
        }
        l = (page + TARGET_PAGE_SIZE) - vaddr;
        if (l > len) {
            l = len;
        }
        phys_addr += (vaddr & ~TARGET_PAGE_MASK);
        //phys_addr = get_phys_addr1(cpu, vaddr);
        cpu_physical_memory_read(phys_addr, buf, l);
        len -= l;
        buf += l;
        vaddr += l;
    }
    return 0;
}

void init_status(){
    debug_count = 0;
    loop_count = 0;
    _3bps_in_2CPUS = false;
    fore_inst_ran = false;
    CPU_with_2bp = NULL;
    CPU_with_1bp = NULL;
    addr_fore = 0x0;
    addr_back = 0x0;
    phase[0] = PHASE_UNREACHED; phase[1] = PHASE_UNREACHED; phase[2] = PHASE_UNREACHED;
    CPU_go_first_phase = PHASE_1;    CPU_go_second_phase = PHASE_1;    CPU_go_third_phase = PHASE_1;
    first_insn_exec = false;    second_insn_exec = false;    third_insn_exec = false;

    cpu_arr[0]->wait_race = false;
    cpu_arr[1]->wait_race = false;
    cpu_arr[2]->wait_race = false;  //其实对方CPU（cpu_arr[opponent]）的值是不会立即更新，但也不能
                                    //kvm_cpu_synchronize_state(opponent_cpu);  /* DANGER */
                                    //因为这样不会之更新cpu->wait_race，而其他寄存器变量也会更新，导致错误
                                    //那么对这情况，怎么处理？
                                    //要么向对方CPU触发中断
                                    //要么不考虑这情况（由于这情况很少发生）
    

    kvm_remove_breakpoint_per_cpu(cpu_arr[0], addr1);
    kvm_remove_breakpoint_per_cpu(cpu_arr[1], addr1);
    kvm_remove_breakpoint_per_cpu(cpu_arr[2], addr1);
    kvm_remove_breakpoint_per_cpu(cpu_arr[0], addr2);
    kvm_remove_breakpoint_per_cpu(cpu_arr[1], addr2);
    kvm_remove_breakpoint_per_cpu(cpu_arr[2], addr2);
    kvm_remove_breakpoint_per_cpu(cpu_arr[0], addr3);
    kvm_remove_breakpoint_per_cpu(cpu_arr[1], addr3);
    kvm_remove_breakpoint_per_cpu(cpu_arr[2], addr3);
    kvm_remove_breakpoint_per_cpu(cpu_arr[0], addr1_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[1], addr1_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[2], addr1_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[0], addr2_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[1], addr2_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[2], addr2_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[0], addr3_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[1], addr3_next);
    kvm_remove_breakpoint_per_cpu(cpu_arr[2], addr3_next);

    cpu_arr[0]->go_first = false; cpu_arr[0]->go_second = false; cpu_arr[0]->go_third = false;
    cpu_arr[1]->go_first = false; cpu_arr[1]->go_second = false; cpu_arr[1]->go_third = false;
    cpu_arr[2]->go_first = false; cpu_arr[2]->go_second = false; cpu_arr[2]->go_third = false;

    addr1 = 0; addr2 = 0; addr3 = 0;
    addr1_next = 0; addr2_next = 0; addr3_next = 0;
    CPU_go_first = NULL;
    CPU_go_second = NULL;
    CPU_go_third = NULL;
    thread_end_num = 0;
    scheduling_thread_num = 0;
}

void handle_breakpoint(CPUState *cpu, int sched){
    struct kvm_regs *regs = _NONZERO(cpu->regs);
    uint8_t buf[16];
    int err;
    uint32_t tid __attribute__((unused)) = gettid();

    if(cpu->wait_race == true){     //already handled bp, not need to analyse inst any more
        debug_count++;
        if(debug_count % 100000 == 0){

            Logf("[%u] HANDLE BREAKPOINT", tid);

            if(phase[cpu->cpu_index] == PHASE_SLEEPING)
                Logf("[%u] CPU%d has been waiting %d in PHASE_SLEEPING", tid, (int)cpu->cpu_index, debug_count);
            else if(phase[cpu->cpu_index] == PHASE_PASSED)
                Logf("[%u] CPU%d has been waiting %d in PHASE_PASSED", tid, (int)cpu->cpu_index, debug_count);
            else
                Logf("[%u] CPU%d has been waiting %d in ????", tid, (int)cpu->cpu_index, debug_count);
            Logf("bp %llx: cpu: %d cr3: %llx\n", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);

            if(debug_count >= 500000){
                Logf("[%u] CPU%d has been waiting %d\n     It seems the two hw_bp is not concurrent\n     Thread Scheduling Ended\n", tid, (int)cpu->cpu_index, debug_count);        
                qemu_mutex_lock(&qemu_race_mutex);
                init_status();
                qemu_mutex_unlock(&qemu_race_mutex);
            }
        }
        return;
    }
    if(kvm_virtual_memory_rw(cpu, regs->rip, buf, 15) == -1){
        return;
    }
    //    print read insn
    //print_insn(cpu, buf);

    if(1/*check_inst(buf, target_inst, target_size)*/){ //通过比较指令内容判断是否在目标进程
        qemu_mutex_lock(&qemu_race_mutex);

        if(_3bps_in_2CPUS){
            if(CPU_with_2bp){
                if(regs->rip == addr_back && !fore_inst_ran){
                    Logf("Back_inst ran before Fore_inst");
                    Logf("The scheduling has failed\n");
                    /*quit test*/
                }
                if(regs->rip == addr_fore){
                    fore_inst_ran = true;
                }
            }
        }

        cpu->wait_race = true;
        
        Logf("[%u] TARGET:", tid);
        Logf("[%u] [HANDLE BREAKPOINT]", tid);
        Logf("[%u] \t cpu      :  %d", tid, (int)cpu->cpu_index);
        Logf("[%u] \t cr3      : %llx", tid, X86_CPU(cpu)->env.cr[3]);
        Logf("[%u] \t regs.rip       : %llx", tid, regs->rip);
        Logf("reached target bp  \n");

        qemu_mutex_unlock(&qemu_race_mutex);
    }
    return;
}
void hypercall_manage_bp(CPUState *cpu){
    struct kvm_regs *regs = _NONZERO(cpu->regs);
    uint8_t buf[16];

    if(kvm_virtual_memory_rw(cpu, regs->rip, buf, 15) == -1){
        return;
    }
	
    if(check_inst(buf, manage_bp, manage_bp_size)){ //通过比较指令内容判断是否在目标进程
        qemu_mutex_lock(&qemu_race_mutex);
        uint32_t tid __attribute__((unused)) = gettid();

        uint64_t hw_bp_addr = regs->rdi;
        uint64_t sched = regs->rsi;
        uint64_t CPU_index = regs->rdx;
        uint64_t type = regs->rcx;

        
        if(type == 0){
        //remove bp
            Logf("[%u] HYPERCALL_REMOVE_BP:", tid);
            Logf("reached bp %llx: cpu: %d cr3: %llx", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);
            Logf("[%u] hw_bp_addr: %llx", tid, hw_bp_addr);
            Logf("");
            kvm_remove_breakpoint_per_cpu(cpu_arr[0], hw_bp_addr);
            kvm_remove_breakpoint_per_cpu(cpu_arr[1], hw_bp_addr);
            kvm_remove_breakpoint_per_cpu(cpu_arr[2], hw_bp_addr);
        }
        else if(type == 1){
        //insert bp
            Logf("[%u] HYPERCALL_INSERT_BP:", tid);
            Logf("reached bp %llx: cpu: %d cr3: %llx", regs->rip, (int)cpu->cpu_index, X86_CPU(cpu)->env.cr[3]);

            Logf("[%u] sched: %llx", tid, sched);

        
            if(sched == 1){
                addr1 = hw_bp_addr;
                addr1_next = 0;
                CPU_go_first = cpu;
                cpu->go_first = true;
                Logf("[%u] Insert go_first bp:", tid);
                Logf("[%u] hw_bp_addr: %llx", tid, addr1);
                Logf("");
            }
            else if(sched == 2){
                addr2 = hw_bp_addr;
                addr2_next = 0;
                CPU_go_second = cpu;
                cpu->go_second = true;
                Logf("[%u] Insert go_second bp:", tid);
                Logf("[%u] hw_bp_addr: %llx", tid, addr2);
                Logf("");
            }
            else if(sched == 3){
                addr3 = hw_bp_addr;
                addr3_next = 0;
                CPU_go_third = cpu;
                cpu->go_third = true;
                Logf("[%u] Insert go_third bp:", tid);
                Logf("[%u] hw_bp_addr: %llx", tid, addr3);
                Logf("");
            }
            else{
                Logf("[%u] sched is incorrect", tid);
                Logf("");
            }
        }
        else if(type == 2){
        // manage_hw_bp start
            init_status();
        }
        else if(type == 3){
        // manage_hw_bp end
            // only scheduling 2 bps
            if(addr3 == 0){
                third_insn_exec = true;
                CPU_go_third_phase = PHASE_END;
                phase[3 - CPU_go_first->cpu_index - CPU_go_second->cpu_index] = PHASE_PASSED;
                Logf("Only scheduling 2 bps\n");
                scheduling_thread_num = 2;
            }
            //3bps_in_2CPUS
            else if(CPU_go_first == CPU_go_second || CPU_go_first == CPU_go_third || CPU_go_second == CPU_go_third){
                _3bps_in_2CPUS = true;
                if(CPU_go_first == CPU_go_second){
                    CPU_with_2bp = CPU_go_first;
                    CPU_with_1bp = CPU_go_third;
                    addr_fore = addr1;
                    addr_back = addr2;
                }else if(CPU_go_first == CPU_go_third){
                    CPU_with_2bp = CPU_go_first;
                    CPU_with_1bp = CPU_go_second;
                    addr_fore = addr1;
                    addr_back = addr3;
                }else if(CPU_go_second == CPU_go_third){
                    CPU_with_2bp = CPU_go_second;
                    CPU_with_1bp = CPU_go_first;
                    addr_fore = addr2;
                    addr_back = addr3;
                }
                Logf("Scheduling 3 bps in 2 cpus\n");
                scheduling_thread_num = 2;
            }
            else{
                Logf("Scheduling 3 bps in 3 cpus\n");
                scheduling_thread_num = 3;
            }
        }
        else if(type == 4){
        // begin of __start_routine
            uint32_t tid2 __attribute__((unused)) = gettid();
            Logf("[%u]======__start_routine started======", tid2);
            if(cpu == CPU_go_first){
                kvm_insert_breakpoint_per_cpu(cpu, addr1);
                Logf("[%u] Insert go_first bp:", tid);
            }else if(cpu == CPU_go_second){
                kvm_insert_breakpoint_per_cpu(cpu, addr2);
                Logf("[%u] Insert go_sedond bp:", tid);
            }else if(cpu == CPU_go_third){
                kvm_insert_breakpoint_per_cpu(cpu, addr3);
                Logf("[%u] Insert go_third bp:", tid);
            }else{
                Logf("[%u] Insert ??? bp:", tid);
            }
        }
        else if(type == 5){
        // end of __start_routine
            uint32_t tid2 __attribute__((unused)) = gettid();
            Logf("[%u]======__start_routine ended======", tid2);
            thread_end_num += 1;
            if(thread_end_num == scheduling_thread_num){    //all threads has ended
                init_status();
            }
        }
        cpu->regs->rip += manage_bp_size;
        cpu->update_regs = true;

        qemu_mutex_unlock(&qemu_race_mutex);
    }
    else{
        uint32_t tid2 __attribute__((unused)) = gettid();
        Logf("[%u] There are some insts except manage_hw_bp in %llx address", tid2, manage_bp_addr);
    }
}

void handle_hw_breakpoint(CPUState *cpu) {
    struct kvm_regs *regs = _NONZERO(cpu->regs);
    uint32_t tid __attribute__((unused)) = gettid();
    
//    ??为什么rip不是0x40078b, 也会进入handle_brekapoint??, 比如0xffffffffc00090c7

    if ((target_ulong)(regs->rip) == manage_bp_addr) {
        hypercall_manage_bp(cpu);
    }
    else if ((target_ulong)(regs->rip) == addr1) {
        handle_breakpoint(cpu, 1);
    }
    else if ((target_ulong)(regs->rip) == addr2){
        handle_breakpoint(cpu, 2);
    }
    else if ((target_ulong)(regs->rip) == addr3){
        handle_breakpoint(cpu, 3);
    }
}
