#define MAKE_TRAMPOLINE_ALIAS(to, alias) .global _##alias %% .global _MACHOMERGER_TRAMPOLINE_##to## %% _##alias: %% _MACHOMERGER_TRAMPOLINE_##to##: %% b .
#define MAKE_TRAMPOLINE(to) MAKE_TRAMPOLINE_ALIAS(to, to)

#define SYSCALL_PROLOGUE stp x0, x1, [sp, -16]! %% stp x2, x3, [sp, -16]! %% stp x4, x5, [sp, -16]! %% stp x6, x7, [sp, -16]!
#define SYSCALL_EPILOGUE ldp x6, x7, [sp], 16 %% ldp x4, x5, [sp], 16 %% ldp x2, x3, [sp], 16 %% ldp x0, x1, [sp], 16

#define DEF_SYSCALL(name, num)  .global _##name %% _##name: %% SYSCALL_PROLOGUE %% mov x16, num %% svc #0x80 %% mov x16, x0 %% SYSCALL_EPILOGUE %% bcc name##_end %% cmp x16, #4 %% beq _##name %% mov x16, #-1 %% name##_end: %% mov x0, x16 %% ret
#define DEF_MACHTRAP(name, num) .global _##name %% _##name: %% mov x16, -num %% svc #0x80 %% ret

.text
.align 4

.global _MACHOMERGER_START_HOOK
_MACHOMERGER_START_HOOK:
    // Copy-Paste from dyld
    mov    x0, sp
    mov    x19, sp
    and    sp, x0, #~15 // force 16-byte alignment of stack
    mov    fp, #0

    // Call init
    bl _libdyldhook_init

    // Restore stack
    mov sp, x19

    // Jump to real start
    b _MACHOMERGER_REAL_START

.global _real_simple_getenv
.global _MACHOMERGER_HOOKTRAMPOLINE__simple_getenv
_real_simple_getenv:
    pacibsp
    // FALLTHROUGH
_MACHOMERGER_HOOKTRAMPOLINE__simple_getenv:
    b . // Will be patched by machomerger


.global _real_ZN5dyld3L23mapSplitCacheSystemWideERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE
.global _MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld3L23mapSplitCacheSystemWideERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE
_real_ZN5dyld3L23mapSplitCacheSystemWideERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE:
    pacibsp
    // FALLTHROUGH
_MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld3L23mapSplitCacheSystemWideERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE:
    b . // Will be patched by machomerger

.global _real_ZNK5dyld313MachOAnalyzer16hasCodeSignatureERjS1_
.global _MACHOMERGER_HOOKTRAMPOLINE__ZNK5dyld313MachOAnalyzer16hasCodeSignatureERjS1_
_real_ZNK5dyld313MachOAnalyzer16hasCodeSignatureERjS1_:
    pacibsp
_MACHOMERGER_HOOKTRAMPOLINE__ZNK5dyld313MachOAnalyzer16hasCodeSignatureERjS1_:
    b .

.global _real_ZN5dyld44APIs6dlopenEPKci
.global _MACHOMERGER_HOOKTRAMPLOINE__ZN5dyld44APIs6dlopenEPKci
_real_ZN5dyld44APIs6dlopenEPKci:
    mov x3, x30
_MACHOMERGER_HOOKTRAMPLOINE__ZN5dyld44APIs6dlopenEPKci:
    b . 

.global _real_ZN5dyld44APIs5dlsymEPvPKc
.global _MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld44APIs5dlsymEPvPKc
_real_ZN5dyld44APIs5dlsymEPvPKc:
    pacibsp
_MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld44APIs5dlsymEPvPKc:
    b .

.global _real_ZN5dyld3L18reuseExistingCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE
.global _MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld3L18reuseExistingCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE
_real_ZN5dyld3L18reuseExistingCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE:
    pacibsp
_MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld3L18reuseExistingCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE:
    b .



MAKE_TRAMPOLINE(MACHOMERGER_REAL_START)
MAKE_TRAMPOLINE(cerror)
MAKE_TRAMPOLINE_ALIAS(__getpid, getpid)
MAKE_TRAMPOLINE_ALIAS(__bzero, bzero)
MAKE_TRAMPOLINE(mach_msg)
MAKE_TRAMPOLINE(mach_msg_destroy)
MAKE_TRAMPOLINE(mach_reply_port)
MAKE_TRAMPOLINE(memset)
MAKE_TRAMPOLINE(task_self_trap)
MAKE_TRAMPOLINE(__stack_chk_fail)
MAKE_TRAMPOLINE_ALIAS(_kernelrpc_mach_vm_allocate_trap, vm_allocate)
MAKE_TRAMPOLINE_ALIAS(_kernelrpc_mach_vm_deallocate_trap, vm_deallocate)
MAKE_TRAMPOLINE(vm_protect)
MAKE_TRAMPOLINE(memcpy)
MAKE_TRAMPOLINE(strcmp)
MAKE_TRAMPOLINE(strcpy)
MAKE_TRAMPOLINE_ALIAS(mig_get_reply_port, dyld_mig_get_reply_port)

DEF_SYSCALL(read, 3)
DEF_SYSCALL(lseek, 199)
DEF_SYSCALL(__sandbox_ms, 381)



.data
.global ___stack_chk_guard
___stack_chk_guard:
    .quad 0x1337
