#include "libdyldhook.h"

#include <mach/mach.h>
#include <mach/machine/ndr_def.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "dyld_cache_format.h"
#include <sys/mman.h>
#include <limits.h>
#include <asl.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <dlfcn.h>


#include "CodeSignature.h"

#define HOOK(name) MACHOMERGER_HOOK_##name

#define safeClose(fd) do{if ((fd) != -1){close(fd); fd = -1;}}while(0)
#define safePFree(buf) do{if ((buf)){pfree(buf); buf = NULL;}}while(0)
#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

// #define MAP_FAILED ((void*) -1)


extern mach_port_t mach_reply_port(void);

extern void *real_ZN5dyld44APIs6dlopenEPKci(char *filename, int flags);
extern void *real_ZN5dyld44APIs5dlsymEPvPKc(void *handle, char *symbol);
long slide = 0;

#undef bzero

kern_return_t fufuguguRequest(struct FuFuGuGuMsg *msg, struct FuFuGuGuMsgReply *reply);
mach_port_t dyld_mig_get_reply_port(void);


mach_port_t gReplyPort = 0;
mach_port_t gBootstrapPort = 0;

int gTweakCompatEn = 0;

int amIFork = 0;

uint8_t fixupsDone[] = {
    // "LIBDYLDHOOK_NOTIFY_FIXUPS_DONE"
    0x4c, 0x49, 0x42, 0x44, 0x59, 0x4c, 0x44, 0x48,
    0x4f, 0x4f, 0x4b, 0x5f, 0x4e, 0x4f, 0x54, 0x49,
    0x46, 0x59, 0x5f, 0x46, 0x49, 0x58, 0x55, 0x50,
    0x53, 0x5f, 0x44, 0x4f, 0x4e, 0x45, 0x00
};

uint64_t __attribute((noinline, naked)) get_tpidrro_el0(void)
{
    __asm("mrs x0, TPIDRRO_EL0");
    __asm("ret");
}

mach_port_t mig_get_reply_port(void) {
    if (get_tpidrro_el0() == 0) {
        if (!gReplyPort) {
            gReplyPort = mach_reply_port();
        }
        return gReplyPort;
    }
    
    return dyld_mig_get_reply_port();;
}

int giveCSDebugToPID(int pid, int forceDisablePAC, int *pacDisabled) {
    *pacDisabled = 0;
    
    struct FuFuGuGuMsgCSDebug csdebug;
    bzero(&csdebug, sizeof(csdebug));
    
    struct FuFuGuGuMsgReplyCSDebug csdebugRpl;
    bzero(&csdebugRpl, sizeof(csdebugRpl));
    
    csdebug.base.hdr.msgh_size = sizeof(csdebug);
    csdebugRpl.base.hdr.msgh_size = sizeof(csdebugRpl);
    
    csdebug.base.action     = FUFUGUGU_ACTION_CSDEBUG;
    csdebug.pid             = pid;
    csdebug.forceDisablePAC = forceDisablePAC;
    
    kern_return_t kr = fufuguguRequest(&csdebug.base, &csdebugRpl.base);
    if (kr != KERN_SUCCESS)
        return kr;
    
    if (csdebugRpl.base.status)
        return csdebugRpl.base.status;
    
    *pacDisabled = csdebugRpl.pacDisabled;
    return 0;
}

int trustCDHash(const uint8_t *hash, size_t hashSize, uint8_t hashType) {
    struct FuFuGuGuMsgTrust20 trust;
    bzero(&trust, sizeof(trust));
    
    struct FuFuGuGuMsgReply trustRpl;
    bzero(&trustRpl, sizeof(trustRpl));
    
    trust.base.hdr.msgh_size = sizeof(trust);
    trustRpl.hdr.msgh_size = sizeof(trustRpl);
    
    trust.base.action = FUFUGUGU_ACTION_TRUST;
    trust.hashType    = 2;
    trust.hashLen     = 20;
    memcpy(trust.hash, hash, 20);
    
    kern_return_t kr = fufuguguRequest(&trust.base, &trustRpl);
    if (kr != KERN_SUCCESS)
        return kr;
    
    return trustRpl.status;
}

int fixprotSingle(uint64_t pid, void *addr, size_t size) {
    struct FuFuGuGuMsgFixprotSingle fixprot;
    bzero(&fixprot, sizeof(fixprot));
    
    struct FuFuGuGuMsgReply fixprotRpl;
    bzero(&fixprotRpl, sizeof(fixprotRpl));
    
    fixprot.base.hdr.msgh_size = sizeof(fixprot);
    fixprotRpl.hdr.msgh_size = sizeof(fixprotRpl);
    
    fixprot.base.action = FUFUGUGU_ACTION_FIXPROT_SINGLE;
    fixprot.pid         = pid;
    fixprot.address     = addr;
    fixprot.size        = size;
    
    kern_return_t kr = fufuguguRequest(&fixprot.base, &fixprotRpl);
    if (kr != KERN_SUCCESS)
        return kr;
    
    return fixprotRpl.status;
}

kern_return_t fufuguguRequest(struct FuFuGuGuMsg *msg, struct FuFuGuGuMsgReply *reply) {
    mach_port_t replyPort = mig_get_reply_port();
    
    if (!replyPort)
        return KERN_FAILURE;
    
    if (!gBootstrapPort)
        task_get_bootstrap_port(task_self_trap(), &gBootstrapPort);
    
    if (!gBootstrapPort)
        return KERN_FAILURE;
    
    msg->magic = FUFUGUGU_MSG_MAGIC;
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    // size already set
    msg->hdr.msgh_remote_port  = gBootstrapPort;
    msg->hdr.msgh_local_port   = replyPort;
    msg->hdr.msgh_voucher_port = 0;
    msg->hdr.msgh_id           = 0x40000000;
    
    kern_return_t kr = mach_msg(&msg->hdr, MACH_SEND_MSG, msg->hdr.msgh_size, 0, 0, 0, 0);
    if (kr != KERN_SUCCESS)
        return kr;
    
    kr = mach_msg(&reply->hdr, MACH_RCV_MSG, 0, reply->hdr.msgh_size, replyPort, 0, 0);
    if (kr != KERN_SUCCESS)
        return kr;
    
    // Get rid of any rights we might have received
    mach_msg_destroy(&reply->hdr);
    return KERN_SUCCESS;
}

__attribute__((naked)) uint64_t msyscall_errno(uint64_t syscall, ...){
    asm(
        "mov x16, x0\n"
        "ldp x0, x1, [sp]\n"
        "ldp x2, x3, [sp, 0x10]\n"
        "ldp x4, x5, [sp, 0x20]\n"
        "ldp x6, x7, [sp, 0x30]\n"
        "svc 0x80\n"
        "b.cs 20f\n"
        "ret\n"
        "20:\n"
        "b _cerror\n"
        );
}

void *palloc(void) {
    uintptr_t addr = 0;
    kern_return_t kr = vm_allocate(task_self_trap(), &addr, 0x4000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
        return NULL;
    
    return (void*) addr;
}

void pfree(void *ptr) {
    vm_deallocate(task_self_trap(), (vm_address_t) ptr, 0x4000);
}

// Tell mmap hook to force fix the next executable section
// This is set if attaching signatures failed
// Dylibs only have on executable segment and mmap is called directly after fcntl
int forceFixNext = 0;

int HOOK(__fcntl)(int fd, int cmd, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7, void *arg8) {
    int hideErrors = 0;
    switch (cmd){
        case F_ADDSIGS:
        case F_ADDFILESIGS:
        case F_ADDFILESIGS_RETURN:
        {
            uint8_t *buf = NULL;
            //
            int err = 0;
            uint64_t lpos = -1;
            fsignatures_t *siginfo = (fsignatures_t *)arg1;
            lpos = lseek(fd, 0, SEEK_CUR);
            assure(siginfo->fs_blob_size <= 0x4000);
            assure(buf = (uint8_t*)palloc());
            lseek(fd, siginfo->fs_file_start + (uint64_t)siginfo->fs_blob_start, SEEK_SET);
            assure(read(fd, buf, siginfo->fs_blob_size));
            
            err = trustCodeDirectories(NULL, (const CS_SuperBlob *) buf, siginfo->fs_file_start);
        error:
            lseek(fd, lpos, SEEK_SET);
            safePFree(buf);
            hideErrors = 1;
            break;
        }
            
        case F_CHECK_LV:
            hideErrors = 1;
            break;
            
        default:
            break;
    }
    int res = (int)msyscall_errno(0x5C, fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    if (hideErrors && res == -1) {
        if (cmd == F_ADDFILESIGS_RETURN) {
            fsignatures_t *siginfo = (fsignatures_t *)arg1;
            siginfo->fs_file_start = -1;
        }
        
        forceFixNext = 1;
        
        return 0;
    }
    
    return res;
}

void* HOOK(__mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t pos) {
    int shouldFix = 0;
    void *res = (void*) msyscall_errno(0xC5, addr, len, prot, flags, fd, pos);
    if (res == MAP_FAILED) {
        res = (void*) msyscall_errno(0xC5, addr, len, (prot & ~(VM_PROT_EXECUTE)) | VM_PROT_WRITE, flags, fd, pos);
        
        // We mapped this r/w, force the mapping to be fixed
        shouldFix = 1;
    } else if (prot & VM_PROT_EXECUTE && forceFixNext) {
        // If this should have been mapped executable and we succeded,
        // but we know the signature is invalid, force this to be fixed
        // This will incur a performance penalty
        forceFixNext = 0;
        shouldFix = 1;
    }
    
    if (res != MAP_FAILED && shouldFix) {
        // However, we only fix if jbinjector is done
        // If it didn't run yet, do nothing - jbinjector will fix this mapping for us
        // jbinjector is faster because it can fix multiple images in a single request
        if (fixupsDone[0] == 1) {
            fixprotSingle(getpid(), res, len);
            
            if ((prot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE))
                prot &= ~VM_PROT_WRITE;
            
            vm_protect(task_self_trap(), (uintptr_t) res, len, 0, prot);
        }
    }
    
    return res;
}

bool HOOK(_ZNK5dyld415SyscallDelegate18sandboxBlockedMmapEPKc)(char* param1) {
    return false;
} 
bool HOOK(_ZNK5dyld415SyscallDelegate18sandboxBlockedOpenEPKc)(char* param1) {
    return false;
} 
bool HOOK(_ZNK5dyld415SyscallDelegate18sandboxBlockedStatEPKc)(char* param1) {
    return false;
}


extern const char *real_simple_getenv(const char *argv[], const char *which);

const char *HOOK(_simple_getenv)(const char *argv[], const char *which) {
    if (gTweakCompatEn && strcmp(which, "ptrauth_disabled") == 0) {
        return "1";
    }
    
    return real_simple_getenv(argv, which);
}


char *__locate_dsc(void)
{
    // We make two assumptions here
    // 1. This code is only called on iOS 15 arm64e (since the spinlock panic doesn't affect anything else)
    // 2. This code is only called if the shared cache has been mapped in via a shared region
    // For these reasons, we can just hardcode the path
    return "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e";
}

void __dsc_file_enumerate_mappings(int fd, struct dyld_cache_header *header, uintptr_t slide, bool (*enumeratorFunc)(int fd, struct dyld_cache_header *header, uintptr_t slide, struct dyld_cache_mapping_info *mapping))
{
    struct dyld_cache_mapping_info mappingInfos[header->mappingCount];
    lseek(fd, header->mappingOffset, SEEK_SET);
    if (read(fd, mappingInfos, sizeof(struct dyld_cache_mapping_info) * header->mappingCount) != sizeof(struct dyld_cache_mapping_info) * header->mappingCount) return;

    for (uint32_t i = 0; i < header->mappingCount; i++) {
        struct dyld_cache_mapping_info *mapping = &mappingInfos[i];
        enumeratorFunc(fd, header, slide, mapping);
    }
}

void __dsc_enumerate_mappings(uintptr_t slide, bool (*enumeratorFunc)(int fd, struct dyld_cache_header *header, uintptr_t slide, struct dyld_cache_mapping_info *mapping))
{
    char *dscPath = __locate_dsc();

    int dscFd = open(dscPath, O_RDONLY);
    if (dscFd < 0) return;

    struct dyld_cache_header header;
    if (read(dscFd, &header, sizeof(header)) != sizeof(header)) { close(dscFd); return; }

    __dsc_file_enumerate_mappings(dscFd, &header, slide, enumeratorFunc);

    struct dyld_subcache_entry_v1 subcacheEntries[header.subCacheArrayCount];
    lseek(dscFd, header.subCacheArrayOffset, SEEK_SET);
    if (read(dscFd, subcacheEntries, sizeof(struct dyld_subcache_entry_v1) * header.subCacheArrayCount) != sizeof(struct dyld_subcache_entry_v1) * header.subCacheArrayCount) { close(dscFd); return; };

    for (uint32_t i = 0; i < header.subCacheArrayCount; i++) {
        char subcachePath[PATH_MAX];
        strcpy(subcachePath, dscPath);

        // Only supports 1-9
        // Since iOS 15 usually only has one subcache, this shall be fine
        char suffix[3];
        suffix[0] = '.';
        suffix[1] = '1' + i;
        suffix[2] = '\0';
        strcat(subcachePath, suffix);

        int subcacheFd = open(subcachePath, O_RDONLY);
        if (subcacheFd >= 0) {
            struct dyld_cache_header subcacheHeader;
            if (read(subcacheFd, &subcacheHeader, sizeof(subcacheHeader)) != sizeof(subcacheHeader)) continue;
            __dsc_file_enumerate_mappings(subcacheFd, &subcacheHeader, slide, enumeratorFunc);
            close(subcacheFd);
        }
    }

    close(dscFd);
}

int __dsc_attach_signature(int fd, struct dyld_cache_header *header)
{
    fsignatures_t siginfo;
    siginfo.fs_file_start = 0;
    siginfo.fs_blob_start = (void*)header->codeSignatureOffset;
    siginfo.fs_blob_size  = (size_t)(header->codeSignatureSize);
    return fcntl(fd, F_ADDFILESIGS_RETURN, &siginfo);
}

bool __dsc_mapping_make_private(int fd, struct dyld_cache_header *header, uintptr_t slide, struct dyld_cache_mapping_info *mapping)
{
    if (mapping->initProt & PROT_EXEC) {
        int r = __dsc_attach_signature(fd, header);
        if (r == 0) {
            void *r = mmap((void *)(mapping->address + slide), mapping->size, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE, fd, mapping->fileOffset); 
        }
    }
    return true;
}

void dyld_make_text_private(uintptr_t slide)
{
    __dsc_enumerate_mappings(slide, __dsc_mapping_make_private);
}






extern bool real_ZN5dyld3L23mapSplitCacheSystemWideERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE(uintptr_t options, uintptr_t results);
bool HOOK(_ZN5dyld3L23mapSplitCacheSystemWideERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE)(uintptr_t options, uintptr_t results) {
    bool r = real_ZN5dyld3L23mapSplitCacheSystemWideERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE(options, results);

    // bool forcePrivate = *(bool *)(options + 8);
    // if (!forcePrivate) {
    //     slide = *(long *)(results + 8);
    //     dyld_make_text_private(slide);
    // }
    return r;
}




bool HOOK(kdebug_is_enabled)(int param_1) {
    return 1;
}
bool HOOK(_ZN5dyld44APIs26dyld_process_is_restrictedEv)(void) {
    return false;
}


extern bool real_ZNK5dyld313MachOAnalyzer16hasCodeSignatureERjS1_(unsigned int  *param_1,unsigned int *param_2);
bool HOOK(_ZNK5dyld313MachOAnalyzer16hasCodeSignatureERjS1_)(unsigned int  *param_1,unsigned int *param_2) {
    bool r = real_ZNK5dyld313MachOAnalyzer16hasCodeSignatureERjS1_(param_1, param_2);
    return true;
}




void libdyldhook_init(void *kernelParams) {
    
    if (getpid() != 1) {

        giveCSDebugToPID(getpid(), 1, &gTweakCompatEn);
        gTweakCompatEn = 1; // Fix it to one for now...
    }
}
