#!/usr/bin/env python3
"""Execute the actual permission/task-work functions with controlled kernel stubs.

This checks control flow and failure handling, not a live Android kernel.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path("ksu/kernel")
def function(text, signature):
    start = text.index(signature)
    body = text.index("{", start)
    depth = 1
    end = body + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]

perm = (root / "supercall/perm.c").read_text()
perm = "\n".join(line for line in perm.splitlines() if not line.startswith("#include"))
source = (root / "supercall/supercall.c").read_text()
functions = "\n".join(function(source, name) for name in (
    "static long anon_ksu_ioctl(", "int ksu_install_fd(",
    "static void ksu_install_fd_tw_func(", "static int reboot_handler_pre("))
prelude = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
typedef uint64_t u64;
#define __user
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define O_CLOEXEC 1
#define O_RDWR 2
#define GFP_ATOMIC 0
#define TWA_RESUME 0
#define KSU_INSTALL_MAGIC1 ((int)0xdeadbeefU)
#define KSU_INSTALL_MAGIC2 ((int)0xcafebabeU)
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define IS_ERR(p) ((p)==NULL)
#define PTR_ERR(p) (-ENOMEM)
struct { unsigned val; } uid;
#define current_uid() uid
static bool manager, allow_uid, domain;
static bool is_manager(void) { return manager; }
static bool is_ksu_domain(void) { return domain; }
static bool ksu_is_allow_uid_for_current(unsigned value) {
    return value == 0 ? domain : allow_uid;
}
static struct { int pid; } task = {123};
#define current (&task)
struct file { int unused; } fake_file;
static const int anon_ksu_fops = 0;
struct callback_head { void (*func)(struct callback_head*); };
struct ksu_install_fd_tw { struct callback_head cb; int *outp; };
struct kprobe { int unused; };
struct pt_regs { unsigned long p[4]; };
#define PT_REAL_REGS(p) (p)
#define PT_REGS_PARM1(regs) ((regs)->p[0])
#define PT_REGS_PARM2(regs) ((regs)->p[1])
#define PT_REGS_SYSCALL_PARM4(regs) ((regs)->p[3])
static int allocations, queued, installs, dispatches, closes;
static bool fail_alloc, fail_queue, fail_file;
static int next_fd = 7;
static struct callback_head *pending;
static void *kzalloc(size_t n, int flags) {
    (void)flags; if(fail_alloc) return NULL; ++allocations; return calloc(1,n);
}
static void kfree(void *p) { --allocations; free(p); }
static int task_work_add(void *t, struct callback_head *cb, int flags) {
    (void)t;(void)flags;if(fail_queue)return -ESRCH;++queued;pending=cb;return 0;
}
static int get_unused_fd_flags(int flags) { (void)flags;return next_fd; }
static void put_unused_fd(int fd) { (void)fd; }
static struct file *anon_inode_getfile(const char *s,const void *ops,void *context,int flags) {
    (void)s;(void)ops;(void)context;(void)flags;return fail_file ? NULL : &fake_file;
}
static void fd_install(int fd,struct file *f) { (void)fd;(void)f;++installs; }
static int copy_to_user(void *p, const void *v,size_t n) { if(!p)return 1;memcpy(p,v,n);return 0; }
static void ksu_close_fd(int fd) { assert(fd>=0);++closes; }
static long ksu_supercall_handle_ioctl(unsigned cmd,void *arg) {
    (void)cmd;(void)arg;++dispatches;return 42;
}
static bool driver_client_authorized(void);
'''
tests = r'''
int main(void) {
    uid.val=10051;assert(!driver_client_authorized());
    struct pt_regs regs = {{KSU_INSTALL_MAGIC1,KSU_INSTALL_MAGIC2,0,0}};
    int reply=-1777;regs.p[3]=(unsigned long)&reply;
    assert(reboot_handler_pre(NULL,&regs)==0);
    assert(reply==-1777 && allocations==0 && queued==0 && installs==0);
    assert(ksu_install_fd()==-EPERM);
    assert(anon_ksu_ioctl(NULL,1,0)==-EPERM && dispatches==0);
    manager=true;assert(driver_client_authorized() && allowed_for_su());
    reboot_handler_pre(NULL,&regs);assert(queued==1 && reply==-1777);
    manager=false;pending->func(pending);
    assert(reply==-1777 && allocations==0 && installs==0);
    allow_uid=true;reboot_handler_pre(NULL,&regs);pending->func(pending);
    assert(reply==7 && allocations==0 && installs==1);
    assert(anon_ksu_ioctl(NULL,1,0)==42 && dispatches==1);
    allow_uid=false;assert(anon_ksu_ioctl(NULL,1,0)==-EPERM && dispatches==1);
    uid.val=2000;assert(!driver_client_authorized());
    uid.val=0;assert(driver_client_authorized());assert(!allowed_for_su());
    domain=true;assert(allowed_for_su());
    uid.val=1000;assert(driver_client_authorized()); // reduced UID in trusted KSU domain
    domain=false;uid.val=10051;manager=true;
    fail_alloc=true;reboot_handler_pre(NULL,&regs);assert(allocations==0);
    fail_alloc=false;fail_queue=true;reboot_handler_pre(NULL,&regs);assert(allocations==0);
    fail_queue=false;fail_file=true;reply=-1777;
    reboot_handler_pre(NULL,&regs);pending->func(pending);
    assert(reply==-1777 && allocations==0);
    fail_file=false;regs.p[3]=0;reboot_handler_pre(NULL,&regs);pending->func(pending);
    assert(closes==1 && allocations==0);
    puts("PASS: unauthorized, authorized, revocation, FD transfer, loader, grant policy, allocation/queue/copy failures");
}
'''
# The function remains public in production; the harness declaration matches it.
prelude = prelude.replace("static bool driver_client_authorized(void);", "bool driver_client_authorized(void);")
with tempfile.TemporaryDirectory() as temp:
    path = Path(temp)/"contract.c"
    path.write_text(prelude + perm + functions + tests)
    binary = Path(temp)/"contract"
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-parameter",str(path),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)

selinux = (root / "feature/selinux_hide.c").read_text()
feature_functions = "\n".join(function(selinux, signature) for signature in (
    "static int selinux_hide_feature_get(", "static int selinux_hide_feature_set("))
stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint64_t u64;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define pr_info(...) ((void)0)
static int selinux_hide_mutex;
static void mutex_lock(int *p){(void)p;}
static void mutex_unlock(int *p){(void)p;}
static bool ksu_selinux_hide_enabled, ksu_selinux_hide_running;
static int error, calls;
static int ksu_selinux_hide_enable(void){++calls;return error;}
'''
test = r'''
int main(void) {
    u64 value=88;error=-38;
    assert(selinux_hide_feature_set(1)==-38);selinux_hide_feature_get(&value);
    assert(value==0 && !ksu_selinux_hide_running);
    error=0;assert(selinux_hide_feature_set(1)==0);selinux_hide_feature_get(&value);
    assert(value==1 && calls==2);
    assert(selinux_hide_feature_set(0)==0);selinux_hide_feature_get(&value);
    assert(value==0 && ksu_selinux_hide_running && calls==2);
    assert(selinux_hide_feature_set(1)==0);selinux_hide_feature_get(&value);
    assert(value==1 && calls==2);
    puts("PASS: failed activation reports disabled; successful activation and guarded disable/re-enable");
}
'''
with tempfile.TemporaryDirectory() as temp:
    path=Path(temp)/"activation.c";path.write_text(stub+feature_functions+test)
    binary=Path(temp)/"activation"
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(path),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)

dispatch = (root / "supercall/dispatch.c").read_text()
for name in ("GET_INFO", "GET_INFO_LEGACY", "CHECK_SAFEMODE"):
    block=dispatch.split(f'.name = "{name}"',1)[1].split("}",1)[0]
    assert ".perm_check = driver_client_authorized" in block
assert selinux.count("!READ_ONCE(ksu_selinux_hide_enabled)") == 3
assert 'KSU_PACKAGE_NAME' in (root / "manager/throne_tracker.c").read_text()
print("PASS: current/legacy information gating, disabled-hook guards, pinned package")
