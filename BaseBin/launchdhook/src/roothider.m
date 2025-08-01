#import <Foundation/Foundation.h>
#include <stdbool.h>

#include <spawn.h>
#include <substrate.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/roothider/common.h>
#include <libjailbreak/util.h>

#include "../systemhook/src/common.h"
#include "../systemhook/src/envbuf.h"

// #include <sys/proc_info.h>

#include <syslog.h>
#include <os/log.h>
#include <stdio.h>

#include <spawn.h>
#include <sys/wait.h>


const char* HOOK_DYLIB_PATH = NULL;

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
extern int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *__restrict, int *__restrict) __API_AVAILABLE(macos(10.8), ios(6.0));
extern int posix_spawnattr_setexceptionports_np(posix_spawnattr_t *__restrict, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

//from launchdhook/spawn_hook.c
extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);
extern int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);

//from systemhook/roothide_common.c
int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

int (*sysctlbyname_orig)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	if (strcmp(name, "vm.shared_region_pivot") == 0) {
		return 0;
	}
	return sysctlbyname_orig(name, oldp, oldlenp, newp, newlen);
}

void roothide_launchd_preinit()
{
	JBLogDebug("roothide_launchd_preinit");

#ifdef ENABLE_LOGS
	enableJBDLog(JBLogDebugFunction, JBLogErrorFunction);
#endif

	exec_set_patch(false);
}

void roothide_launchd_postinit(bool firstLoad)
{
	JBLogDebug("roothide_launchd_postinit: firstLoad=%d", firstLoad);

	launchdhookFirstLoad = firstLoad;

	exec_set_patch(true);

	if(firstLoad)
	{
		HOOK_DYLIB_PATH = "";
		
		if (__builtin_available(iOS 16.0, *))
		{
			hideDeveloperMode();
		}
		
#ifdef __arm64e__
		if (!__builtin_available(iOS 16.0, *))
		{
			if(roothide_config_set_spinlock_fix(dyld_patch_enabled()) != 0) {
				launchd_panic("roothide_config_set_spinlock_fix failed");
				return;
			}
		}
#endif
	}
	else
	{		
		NSString* systemhookFilePath = [NSString stringWithFormat:@"%@/systemhook-%016llX.dylib", JBROOT_PATH(@"/basebin"), jbinfo(jbrand)];

		if([NSFileManager.defaultManager fileExistsAtPath:JBROOT_PATH(@"/basebin/systemhook.dylib")])
		{
			[NSFileManager.defaultManager removeItemAtPath:systemhookFilePath error:nil];
			assert([NSFileManager.defaultManager moveItemAtPath:JBROOT_PATH(@"/basebin/systemhook.dylib") toPath:systemhookFilePath error:nil]);
		}
		
		assert(unsandbox("/usr/lib", systemhookFilePath.fileSystemRepresentation) == 0);

		//new "real path"
		asprintf(&HOOK_DYLIB_PATH, "/usr/lib/systemhook-%016llX.dylib", jbinfo(jbrand));
	}

	if (__builtin_available(iOS 16.0, *))
	{
		void* __sysctl_orig = NULL;
		void* __sysctlbyname_orig = NULL;
		MSHookFunction(&__sysctl, (void *) __sysctl_hook, &__sysctl_orig);
		MSHookFunction(&__sysctlbyname, (void *) __sysctlbyname_hook, &__sysctlbyname_orig);
	}
#ifdef __arm64e__
	else 
	{
		// iOS15 arm64e only
		MSHookFunction(sysctlbyname, (void *)sysctlbyname_hook, (void **)&sysctlbyname_orig);
	}
#endif

	if(!firstLoad)
	{
		int ret = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));
		if (ret != 0) {
			launchd_panic("ensure dyld trustcache failed: %d", ret);
			return;
		}
	}

	// load jailbreakd after applying hooks
	assert(initJailbreakd(firstLoad) == 0);
}

extern int roothide_trust_executable_recurse(const char *executablePath, xpc_object_t preferredArchsArray);
int roothide_launchd_trust_executable(const char* path)
{
	return dyld_patch_enabled() ? systemwide_trust_file_by_path(path) : roothide_trust_executable_recurse(path, NULL);
}

int roothide_launchd___posix_spawn_posthook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	//spawn_prehook ensure this is always available
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	if (should_suspend) {
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	}

	// on some devices dyldhook may fail due to vm_protect(VM_PROT_READ|VM_PROT_WRITE), 2, (os/kern) protection failure in dsc::__DATA_CONST:__const, 
	// so we need to disable dyld-in-cache here. (or we can use VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
	char **envc = envbuf_mutcopy((const char **)envp);
	if(envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	}

#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		if(!dyld_patch_enabled() && process_force_dyld_patch(path, argv)) {
			envbuf_setenv(&envc, "SPINLOCK_FIX_DISABLED", "1");
		}
	}
#endif

	int pid = 0;
	int ret = __posix_spawn_orig_wrapper(&pid, path, desc, argv, envc);
	if(pidp) *pidp = pid;

	envbuf_free(envc);
	
	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

	if (ret == 0 && pid > 0) {
		if(should_suspend) {
			jbdSpawnPatchChild(pid, should_resume);
		}
	} else {
		JBLogError("spawn failed: %d %s, pid=%d", ret, strerror(ret), pid);
	}

	return ret;
}

int roothide_launchd___posix_spawn__spinlock_fix_only(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	//spawn_prehook ensure this is always available
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	bool should_resume = (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);

	int pid = 0;
	int ret = __posix_spawn_orig_wrapper(&pid, path, desc, argv, envp);
	if(pidp) *pidp = pid;
	
	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

	if (ret == 0 && pid > 0) {
		jbdSpinlockFixOnly(pid, should_resume);
	} else {
		JBLogError("spawn failed: %d %s, pid=%d", ret, strerror(ret), pid);
	}

	return ret;
}


// /* Status values. */
// #define SIDL    1               /* Process being created by fork. */
// #define SRUN    2               /* Currently runnable. */
// #define SSLEEP  3               /* Sleeping on an address. */
// #define SSTOP   4               /* Process debugging or suspension. */
// #define SZOMB   5               /* Awaiting collection by parent. */

// int proc_paused(pid_t pid, bool* paused)
// {
//     *paused = false;

//     struct proc_bsdinfo procInfo = {0};
//     int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
//     if (ret != sizeof(procInfo)) {
//         return -1;
//     }

//     if (procInfo.pbi_status == SSTOP) {
//         *paused = true;
//     } else if (procInfo.pbi_status != SRUN) {
//         return -1;
//     }

//     return 0;
// }


#include <errno.h>
#include <string.h>
#include "NSTask.h"


int run_shell_command3(const char *command) {
	JBLogDebug("========= gjj test | run_shell_command3 | command %s", command);
    NSTask *terminalOperation = [[NSTask alloc] init];
     
    NSPipe *pipe;
    pipe = [NSPipe pipe];
    [terminalOperation setStandardOutput: pipe];
    [terminalOperation setStandardError: pipe];

    NSFileHandle *file = [pipe fileHandleForReading];
     
        
	NSDictionary<NSString *, NSString *> *environment = @{
		@"PATH":[NSString stringWithFormat:@"/bin:/sbin:/usr/bin:/usr/sbin:%@:%@:%@", 
			JBROOT_PATH(@"/bin"), 
			JBROOT_PATH(@"/usr/bin"), 
			JBROOT_PATH(@"/usr/sbin")]
	};
	[terminalOperation setEnvironment:environment];
	terminalOperation.launchPath = JBROOT_PATH(@"/usr/bin/zsh");
        
     
    [terminalOperation setArguments:@[@"-c", [NSString stringWithUTF8String:command]]];
    [terminalOperation launch];
     NSMutableData *mut_result = [NSMutableData new];
     [[NSNotificationCenter defaultCenter] addObserverForName:NSFileHandleReadCompletionNotification object:file queue:nil usingBlock:^(NSNotification *notification) {
         NSData *data = notification.userInfo[NSFileHandleNotificationDataItem];
         if (data.length > 0) {
             [mut_result appendData:data];
             [file readInBackgroundAndNotify];
         } else {
             
         }
     }];

     [file readInBackgroundAndNotify];
     [terminalOperation waitUntilExit];
     
    NSString *strResult = [[NSString alloc] initWithData: mut_result encoding: NSUTF8StringEncoding];
	JBLogDebug("========= gjj test | run_shell_command3 | result %s", strResult.UTF8String);
    return strResult.length > 0;
}

int run_shell_command2(const char *command) {
    pid_t pid;
    int status;

    // 使用 /bin/sh -c "command"
    const char *argv[] = { JBROOT_PATH("/bin/sh"), "-c", command, NULL };
	extern char **environ; // 使用当前环境变量

    // int ret = posix_spawn(&pid, JBROOT_PATH("/bin/sh"), NULL, NULL, (char *const *)argv, environ);
    int ret = __posix_spawn_orig_wrapper(&pid, JBROOT_PATH("/bin/sh"), NULL, (char *const *)argv, environ);
    if (ret != 0) {
		JBLogError("__posix_spawn failed with error 01, error=%s (errno = %d)", strerror(errno), errno);
        perror("posix_spawn");
        return -1;
    }

    if (waitpid(pid, &status, 0) == -1) {
		JBLogError("__posix_spawn failed with error 02, error=%s (errno = %d)", strerror(errno), errno);
        perror("waitpid");
        return -1;
    }

    // 返回退出状态码
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
		JBLogError("__posix_spawn failed with error 03, error=%s (errno = %d)", strerror(errno), errno);
        // 异常退出，例如被信号终止
        return -1;
    }
}

int run_shell_command(const char *command) {
    pid_t pid;
    int status;

    // 使用 /bin/sh -c "command"
    const char *argv[] = { "/bin/sh", "-c", command, NULL };
	extern char **environ; // 使用当前环境变量

	// // 自定义环境变量
    // char *my_env[] = {
    //     "PATH=/bin:/usr/bin:/var/jb/usr/bin",   // 设置 PATH
    //     "MYVAR=HelloWorld",                     // 自定义变量
    //     NULL
    // };
    // int ret = posix_spawn(&pid, JBROOT_PATH("/bin/sh"), NULL, NULL, (char *const *)argv, environ);
    // int ret = __posix_spawn_orig_wrapper(&pid, JBROOT_PATH("/bin/sh"), NULL, (char *const *)argv, environ);
    int ret = __posix_spawn_orig(&pid, JBROOT_PATH("/bin/sh"), NULL, (char *const *)argv, environ);
    if (ret != 0) {
		JBLogError("__posix_spawn failed with error 01, error=%s (errno = %d)", strerror(errno), errno);
        perror("posix_spawn");
        return -1;
    }

    if (waitpid(pid, &status, 0) == -1) {
		JBLogError("__posix_spawn failed with error 02, error=%s (errno = %d)", strerror(errno), errno);
        perror("waitpid");
        return -1;
    }

    // 返回退出状态码
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
		JBLogError("__posix_spawn failed with error 03, error=%s (errno = %d)", strerror(errno), errno);
        // 异常退出，例如被信号终止
        return -1;
    }
}


int roothide_launchd___posix_spawn_prehook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}
	posix_spawnattr_t attrp = &desc->attrp;

	if(!path) {
		return __posix_spawn_hook(pidp, path, desc, argv, envp);
	}

	if(strcmp(path, "/sbin/launchd") == 0) {
		short flags = 0;
		posix_spawnattr_getflags(attrp, &flags);
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
		return __posix_spawn_hook(pidp, path, desc, argv, envp);
	}

	if(path && string_has_suffix(path, "/Dopamine.app/Dopamine"))
	{
		/* if the jailbreak activation is interrupted for some reason, 
			we prevent the app from relaunching to prevent the system from being in an unknown state */
		if(launchdhookFirstLoad) {
#ifdef ENABLE_LOGS
			launchd_panic("reboot device due to jailbreak failure!");
#endif
			return EPERM;
		}

		char roothidefile[PATH_MAX];
		snprintf(roothidefile, sizeof(roothidefile), "%s.roothide", path);
		if(access(roothidefile, F_OK) != 0) {
			return EPERM;
		}
	}

	if(launchdhookFirstLoad) {
		//we should not enable system-wide injection until the jailbreak is finalized (userspace reboot).
		return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	}
	
	if(string_has_suffix(path, "/basebin/jailbreakd")) {
		return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	}


	// mitigate spinlock panic for ios15(A12+) devices

	bool iOS15Arm64e = false;
	bool choicyBlocked = false;
#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		iOS15Arm64e = true;
		if(envbuf_getenv(envp, "_SafeMode") || envbuf_getenv(envp, "_MSSafeMode")) {
			if(path && isRemovableBundlePath(path) && !hasTrollstoreMarker(path)) {
				choicyBlocked = true;
			}
		}
	}
#endif

	bool roothideBlacklisted = isBlacklistedPath(path);
	if (choicyBlocked || roothideBlacklisted)
	{
		int ret;

		JBLogDebug("blacklisted app %s", path);

		if(dyld_patch_enabled() && iOS15Arm64e && roothideBlacklisted && (strstr(path, "/PlugIns/") || strstr(path, ".appex/"))) {
			JBLogDebug("prevent blacklisted app's extension from running: ", path);
			ret = EPERM;
		}
		else if(dyld_patch_enabled() && iOS15Arm64e && roothideBlacklisted && (envbuf_getenv(envp, "ActivePrewarm") || envbuf_getenv(envp, "DYLD_USE_CLOSURES"))) {
			JBLogDebug("prevent blacklisted app from prewarming: ", path);
			ret = EPERM;
		}
		else
		{
			char **envc = envbuf_mutcopy((const char **)envp);

			//choicy may set these 
			envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
	
			/* According to xnu, the new thread in new process will not run in userland until after copyout pid
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4321
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4882
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4933
			*/
	
			/* and posix_spawn->kernel->amfid->launchd may cause xpc dead loop so we can't use lock-spawn-unlock here */
	
			volatile pid_t* blacklistedPidp = allocBlacklistProcessId();
	
			if(roothideBlacklisted || !dyld_patch_enabled() || !iOS15Arm64e) {
				if(string_has_suffix(path, "/haha.app/haha")) {

					NSLog(@"========= add POSIX_SPAWN_START_SUSPENDED haha enter, NSLog");
					syslog(LOG_ERR, "========= add POSIX_SPAWN_START_SUSPENDED haha enter, syslog");
					os_log(OS_LOG_DEFAULT, "========= add POSIX_SPAWN_START_SUSPENDED haha enter, os_log");
					printf("========= add POSIX_SPAWN_START_SUSPENDED haha enter, printf\n");

					JBLogDebug("========= gjj test | add POSIX_SPAWN_START_SUSPENDED in %s", path);
					short flags = 0;
					posix_spawnattr_getflags(attrp, &flags);
					posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
				}
				ret = __posix_spawn_orig_wrapper(blacklistedPidp, path, desc, argv, envc);
				JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | __posix_spawn_orig_wrapper ret %d in %s", ret, path);

				if(string_has_suffix(path, "/haha.app/haha")) {
					JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | enter check pid %d is paused, in %s", *blacklistedPidp, path);
						
					while(true) {
						// JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | check pid %d is paused, in %s", *blacklistedPidp, path);
						bool paused = false;
						if (proc_paused(*blacklistedPidp, &paused) != 0) {
							JBLogError("========= gjj test | Failed to check if process(%d) is paused", *blacklistedPidp);
							return -1;
						}
						if(paused) {
							break;
						}
						usleep(10*1000);
					}


					int r0 = jbdCustomizedInject(*blacklistedPidp, path, true);
					JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | jbdCustomizedInject result %d", r0);



					JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd begin in %s", path);
					int r = 0;

					char command[1024] = {0}; 
    				// snprintf(command, 1024, "%s %s", JBROOT_PATH("/usr/bin/touch"), JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test01.txt"));
					// r = run_shell_command(command);
					// // r = system(command);
					// // r = exec_cmd("touch", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test.txt"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 01 success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 01 failed in %s", path);
					// }

					memset(command, 0, sizeof(command));
    				// snprintf(command, 1024, "%s %s", "touch", "/Library/MobileSubstrate/DynamicLibraries/test02.txt");
    				snprintf(command, 1024, "%s %s", "ls -al", "/Library/MobileSubstrate/DynamicLibraries/");
					r = run_shell_command3(command);
					// r = system(command);
					// r = exec_cmd("touch", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test.txt"), NULL);
					if (r == 0) {
						JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 02 success in %s", path);
					} else {
						JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 02 failed in %s", path);
					}

					// memset(command, 0, sizeof(command));
    				// snprintf(command, 1024, "%s %s", JBROOT_PATH("/usr/bin/touch"), "/Library/MobileSubstrate/DynamicLibraries/test02.1.txt");
					// r = run_shell_command(command);
					// // r = system(command);
					// // r = exec_cmd("touch", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test.txt"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 02.1 success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 02.1 failed in %s", path);
					// }

					// memset(command, 0, sizeof(command));
    				// snprintf(command, 1024, "%s %s", "touch", "/Library/MobileSubstrate/DynamicLibraries/test03.txt");
					// r = run_shell_command2(command);
					// // r = system(command);
					// // r = exec_cmd("touch", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test.txt"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 03 success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 03 failed in %s", path);
					// }

					// memset(command, 0, sizeof(command));
    				// snprintf(command, 1024, "%s %s", JBROOT_PATH("/usr/bin/touch"), JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test04.txt"));
					// r = run_shell_command2(command);
					// // r = system(command);
					// // r = exec_cmd("touch", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test.txt"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 04 success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 04 failed in %s", path);
					// }

					// memset(command, 0, sizeof(command));
    				// snprintf(command, 1024, "%s %s", JBROOT_PATH("/usr/bin/touch"), "/Library/MobileSubstrate/DynamicLibraries/test04.1.txt");
					// r = run_shell_command2(command);
					// // r = system(command);
					// // r = exec_cmd("touch", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test.txt"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 04.1 success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 04.1 failed in %s", path);
					// }

					// // memset(command, 0, sizeof(command));
    				// // snprintf(command, 1024, "%s %s", "touch", "/Library/MobileSubstrate/DynamicLibraries/test04.txt");
					// // r = run_shell_command2(command);
					// // r = system(command);
					// r = exec_cmd(JBROOT_PATH("/usr/bin/touch"), "/Library/MobileSubstrate/DynamicLibraries/test05.txt", NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 05 success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 05 failed, error=%s (errno = %d)", strerror(errno), errno);
					// }


					// r = exec_cmd(JBROOT_PATH("/usr/bin/touch"), JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/test06.txt"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 06 success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd touch 06 failed, error=%s (errno = %d)", strerror(errno), errno);
					// }





					// memset(command, 0, sizeof(command));
					// snprintf(command, 1024, "%s trustcache add %s", JBROOT_PATH("/basebin/jbctl"), JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"));
					// // JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | command: %s", command);
					// r = run_shell_command(command);
					// // r = exec_cmd(JBROOT_PATH("/basebin/jbctl"), "trustcache", "add", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd jbctl success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd jbctl failed, error=%s (errno = %d)", strerror(errno), errno);
					// }

					// // char strPid[10] = {0}; 
    				// // snprintf(strPid, 10, "%d", *blacklistedPidp);
					// memset(command, 0, sizeof(command));
					// snprintf(command, 1024, "%s %d %s", JBROOT_PATH("/basebin/opainject"), *blacklistedPidp, JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"));
					// // JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | command: %s", command);
					// r = run_shell_command(command);
					// // r = exec_cmd(JBROOT_PATH("/basebin/opainject"), strPid, JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"), NULL);
					// if (r == 0) {
					// 	JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd opainject success in %s", path);
					// } else {
					// 	JBLogError("========= gjj test | roothide_launchd___posix_spawn_prehook | exec_cmd opainject failed, error=%s (errno = %d)", strerror(errno), errno);
					// }

					usleep(20*1000*1000);

					JBLogDebug("========= gjj test | roothide_launchd___posix_spawn_prehook | SIGCONT pid %d in %s", *blacklistedPidp, path);
					kill(*blacklistedPidp, SIGCONT);
				}


			} else {
				ret = roothide_launchd___posix_spawn__spinlock_fix_only(blacklistedPidp, path, desc, argv, envc);
			}
	
			pid_t pid = *blacklistedPidp;
			if(pidp) *pidp = *blacklistedPidp;

			commitBlacklistProcessId(blacklistedPidp); // will release blacklistedPidp
			blacklistedPidp = NULL;

			envbuf_free(envc);
				
			if(ret==0 && pid>0) {
				short flags = 0;
				posix_spawnattr_getflags(attrp, &flags);
				if((flags & POSIX_SPAWN_START_SUSPENDED) != 0) {
					platform_set_process_debugged(pid, false);
				}
			}
		}
	
		return ret;
	}

	return __posix_spawn_hook(pidp, path, desc, argv, envp);
}

