#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <libproc.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/roothider/common.h>
#include <libjailbreak/util.h>


#include <syslog.h>
#include <os/log.h>
#include <stdio.h>



void jailbreakd_reply_message(JBD_MESSAGE_ID msgId, xpc_object_t reply)
{

    syslog(LOG_ERR, "========= jailbreakd_reply_message enter, syslog");
	os_log(OS_LOG_DEFAULT, "========= jailbreakd_reply_message enter, os_log");
	printf("========= jailbreakd_reply_message enter, printf\n");
	char* desc = NULL;
	JBLogDebug("001 reply message %d with %s", msgId, (desc=xpc_copy_description(reply)));
	if(desc) free(desc);
	int err = xpc_pipe_routine_reply(reply);
	if (err != 0) {
		JBLogError("Error %d sending response", err);
	}
}





#include <spawn.h>
#include <sys/wait.h>
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


int run_shell_command(const char *command) {
    pid_t pid;
    int status;

	extern char **environ; // 使用当前环境变量
    // 使用 /bin/sh -c "command"
    // const char *argv[] = { "/bin/sh", "-c", command, NULL };
    // const char *argv[] = { command, NULL };
	const char *argv[] = { "/usr/bin/zsh", "-c", command, NULL };

	char* path[1024] = {0};
	snprintf(path, 1024, "PATH=/bin:/sbin:/usr/bin:/usr/sbin:%s:%s:%s", ,JBROOT_PATH(@"/bin"), JBROOT_PATH(@"/usr/bin"), JBROOT_PATH(@"/usr/sbin"));	
	// 自定义环境变量
    char *my_env[] = {
        path,   // 设置 PATH              // 自定义变量
        NULL
    };
    // int ret = posix_spawn(&pid, JBROOT_PATH("/usr/bin/touch"), NULL, NULL, (char *const *)argv, environ);
    // int ret = posix_spawn(&pid, JBROOT_PATH("/bin/sh"), NULL, NULL, (char *const *)argv, environ);
    int ret = __posix_spawn_orig_wrapper(&pid, JBROOT_PATH("/usr/bin/zsh"), NULL, (char *const *)argv, my_env);
    if (ret != 0) {
		JBLogError("========= gjj test | run_shell_command failed with error 01, error=%s (errno = %d)", strerror(errno), errno);
        perror("posix_spawn");
        return -1;
    }

    if (waitpid(pid, &status, 0) == -1) {
		JBLogError("========= gjj test | run_shell_command failed with error 02, error=%s (errno = %d)", strerror(errno), errno);
        perror("waitpid");
        return -1;
    }

    // 返回退出状态码
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
		JBLogError("========= gjj test | run_shell_command failed with error 03, error=%s (errno = %d)", strerror(errno), errno);
        // 异常退出，例如被信号终止
        return -1;
    }
}






void jailbreakd_received_message(mach_port_t port)
{

    syslog(LOG_ERR, "========= jailbreakd_received_message enter, syslog");
	os_log(OS_LOG_DEFAULT, "========= jailbreakd_received_message enter, os_log");
	printf("========= jailbreakd_received_message enter, printf\n");

	@autoreleasepool {
		xpc_object_t message = nil;
		int err = xpc_pipe_receive(port, &message);
		if (err != 0) {
			JBLogError("xpc_pipe_receive error %d", err);
			return;
		}

		xpc_object_t reply = xpc_dictionary_create_reply(message);

		JBD_MESSAGE_ID msgId = xpc_dictionary_get_uint64(message, "id");
		
		if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
			audit_token_t auditToken = {0};
			xpc_dictionary_get_audit_token(message, &auditToken);
			uid_t clientUid = audit_token_to_euid(auditToken);
			pid_t clientPid = audit_token_to_pid(auditToken);

			char* desc = NULL;
			JBLogDebug("received message %d from %d(%s) with dictionary: %s", msgId, clientPid, proc_get_path(clientPid,NULL), (desc=xpc_copy_description(message)));
			if(desc) free(desc);

			switch (msgId) {
				case JBD_MSG_CUSTOMIZED_INJECT: {
					JBLogDebug("========= gjj test | jailbreakd_received_message | enter JBD_MSG_CUSTOMIZED_INJECT");
					int64_t result = 0;
					pid_t pid = xpc_dictionary_get_int64(message, "pid");
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					pid_t ppid = proc_get_ppid(pid);
					JBLogDebug("========= gjj test | jailbreakd_received_message | pid=%d, ppid=%d, execfile=%s", pid, ppid, execfile);

					int r = 0;
					char command[1024] = {0}; 
					@try {

						memset(command, 0, sizeof(command));
						snprintf(command, 1024, "%s %s", "ls -al", "/Library/MobileSubstrate/DynamicLibraries/");	
						// snprintf(command, 1024, "%s %s", "/usr/bin/touch", "/Library/MobileSubstrate/DynamicLibraries/test01.txt");
						// r = exec_cmd(JBROOT_PATH("/usr/bin/touch"), "/Library/MobileSubstrate/DynamicLibraries/test01.txt", NULL);
						r = run_shell_command(command);
						if (r == 0) {
							JBLogDebug("========= gjj test | jailbreakd_received_message | exec_cmd touch 01 success");
						} else {
							// JBLogError("========= gjj test | jailbreakd_received_message | exec_cmd touch 01 failed, error=%s (errno = %d)", strerror(errno), errno);
							JBLogError("========= gjj test | jailbreakd_received_message | exec_cmd touch 01 failed");
						}
					}
					@catch (NSException *e) {
						JBLogError("========= gjj test | jailbreakd_received_message | Caught exception");
						JBLogError("========= gjj test | jailbreakd_received_message | Caught exception: %s", e.reason.UTF8String);
					}

					@try {
						memset(command, 0, sizeof(command));
						snprintf(command, 1024, "%s %s", "jbctl trustcache add", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"));
						r = run_shell_command(command);
						if (r == 0) {
							JBLogDebug("========= gjj test | jailbreakd_received_message | exec_cmd jbctl 01 success");
						} else {
							JBLogError("========= gjj test | jailbreakd_received_message | exec_cmd jbctl 01 failed");
						}

						memset(command, 0, sizeof(command));
						snprintf(command, 1024, "%s %d %s", "opainject", pid, JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"));
						r = run_shell_command(command);
						if (r == 0) {
							JBLogDebug("========= gjj test | jailbreakd_received_message | exec_cmd opainject 01 success");
						} else {
							JBLogError("========= gjj test | jailbreakd_received_message | exec_cmd opainject 01 failed");
						}
					}
					@catch (NSException *e) {
						JBLogError("========= gjj test | jailbreakd_received_message | Caught exception");
						JBLogError("========= gjj test | jailbreakd_received_message | Caught exception: %s", e.reason.UTF8String);
					}

					// @try {
					// 	memset(command, 0, sizeof(command));
					// 	snprintf(command, 1024, "%s %s", "jbctl trustcache add", JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"));
					// 	r = run_shell_command3(command);
					// 	if (r == 0) {
					// 		JBLogDebug("========= gjj test | jailbreakd_received_message | exec_cmd jbctl 02 success");
					// 	} else {
					// 		JBLogError("========= gjj test | jailbreakd_received_message | exec_cmd jbctl 02 failed");
					// 	}

					// 	memset(command, 0, sizeof(command));
					// 	snprintf(command, 1024, "%s %d %s", "opainject", pid, JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/cosmos_noinject.dylib"));
					// 	r = run_shell_command3(command);
					// 	if (r == 0) {
					// 		JBLogDebug("========= gjj test | jailbreakd_received_message | exec_cmd opainject 02 success");
					// 	} else {
					// 		JBLogError("========= gjj test | jailbreakd_received_message | exec_cmd opainject 02 failed");
					// 	}
					// }
					// @catch (NSException *e) {
					// 	JBLogError("========= gjj test | jailbreakd_received_message | Caught exception");
					// 	JBLogError("========= gjj test | jailbreakd_received_message | Caught exception: %s", e.reason.UTF8String);
					// }

					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPINLOCK_FIX_ONLY: {
					int64_t result = 0;
					pid_t pid = xpc_dictionary_get_int64(message, "pid");
					bool resume = xpc_dictionary_get_bool(message, "resume");
					pid_t ppid = proc_get_ppid(pid);
					if(ppid == clientPid) {
						JBLogDebug("spinlock fix: client pid=%d, child pid=%d, child's parent pid=%d, child proc=%s", clientPid, pid, ppid, proc_get_path(pid,NULL));

						if(proc_fix_spinlock(pid) == 0) {
							if(resume) kill(pid, SIGCONT);
						} else {
							JBLogError("spinlock fix failed: %d", pid);
							result = -1;
						}

					} else {
						JBLogError("spinlock fix denied: %d", pid);
						result = -1;
					}
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_PATCH_CHILD: {
					int64_t result = 0;
					pid_t pid = xpc_dictionary_get_int64(message, "pid");
					bool resume = xpc_dictionary_get_bool(message, "resume");
					pid_t ppid = proc_get_ppid(pid);
					if(ppid == clientPid) {
						JBLogDebug("spawn patch: client pid=%d, child pid=%d, child's parent pid=%d, child proc=%s", clientPid, pid, ppid, proc_get_path(pid,NULL));

						if(roothide_patch_proc(pid) == 0) {
							if(resume) kill(pid, SIGCONT);
						} else {
							JBLogError("spawn patch failed: %d", pid);
							result = -1;
						}

					} else {
						JBLogError("spawn patch denied: %d", pid);
						result = -1;
					}
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_EXEC_START: {
					bool resume = xpc_dictionary_get_bool(message, "resume");
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("spawn exec start: %d %s", clientPid, execfile);
					int64_t result = spawnExecPatchAdd(clientPid, resume);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_EXEC_CANCEL: {
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("spawn exec cancel: %d %s", clientPid, execfile);
					int64_t result = spawnExecPatchDel(clientPid);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_EXEC_TRACE_START: {
					//dead lock: jbd->ptrace->kernel->amfi port->launchd->spawn amfid->jdb
					dispatch_async(dispatch_get_global_queue(0, 0), ^{
						int64_t result = -1;
						uint64_t traced = xpc_dictionary_get_uint64(message, "traced");
						const char* execfile = xpc_dictionary_get_string(message, "execfile");
						JBLogDebug("exec trace start: %d %s", clientPid, execfile);
						result = execTraceProcess(clientPid, traced);
						xpc_dictionary_set_int64(reply, "result", result);
						jailbreakd_reply_message(msgId, reply);
					});
					reply = nil; //reply later
					break;
				}

				case JBD_MSG_EXEC_TRACE_CANCEL: {
					int64_t result = -1;
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("exec trace cancel: %d %s", clientPid, execfile);
					result = execTraceCancel(clientPid);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SYSTEMWIDE_LOG: {
#ifdef ENABLE_LOGS
					const char* progname = NULL;
					const char* procpath = proc_get_path(clientPid,NULL);
					if(procpath) {
						progname = strrchr(procpath, '/');
						if(progname) progname++; else progname = procpath;
					}
					uint64_t tid = xpc_dictionary_get_uint64(message, "tid");
					const char* log = xpc_dictionary_get_string(message, "log");
					JBLogFunction(JBLogGetLogFilePath("systemwide", NULL), clientPid, tid, progname ? progname : "(null)", "%s", log);
					xpc_dictionary_set_int64(reply, "result", 0);
#else
					abort();
#endif
					break;
				}

				case JBD_MSG_TEST_CALL: {
					int value = xpc_dictionary_get_int64(message, "value");
					JBLogDebug("jailbreakd test call(%llu) from %d,%s", value, clientPid, proc_get_path(clientPid,NULL));	
					xpc_dictionary_set_int64(reply, "result", value * 2);
					
					if(clientUid == 0) {
						abort(); // crashreporter test
					}

					break;
				}
			}
		}
		if (reply) {
			jailbreakd_reply_message(msgId, reply);
		}
	}
}
