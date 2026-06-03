import os
import sys
import argparse
import subprocess
import win32api
import win32con
import win32security
import win32process
import win32job
import win32event

def main():
    parser = argparse.ArgumentParser(description="Windows Process Sandboxing Wrapper")
    parser.add_argument("--provider", required=True, help="MCP provider name")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run")
    
    args = parser.parse_args()
    
    # Remove leading '--' if present in command list
    cmd_list = args.cmd
    if cmd_list and cmd_list[0] == "--":
        cmd_list = cmd_list[1:]
        
    if not cmd_list:
        print("[SANDBOX] Error: No command specified to run.", file=sys.stderr)
        sys.exit(1)
        
    # Use standard library function to format command line exactly as Windows expects
    cmd_line = subprocess.list2cmdline(cmd_list)
    
    # 1. Open current process token
    h_token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY | win32con.TOKEN_ASSIGN_PRIMARY
    )
    
    # 2. Create restricted token (strip Administrators SID to enforce standard user NTFS boundaries)
    sids_to_disable = []
    try:
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
        sids_to_disable.append((admin_sid, 0))
    except Exception as e:
        print(f"[SANDBOX] Warning: Failed to create admin SID: {e}", file=sys.stderr)
        
    try:
        r_token = win32security.CreateRestrictedToken(
            h_token,
            0,
            sids_to_disable,
            None,
            None
        )
    except Exception as e:
        print(f"[SANDBOX] Error: Failed to create restricted token: {e}", file=sys.stderr)
        sys.exit(1)
        
    # 3. Duplicate as primary token for CreateProcessAsUser
    try:
        p_token = win32security.DuplicateTokenEx(
            r_token,
            win32security.SecurityImpersonation,
            win32con.TOKEN_ALL_ACCESS,
            win32security.TokenPrimary
        )
    except Exception as e:
        print(f"[SANDBOX] Error: Failed to duplicate primary token: {e}", file=sys.stderr)
        sys.exit(1)
        
    # 4. Set up standard handles for redirection
    si = win32process.STARTUPINFO()
    si.dwFlags = win32process.STARTF_USESTDHANDLES
    si.hStdInput = win32api.GetStdHandle(win32api.STD_INPUT_HANDLE)
    si.hStdOutput = win32api.GetStdHandle(win32api.STD_OUTPUT_HANDLE)
    si.hStdError = win32api.GetStdHandle(win32api.STD_ERROR_HANDLE)
    
    # 5. Create Job Object and configure limits
    try:
        job_name = f"mcp-job-{args.provider}-{os.getpid()}"
        h_job = win32job.CreateJobObject(None, job_name)
        
        limit_info = win32job.QueryInformationJobObject(h_job, win32job.JobObjectExtendedLimitInformation)
        limit_flags = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        
        # Enforce strict 256MB memory limit per process
        limit_flags |= win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
        limit_info['ProcessMemoryLimit'] = 256 * 1024 * 1024
        
        # Enforce strict 512MB memory limit for the entire job
        limit_flags |= win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
        limit_info['JobMemoryLimit'] = 512 * 1024 * 1024
        
        limit_info['BasicLimitInformation']['LimitFlags'] = limit_flags
        win32job.SetInformationJobObject(h_job, win32job.JobObjectExtendedLimitInformation, limit_info)
    except Exception as e:
        print(f"[SANDBOX] Error: Failed to create or configure Job Object: {e}", file=sys.stderr)
        sys.exit(1)
        
    # 6. Spawn process suspended using CreateProcessAsUser
    # DEBUG: show launch context before CreateProcessAsUser
    print(f"[SANDBOX] Launching sandbox: cwd={os.getcwd()}, cmd_line={cmd_line}, env_ALIGNED={{'ALLOWED_PATHS': os.getenv('ALLOWED_PATHS'), 'SPIFFE_ID': os.getenv('SPIFFE_ID')}}", file=sys.stderr)
    try:
        # inherit_handles=True to inherit standard I/O pipes
        h_process, h_thread, pid, tid = win32process.CreateProcessAsUser(
            p_token,
            None,
            cmd_line,
            None,
            None,
            True,  # inherit handles
            win32process.CREATE_SUSPENDED,
            os.environ.copy(),  # Propagate current environment variables explicitly
            None,
            si
        )
    except Exception as e:
        print(f"[SANDBOX] Error: CreateProcessAsUser failed to spawn child: {e}", file=sys.stderr)
        sys.exit(1)
        
    # 7. Assign process to Job Object
    try:
        win32job.AssignProcessToJobObject(h_job, h_process)
    except Exception as e:
        print(f"[SANDBOX] Error: Failed to assign process to Job Object: {e}", file=sys.stderr)
        win32api.TerminateProcess(h_process, 1)
        win32api.CloseHandle(h_process)
        win32api.CloseHandle(h_thread)
        sys.exit(1)
        
    # 8. Resume main thread to begin sandboxed execution
    win32process.ResumeThread(h_thread)
    
    # 9. Wait for child to exit
    win32event.WaitForSingleObject(h_process, win32event.INFINITE)
    exit_code = win32process.GetExitCodeProcess(h_process)
    
    # Clean up handles
    win32api.CloseHandle(h_process)
    win32api.CloseHandle(h_thread)
    
    # Keep Job Object handle alive until wait finishes
    win32api.CloseHandle(h_job)
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
