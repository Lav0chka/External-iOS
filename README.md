Creating an external iOS cheat requires a jailbroken device (using tools like TrollStore for persistent exploits) and involves several key steps:

1. Obtaining the Process ID (PID):



```objectivec
pid_t get_Pid(NSString GameName) {
    size_t length = 0;
    int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int err = sysctl((int )name, (sizeof(name) / sizeof(name)) - 1, NULL, &length, NULL, 0);

    if (err == -1) err = errno;
    if (err == 0) {
        struct kinfo_proc procBuffer = (struct kinfo_proc )malloc(length);
        if (procBuffer == NULL) {
            free(procBuffer);
            return -1;
        }
        sysctl((int )name, (sizeof(name) / sizeof(name)) - 1, procBuffer, &length, NULL, 0);

        int count = (int)length / sizeof(struct kinfo_proc);
        for (int i = 0; i < count; ++i) {
            NSString procname = [NSString stringWithUTF8String:procBuffer[i].kp_proc.p_comm];
            pid_t pid = procBuffer[i].kp_proc.p_pid;
            if ([GameName rangeOfString:procname options:NSCaseInsensitiveSearch].location != NSNotFound) {
                free(procBuffer);
                return pid;
            }
        }
        free(procBuffer);
    }
    return -1;
}
```



2. Obtaining the Task Port:

The `task_for_pid_workaround` function aims to get the task port without directly using `task_for_pid`, which is more likely to trigger anti-cheat detection. It iterates through all tasks, checking PIDs until it finds a match.

```objectivec
task_port_t task_for_pid_workaround(int Pid) {
    host_t myhost = mach_host_self();
    task_port_t psDefault, psDefault_control;
    task_array_t tasks;
    mach_msg_type_number_t numTasks;
    kern_return_t kr;

    kr = processor_set_default(myhost, &psDefault);
    if (kr != KERN_SUCCESS) { NSLog(@"processor_set_default failed: %x", kr); return MACH_PORT_NULL; }

    kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
    if (kr != KERN_SUCCESS) { NSLog(@"host_processor_set_priv failed: %x", kr); return MACH_PORT_NULL; }

    kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
    if (kr != KERN_SUCCESS) { NSLog(@"processor_set_tasks failed: %x", kr); return MACH_PORT_NULL; }

    for (int i = 0; i < numTasks; i++) {
        int pid;
        pid_for_task(tasks[i], &pid);
        if (pid == Pid) return tasks[i];
    }
    return MACH_PORT_NULL;
}
```



3. Finding the Base Address:



```objectivec

    vm_map_offset_t vmoffset = 0;
    vm_map_size_t vmsize = 0;
    uint32_t nesting_depth = 0;
    struct vm_region_submap_info_64 vbr;
    mach_msg_type_number_t vbrcount = 16;
    kern_return_t kret = mach_vm_region_recurse(task, &vmoffset, &vmsize, &nesting_depth, (vm_region_recurse_info_t)&vbr, &vbrcount);
    // vmoffset - base address 

    // this code can be used only if u need slide of main executable. otherwise u need task_info

```

uisng this u may avoid a lot of anticheat systems and so on, **but not all.**

so then ofc u can use vm_read/write to do anything.
actually u can even call methods externally with remote threads and so on, kinda funny tho 

