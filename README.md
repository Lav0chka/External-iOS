
so basicly to make an external cheat on iOS you need just few things. This may require TrollStore for its coretrust exploit or just jb

1) to read another application/proccess memory u need its PID 

you can use this shit or use own

```markdown
pid_t get_Pid(NSString* GameName)
{
    size_t length = 0;
    static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int err = sysctl_((int *)name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0);
    
    if (err == -1) err = errno;
    if (err == 0) {
        procBuffer = (struct kinfo_proc *)malloc(length);
        
        if(procBuffer == NULL)
        {
            free(procBuffer);
            return -1;
        }
            
        sysctl_((int *)name, (sizeof(name) / sizeof(*name)) - 1, procBuffer, &length, NULL, 0);
        
        int count = (int)length / sizeof(struct kinfo_proc);
        for (int i = 0; i < count; ++i) {
            const char *procname = procBuffer[i].kp_proc.p_comm;
            NSString *进程名字=[NSString stringWithFormat:@"%s",procname];
            pid_t pid = procBuffer[i].kp_proc.p_pid;
            
                if (strstr(GameName.UTF8String,进程名字.UTF8String)) {

                    free(procBuffer);
                    //return 0;
                    return pid;
                }
            
        }
        free(procBuffer);
    }
    
    return  -1;
}

```

2) then basicly we need task_port
but its imporant to get task_port avoiding calling task_for_pid since it may cause an easier detection from game anticheat
so to avoid using task_for_pid u can use this shit




```markdown
task_port_t task_for_pid_workaround(int Pid)
{
  
  host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
  task_port_t   psDefault;
  task_port_t   psDefault_control;

  task_array_t  tasks;
  mach_msg_type_number_t numTasks;
  int i;

   thread_array_t       threads;
   thread_info_data_t   tInfo;

  kern_return_t kr;

  kr = processor_set_default(myhost, &psDefault);

  kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
 if (kr != KERN_SUCCESS) { NSLog(@"host_processor_set_priv failed with error %x\n", kr);
         mach_error("host_processor_set_priv",kr); exit(1);}


  kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
  if (kr != KERN_SUCCESS) { NSLog(@"processor_set_tasks failed with error %x\n",kr); exit(1); }

  for (i = 0; i < numTasks; i++)
        {
                int pid;
                pid_for_task(tasks[i], &pid);
                NSLog(@"TASK %d PID :%d\n", i,pid);
                if (pid == Pid) return (tasks[i]);
        }

   return (MACH_PORT_NULL);
} // end workaround

```

3) then we need kinda base address of target library of proccess. aslr shit


```markdown

    vm_map_offset_t vmoffset = 0;
    vm_map_size_t vmsize = 0;
    uint32_t nesting_depth = 0;
    struct vm_region_submap_info_64 vbr;
    mach_msg_type_number_t vbrcount = 16;
    kern_return_t kret = mach_vm_region_recurse(task, &vmoffset, &vmsize, &nesting_depth, (vm_region_recurse_info_t)&vbr, &vbrcount);
    if (kret == KERN_SUCCESS) {
       
    } else {
        
    }
    
    return vmoffset;
}
```

4) thats it, now we can read any address externally.

```markdown
static bool Read(long address, void *buffer, int length)
{
    vm_size_t size = 0;
    kern_return_t error = vm_read_overwrite_(task, (vm_address_t)address, length, (vm_address_t)buffer, &size);
    if(error != KERN_SUCCESS || size != length){
        return NO;
    }
    return YES;
}
```


uisng this u may avoid a lot of anticheat systems and so on, **but not all**.




