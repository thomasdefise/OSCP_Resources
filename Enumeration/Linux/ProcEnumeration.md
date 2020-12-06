
### Network Enumeration

#### Open ports

```
$ head -1 /proc/24784/net/tcp; grep 15907701 /proc/24784/net/tcp
  sl  local_address rem_address   st  tx_queue  rx_queue tr tm->when  retrnsmt   uid  timeout inode
  46: 010310AC:9C4C 030310AC:1770 01 0100000150:00000000  01:00000019 00000000  1000 0 54165785 4 cd1e6040 25 4 27 3 -1

46: 010310AC:9C4C 030310AC:1770 01 
|   |         |   |        |    |--> connection state
|   |         |   |        |------> remote TCP port number
|   |         |   |-------------> remote IPv4 address
|   |         |--------------------> local TCP port number
|   |---------------------------> local IPv4 address
|----------------------------------> number of entry

00000150:00000000 01:00000019 00000000 
|        |        |  |        |--> number of unrecovered RTO timeouts
|        |        |  |----------> number of jiffies until timer expires
|        |        |----------------> timer_active (see below)
|        |----------------------> receive-queue
|-------------------------------> transmit-queue

1000 0 54165785 4 cd1e6040 25 4 27 3 -1
|    | |        | |        |  | |  |  |--> slow start size threshold, 
|    | |        | |        |  | |  |       or -1 if the treshold
|    | |        | |        |  | |  |       is >= 0xFFFF
|    | |        | |        |  | |  |----> sending congestion window
|    | |        | |        |  | |-------> (ack.quick<<1)|ack.pingpong
|    | |        | |        |  |---------> Predicted tick of soft clock
|    | |        | |        |               (delayed ACK control data)
|    | |        | |        |------------> retransmit timeout
|    | |        | |------------------> location of socket in memory
|    | |        |-----------------------> socket reference count
|    | |-----------------------------> inode
|    |----------------------------------> unanswered 0-window probes
|---------------------------------------------> uid
```


```bash
kali@kali:~$ head -2 /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:1E61 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 68832 1 00000000f17b940a 100 0 0 10 0                     
kali@kali:~$ printf "%d\n" $((16#1E61))
7777
```

### Capabilities Enumeration

```
grep Ca /proc/1216/status
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

capsh --decode=000001ffffffffff
0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,
cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,
cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,
cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,
cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,
cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,
cap_checkpoint_restore
```

#### Others

```bash
cat /proc/self/environ # Contains the environment of the process.
```
