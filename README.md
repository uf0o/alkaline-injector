# alkaline-injector

An ongoing effort to include multuple DLL/code_injection techniques in a single tool.
This is meant to be as a PoC/template reference that can be tailored for specific engagements

### Supported techniques

.0 - Create Remote Thread - DLL Injection
.1 - Create Remote Thread - Shellcode Injection 

### TO-DO
.2 - Reflective DLL Injection


### Example output 
```
Usage: DS_Injector.exe <target process ID> <0-1> [DLL Path to inject]
Example: DS_Injector.exe 4242 2 InjectDLL.dll

[0] - Create Remote Thread - DLL Injection
[1] - Create Remote Thread - Shellcode Injection *



[*] Shellcode can be replaced in the 'resource' section of the project.>
[*] WARNING - it might kill the parent process
```
