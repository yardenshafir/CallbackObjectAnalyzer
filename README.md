# CallbackObjectAnalyzer
Dumps information about all the callback objects found in a dump file and the functions registered for them.
Will show the names of all callbacks and the symbols for the registered functions, if available, as well as the address of the callback contexts.

## To use
Build the solution and copy dbgeng.dll, dnghelp.dll and symsrv.dll from the directory windbg.exe is installed in into the output directory.
The DLLs that are shipped with Windows are not always stable and could cause unexpected issues.

## Usage
```
-l : Create a dump of the local machine and analyze it. Requires admin privileges.
-d <dump file path> : Analyze the dump in the supplied path.
-k <connection options> : Connect to a kernel debugger and dump callback object information.
```
