# inject
This library implements a library injector.

# API
For very simple use, only one function call is necessary.
```c++
#include <dyntrace/inject/inject.hpp>
using namespace dyntrace::inject;
inject(1234, "libfoo.so");
```
This will inject the library `libfoo.so` into the process with PID `1234`. The library must be findable by dlopen from the perspective of the injected process.

## Advanced usage
### injector
The first class is the injector. This is the class that does the actual injection. While the object exists, the target process is stopped.
```c++
#include <dyntrace/inject/injector.hpp>
using namespace dyntrace::inject;
injector inj{1234}; // Attach to PID 1234
auto libfoo = inj.inject("libfoo.so"); // Inject libfoo.so
inj.inject("libbar.so"); // Inject libbar.so
inf.remove(libfoo); // Remove libfoo.so
// Detach from PID 1234 in inj.~injector()
```
### executor
The second class is the executor. This is a lower level class that is used by the injector. This classes lets you call functions from the address space of the target process.
```c++
#include <dyntrace/inject/executor.hpp>
using namespace dyntrace::inject;
executor e{1234}; // Attach to PID 1234
// Creates a remote function to the target process's malloc, free and printf. Replace every pointer with remote_ptr.
auto r_malloc = e.create<remote_ptr(size_t)>("malloc", std::regex{".*libc.*"});
auto r_free = e.create<void(remote_ptr)>("free", std::regex{".*libc.*"});
auto r_printf = e.create<int(remote_ptr)>("printf", std::regex{".*libc.*"});
auto msg = "Hello World !\n";
remote_ptr r_ptr = r_malloc(strlen(msg) + 1); // Allocates 16 bytes in the other process. The pointer is NOT valid in this address space.
e.copy(r_ptr, msg, strlen(msg) + 1); // Copy the 16 bytes to the other process
r_printf(r_ptr); // Call printf from the other process
r_free(r_ptr); // Free the pointer
```