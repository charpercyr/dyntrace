# fasttp
This library implements the fast tracepoints.
The tracepoints are thread-safe and are atomically placed/removed.

# API
The API is very simple to use since constructing one object is enough to create a tracepoint.
```c++
#include <dyntrace/fasttp/fasttp.hpp>
using namespace dyntrace::fasttp;
auto handler = [](const void* addr, const dyntrace::arch::regs& regs)
{
    std::cout << "Tracepoint hit at " << addr << "\n";
};
tracepoint tp{"foo", handler}; // Creates the tracepoint with a name
tp = tracepoint{make_location(0x1234), handler}; // Creates the tracepoint with an address
tp = tracepoint{make_location(foo), handler}; // Creates the tracepoint with a function pointer
tp.enable(); // Enables the tracepoint
tp.disable(); // Disables the tracepoint
/// On tp.~tracepoint(), the tracepoint is removed
```
While the `tracepoint` object is alive, the tracepoint exists. When the destructor is called, the tracepoint is removed. This object is move-constructible and move-assignable.

Don't place two tracepoints too close to each other (less than a 5 bytes distance), it will crash the program.