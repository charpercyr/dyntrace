#include "tracepoint.hpp"

#include "jmp.hpp"
#include "out_of_line.hpp"

#include <capstone.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <util/util.hpp>
#include <fasttp/error.hpp>

using namespace dyntrace;
using namespace dyntrace::fasttp;

extern "C" void safe_write8(void* where, uint64_t val) noexcept;

namespace
{
    constexpr uint8_t handler_code[] = {
    /// Save urgent registers (rsp, rbp, rflags)
        /* 00: push %rsp                        */ 0x54,
        /* 01: push %rbp                        */ 0x55,
        /* 02: pushf                            */ 0x9c,
    /// Increment refcount
        /* 03: movabs &refcount, %rbp           */ 0x48, 0xbd, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        /* 0d: lock incq (%rbp)                 */ 0xf0, 0x48, 0xff, 0x45, 0x00,
    /// Save other registers
        /* 12: push %r15                        */ 0x41, 0x57,
        /* 14: push %r14                        */ 0x41, 0x56,
        /* 16: push %r13                        */ 0x41, 0x55,
        /* 18: push %r12                        */ 0x41, 0x54,
        /* 1a: push %r11                        */ 0x41, 0x53,
        /* 1c: push %r10                        */ 0x41, 0x52,
        /* 1e: push %rbx                        */ 0x53,
        /* 1f: push %r9                         */ 0x41, 0x51,
        /* 21: push %r8                         */ 0x41, 0x50,
        /* 23: push %rcx                        */ 0x51,
        /* 24: push %rdx                        */ 0x52,
        /* 25: push %rsi                        */ 0x56,
        /* 26: push %rdi                        */ 0x57,
        /* 27: push %rax                        */ 0x50,
    /// call handler(arch_tracepoint*, regs*)
        /* 28: movabs &tracepoint, %rdi         */ 0x48, 0xbf, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        /* 32: mov %rsp, %rsi                   */ 0x48, 0x89, 0xe6,
        /* 35: movabs &handler, %rax            */ 0x48, 0xb8, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba, 0xad, 0xde,
        /* 3f: callq *%rax                      */ 0xff, 0xd0,
    /// Restore other registers
        /* 41: pop %rax                         */ 0x58,
        /* 42: pop %rdi                         */ 0x5f,
        /* 43: pop %rsi                         */ 0x5e,
        /* 44: pop %rdx                         */ 0x5a,
        /* 45: pop %rcx                         */ 0x59,
        /* 46: pop %r8                          */ 0x41, 0x58,
        /* 48: pop %r9                          */ 0x41, 0x59,
        /* 4a: pop %rbx                         */ 0x5b,
        /* 4b: pop %r10                         */ 0x41, 0x5a,
        /* 4d: pop %r11                         */ 0x41, 0x5b,
        /* 4f: pop %r12                         */ 0x41, 0x5c,
        /* 51: pop %r13                         */ 0x41, 0x5d,
        /* 53: pop %r14                         */ 0x41, 0x5e,
        /* 55: pop %r15                         */ 0x41, 0x5f,
    /// Decrement refcount
        /* 57: movabs &refcount, %rbp           */ 0x48, 0xbd, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        /* 61: lock decq (%rbp)                 */ 0xf0, 0x48, 0xff, 0x4d, 0x00,
    /// Restore urgent registers (rsp, rbp, rflags)
        /* 66: popf                             */ 0x9d,
        /* 67: pop %rbp                         */ 0x5d,
        /* 68: pop %rsp                         */ 0x5c
    };
    constexpr size_t refcount_addr_1 = 0x05;
    constexpr size_t refcount_addr_2 = 0x59;
    constexpr size_t tp_addr = 0x2a;
    constexpr size_t handler_addr = 0x37;

    void set_refcount(void* _code, uintptr_t refcount) noexcept
    {
        auto code = reinterpret_cast<uint8_t*>(_code);
        safe_write8(code + refcount_addr_1, refcount);
        safe_write8(code + refcount_addr_2, refcount);
    }

    void set_tracepoint(void* _code, uintptr_t tp) noexcept
    {
        auto code = reinterpret_cast<uint8_t*>(_code);
        safe_write8(code + tp_addr, tp);
    }

    void set_handler(void* _code, uintptr_t handler) noexcept
    {
        auto code = reinterpret_cast<uint8_t*>(_code);
        safe_write8(code + handler_addr, handler);
    }

    bool set_jmp(void* where, uintptr_t to)
    {
        auto odiff = calc_jmp(reinterpret_cast<uintptr_t>(where), to);
        if(!odiff)
            return false;
        auto diff = odiff.value();
        uint8_t bytes[8];
        memcpy(bytes, where, 8);
        bytes[0] = 0xe9;
        memcpy(bytes + 1, &diff, 4);
        safe_write8(where, *reinterpret_cast<uint64_t*>(bytes));
        return true;
    }

    uintptr_t find_location(const process::process& proc, address_range range)
    {
        auto free = proc.create_memmap().free();
        for(auto& z : free)
        {
            if(range.contains(z.start))
            {
                return z.start;
            }
            else if(range.contains(z.end - PAGE_SIZE))
            {
                return z.end - PAGE_SIZE;
            }
            else if(z.contains(range))
            {
                return range.start;
            }
        }
        return 0;
    }

    std::pair<code_ptr, size_t> get_pages(code_ptr loc, size_t size) noexcept
    {
        // TODO better alloc
        size_t mmap_size = ((loc.as_int() & PAGE_MASK) - ((loc.as_int()  + size) & PAGE_MASK)) + PAGE_SIZE;
        loc = loc.as_int() & PAGE_MASK;
        return {loc, mmap_size};
    };

    void* do_mmap(code_ptr loc, size_t size)
    {
        auto [real_loc, mmap_size] = get_pages(loc, size);
        real_loc = mmap(
            real_loc, mmap_size,
            PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
            -1, 0
        );
        if(real_loc == MAP_FAILED)
            throw fasttp_error("mmap failed for " + to_hex_string(loc.as_int()));
        return loc.as_ptr();
    }

    void do_unmap(code_ptr loc, size_t size) noexcept
    {
        auto [real_loc, mmap_size] = get_pages(loc, size);
        munmap(real_loc, mmap_size);
    }
}
void arch_tracepoint::do_insert(const process::process &proc)
{
    memcpy(&_old_code, _location, 8);

    auto ool = out_of_line(_location.as_ptr());

    _handler_size = 5 + ool.size() + sizeof(handler_code);
    _handler_location = do_mmap(find_location(proc, make_address_range(_location.as_int(), 2_G - 5 - _handler_size)), _handler_size);

    memcpy(_handler_location, handler_code, sizeof(handler_code));
    set_refcount(_handler_location, reinterpret_cast<uintptr_t>(&_refcount));
    set_tracepoint(_handler_location, reinterpret_cast<uintptr_t>(this));
    set_handler(_handler_location, reinterpret_cast<uintptr_t>(do_handle));
    ool.write(_handler_location + sizeof(handler_code));
    set_jmp(_handler_location + sizeof(handler_code) + ool.size(), _location.as_int() + ool.size());

    auto pages = get_pages(_location, 8);
    mprotect(pages.first, pages.second, PROT_WRITE | PROT_EXEC | PROT_READ);
    set_jmp(_location, _handler_location.as_int());
    mprotect(pages.first, pages.second, PROT_EXEC | PROT_READ);
}

void arch_tracepoint::do_remove()
{
    auto [real_loc, mmap_size] = get_pages(_location, 8);
    mprotect(real_loc, mmap_size, PROT_WRITE | PROT_EXEC | PROT_READ);
    safe_write8(_location, _old_code);
    mprotect(real_loc, mmap_size, PROT_EXEC | PROT_READ);
    while(_refcount);
    do_unmap(_handler_location, _handler_size);
}

void arch_tracepoint::do_handle(arch_tracepoint *self, const tracer::regs &r)
{
    try
    {
        self->_user_handler(self->_location, r);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Catched exception from handler: %s", e.what());
    }
    catch(...)
    {
        fprintf(stderr, "Catched unknown exception from handler");
    }
}