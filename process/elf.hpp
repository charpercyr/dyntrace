#ifndef DYNTRACE_PROCESS_ELF_HPP_
#define DYNTRACE_PROCESS_ELF_HPP_

#include <libelf.h>

#include <string>

#include "error.hpp"

namespace dyntrace::process
{
    class ElfError : public ProcessError
    {
        using ProcessError::ProcessError;
    };

    struct Symbol
    {
        std::string name;
        uintptr_t addr;
        size_t size;
    };

    class SymbolRef
    {
    public:
        explicit SymbolRef(Symbol sym)
            : _sym{std::move(sym)} {}

        Symbol& operator*()
        {
            return _sym;
        }
        const Symbol& operator*() const
        {
            return _sym;
        }

        Symbol* operator->()
        {
            return &_sym;
        }
        const Symbol* operator->() const
        {
            return &_sym;
        }

    private:
        Symbol _sym;
    };

    class Elf;

    class SymbolTable
    {
        friend class Elf;
    public:

        class iterator
        {
            friend class SymbolTable;
        public:
            iterator& operator++() noexcept
            {
                ++_idx;
                return *this;
            }
            iterator operator++(int) noexcept
            {
                auto it = *this;
                ++_idx;
                return it;
            }

            Symbol operator*() const;
            SymbolRef operator->() const;

            bool operator==(const iterator& rhs) const noexcept
            {
                return _idx == rhs._idx;
            }
            bool operator!=(const iterator& rhs) const noexcept
            {
                return _idx != rhs._idx;
            }

        private:
            iterator(::Elf* elf, ::Elf_Data* data, size_t strtab, int idx) noexcept
                : _elf{elf}, _data{data}, _strtab{strtab}, _idx{idx} {}

            ::Elf* _elf;
            ::Elf_Data* _data;
            size_t _strtab;
            int _idx;
        };
        using const_iterator = iterator;

        iterator begin() const;
        iterator end() const;

    private:
        SymbolTable(const process::Elf& elf, ::Elf_Scn* scn) noexcept
            : _elf{elf}, _scn{scn} {}
        const process::Elf& _elf;
        ::Elf_Scn* _scn;
    };

    class Elf
    {
        friend class SymbolTable;
    public:
        static Elf from_pid(pid_t pid);

        explicit Elf(const char* path);
        explicit Elf(const std::string& path);
        ~Elf() noexcept;

        SymbolTable symtab() const;
        SymbolTable dynsym() const;

    private:
        SymbolTable table(int type) const;
        int _fd;
        ::Elf* _elf;
    };
}

#endif