#ifndef DYNTRACE_PROCESS_ELF_HPP_
#define DYNTRACE_PROCESS_ELF_HPP_

#include <gelf.h>

#include <memory>
#include <string_view>

namespace dyntrace::process
{
    class elf;

    class elf_symbol
    {
    public:

        elf_symbol(const elf* e, Elf_Scn* scn, size_t idx);

        std::string_view name() const;
        uintptr_t value() const;
        size_t size() const;
        int type() const;

    private:
        const elf* _e;
        Elf_Scn* _scn;
        size_t _idx;
    };

    class elf_symtab
    {
    public:

        elf_symtab(const elf* e, Elf_Scn* scn);

        class iterator
        {
        public:

            iterator(const elf* e, Elf_Scn* scn, size_t idx);

            iterator& operator++();
            iterator operator++(int);

            elf_symbol operator*() const;


            bool operator==(const iterator& rhs) const;
            bool operator!=(const iterator& rhs) const;

        private:
            const elf* _e;
            Elf_Scn* _scn;
            size_t _idx;
        };

        iterator begin() const;
        iterator end() const;

    private:
        const elf* _e;
        Elf_Scn* _scn;
    };

    class elf_section
    {
    public:
        explicit elf_section(const elf* e, Elf_Scn* scn);

        elf_symtab as_symtab() const;

        GElf_Word type() const;
        std::string_view name() const;

        bool valid() const;
    private:

        const elf* _e;
        Elf_Scn* _scn;
    };

    class elf
    {
    public:

        explicit elf(int fd);

        elf_section get_section(std::string_view name) const;

        Elf* inner() const;
        size_t shstrndr() const;

        GElf_Ehdr get_ehdr() const;

    private:
        int _fd;
        std::shared_ptr<Elf> _e;
        size_t _shstrndx;
    };
}

#endif