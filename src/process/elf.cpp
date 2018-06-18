#include "dyntrace/process/elf.hpp"

#include "dyntrace/process/error.hpp"

#include <mutex>
#include <elf.h>

using namespace dyntrace;
using namespace dyntrace::process;

elf::elf(int fd)
    : _fd{fd}
{
    static std::once_flag elf_init{};
    std::call_once(elf_init, []()
    {
        if(elf_version(EV_CURRENT) == EV_NONE)
            throw process_error{"Could not initialize elf"};
    });

    _e = std::shared_ptr<Elf>{
        elf_begin(_fd, ELF_C_READ, nullptr),
        [fd = _fd](Elf* e)
        {
            elf_end(e);
            close(fd);
        }
    };

    if(!_e)
        throw process_error{"Could not open elf file"};

    if(elf_kind(_e.get()) != ELF_K_ELF)
    {
        elf_end(_e.get());
        throw process_error{"Invalid elf file"};
    }

    if(elf_getshdrstrndx(_e.get(), &_shstrndx) != 0)
        throw process_error{"Could not get string table"};
}

Elf* elf::inner() const
{
    return _e.get();
}

size_t elf::shstrndr() const
{
    return _shstrndx;
}

GElf_Ehdr elf::get_ehdr() const
{
    GElf_Ehdr ehdr;
    gelf_getehdr(_e.get(), &ehdr);
    return ehdr;
}

elf_section elf::get_section(std::string_view name) const
{
    Elf_Scn* scn = nullptr;
    while((scn = elf_nextscn(_e.get(), scn)) != nullptr)
    {
        GElf_Shdr shdr;
        if(gelf_getshdr(scn, &shdr) != &shdr)
            throw process_error{"Could not read section\n"};
        if(name == elf_strptr(_e.get(), _shstrndx, shdr.sh_name))
            return elf_section{this, scn};
    }
    return elf_section{this, nullptr};
}

elf_section::elf_section(const elf* e, Elf_Scn* scn)
    : _e{e}, _scn{scn}
{

}

elf_symtab elf_section::as_symtab() const
{
    if(type() != SHT_SYMTAB && type() != SHT_DYNSYM)
        throw process_error{"This section is not a symbol table"};
    return elf_symtab{_e, _scn};
}

std::string_view elf_section::name() const
{
    GElf_Shdr shdr;
    gelf_getshdr(_scn, &shdr);
    return elf_strptr(_e->inner(), _e->shstrndr(), shdr.sh_name);
}

GElf_Word elf_section::type() const
{
    GElf_Shdr shdr;
    gelf_getshdr(_scn, &shdr);
    return shdr.sh_type;
}

bool elf_section::valid() const
{
    return _scn != nullptr;
}

elf_symtab::elf_symtab(const elf* e, Elf_Scn* scn)
    : _e{e}, _scn{scn}
{
}

elf_symtab::iterator elf_symtab::begin() const
{
    return iterator{_e, _scn, 0};
}

elf_symtab::iterator elf_symtab::end() const
{
    GElf_Shdr shdr;
    gelf_getshdr(_scn, &shdr);
    return iterator(_e, _scn, shdr.sh_size / shdr.sh_entsize);
}

elf_symtab::iterator::iterator(const elf* e, Elf_Scn* scn, size_t idx)
    : _e{e}, _scn{scn}, _idx{idx}
{

}

elf_symtab::iterator& elf_symtab::iterator::operator++()
{
    ++_idx;
    return *this;
}

elf_symtab::iterator elf_symtab::iterator::operator++(int)
{
    auto ret = *this;
    ++_idx;
    return ret;
}

elf_symbol elf_symtab::iterator::operator*() const
{
    return elf_symbol{_e, _scn, _idx};
}

bool elf_symtab::iterator::operator==(const dyntrace::process::elf_symtab::iterator& rhs) const
{
    return _scn == rhs._scn && _idx == rhs._idx;
}

bool elf_symtab::iterator::operator!=(const dyntrace::process::elf_symtab::iterator& rhs) const
{
    return _scn != rhs._scn || _idx != rhs._idx;
}

elf_symbol::elf_symbol(const elf* e, Elf_Scn* scn, size_t idx)
    : _e{e}, _scn{scn}, _idx{idx}
{

}

std::string_view elf_symbol::name() const
{
    auto data = elf_getdata(_scn, nullptr);

    GElf_Sym sym;
    gelf_getsym(data, _idx, &sym);

    GElf_Shdr shdr;
    gelf_getshdr(_scn, &shdr);
    return elf_strptr(_e->inner(), shdr.sh_link, sym.st_name);
}

uintptr_t elf_symbol::value() const
{
    auto data = elf_getdata(_scn, nullptr);

    GElf_Sym sym;
    gelf_getsym(data, _idx, &sym);

    return sym.st_value;
}

size_t elf_symbol::size() const
{
    auto data = elf_getdata(_scn, nullptr);

    GElf_Sym sym;
    gelf_getsym(data, _idx, &sym);

    return sym.st_size;
}

int elf_symbol::type() const
{
    auto data = elf_getdata(_scn, nullptr);

    GElf_Sym sym;
    gelf_getsym(data, _idx, &sym);

    return GELF_ST_TYPE(sym.st_info);
}