#include "elf.hpp"

#include "util.hpp"

#include <sstream>

#include <fcntl.h>
#include <unistd.h>

#include <gelf.h>
#include <elf.h>
#include <libelf.h>

using namespace dyntrace;

process::Symbol process::SymbolTable::iterator::operator*() const
{
    GElf_Sym sym{};
    if(!gelf_getsym(_data, _idx, &sym))
        throw ElfError("Out of bound");
    return process::Symbol{elf_strptr(_elf, _strtab, sym.st_name), sym.st_value, sym.st_size};
}

process::SymbolRef process::SymbolTable::iterator::operator->() const
{
    return process::SymbolRef{operator*()};
}

process::SymbolTable::iterator process::SymbolTable::begin() const
{
    GElf_Shdr shdr;
    gelf_getshdr(_scn, &shdr);
    Elf_Data* data = elf_getdata(_scn, nullptr);
    if(!data)
        throw ElfError("Could not get symbol table data");
    return iterator(_elf._elf, data, shdr.sh_link, 0);
}

process::SymbolTable::iterator process::SymbolTable::end() const
{
    GElf_Shdr shdr;
    gelf_getshdr(_scn, &shdr);
    Elf_Data* data = elf_getdata(_scn, nullptr);
    if(!data)
        throw ElfError("Could not get symbol table data");
    return iterator(_elf._elf, data, shdr.sh_link, shdr.sh_size / shdr.sh_entsize);
}

process::Elf process::Elf::from_pid(pid_t pid)
{
    std::ostringstream path;
    path << "/proc/" << pid << "/exe";
    return process::Elf(path.str());
}

process::Elf::Elf(const char *path)
{
    static process::RunOnce _init_elf([]()
    {
        elf_version(EV_CURRENT);
    });

    _fd = open(path, O_RDONLY);
    if(_fd < 0)
    {
        throw ElfError("Could not open file");
    }

    if((_elf = elf_begin(_fd, ELF_C_READ, nullptr)) == nullptr)
    {
        close(_fd);
        throw ElfError("Could not read elf file");
    }
}

process::Elf::Elf(const std::string &path)
    : Elf(path.c_str()) {}

process::Elf::~Elf() noexcept
{
    elf_end(_elf);
    close(_fd);
}

process::SymbolTable process::Elf::table(int type) const
{
    Elf_Scn* scn{nullptr};
    while((scn = elf_nextscn(_elf, scn)) != nullptr)
    {
        GElf_Shdr shdr;
        if(!gelf_getshdr(scn, &shdr))
            continue;
        if(shdr.sh_type == type)
        {
            return process::SymbolTable(*this, scn);
        }
    }
    throw ElfError("Could not find symtab");
}

process::SymbolTable process::Elf::symtab() const
{
    return table(SHT_SYMTAB);
}

process::SymbolTable process::Elf::dynsym() const
{
    return table(SHT_DYNSYM);
}