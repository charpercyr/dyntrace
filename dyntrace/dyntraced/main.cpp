
#include <iostream>
#include <memory>

#include <unistd.h>

#include <dwarf++.hh>
#include <elf++.hh>
#include <fcntl.h>

using namespace std;

void parse_subprogram(const dwarf::die& sp)
{
    cout << "Subprogram ";
    if(sp.has(dwarf::DW_AT::name))
    {
        cout << sp[dwarf::DW_AT::name].as_string() << endl;
    }
    else
    {
        cout << sp[dwarf::DW_AT::abstract_origin].as_reference()[dwarf::DW_AT::name].as_string() << endl;
    }
    for(auto& ch : sp)
    {
        if(ch.tag == static_cast<dwarf::DW_TAG>(0x1001))
        {
            cout << "    0x" << hex << ch[dwarf::DW_AT::low_pc].as_address() << endl;
            cout << "    0x" << hex << ch[dwarf::DW_AT::high_pc].as_uconstant() << endl;
            cout << "     ----" << endl;
        }
    }
}

int main(int argc, char** argv)
{
    int fd = open("/home/charpercyr/Documents/dyntrace/cmake-build-debug/dyntrace/dyntraced/foo", O_RDONLY);

    elf::elf e(elf::create_mmap_loader(fd));
    dwarf::dwarf d(dwarf::elf::create_loader(e));

    for(auto& cu : d.compilation_units())
    {
        for(auto& ch : cu.root())
        {
            if(ch.tag == dwarf::DW_TAG::subprogram)
            {
                parse_subprogram(ch);
            }
        }
    }
    close(fd);
    return 0;
}