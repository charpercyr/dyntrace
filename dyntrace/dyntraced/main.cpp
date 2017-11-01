
#include <iostream>

#include <unistd.h>

#include <process/memmap.hpp>
#include <process/elf.hpp>

using namespace std;

int main(int argc, char** argv)
{
    auto e = dyntrace::process::Elf::from_pid(getpid());
    auto symtab = e.dynsym();
    for(auto it = symtab.begin(); it != symtab.end(); ++it)
    {
        cout << it->name << endl;
    }
    return 0;
}