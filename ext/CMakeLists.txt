
function(create_to_string_cc cwd)
    execute_process(COMMAND make to_string.cc WORKING_DIRECTORY ${cwd})
endfunction()

create_to_string_cc(${CMAKE_CURRENT_SOURCE_DIR}/libelfin/dwarf)
create_to_string_cc(${CMAKE_CURRENT_SOURCE_DIR}/libelfin/elf)

add_library(libelfin-elf STATIC
        libelfin/elf/common.hh
        libelfin/elf/data.hh
        libelfin/elf/elf++.hh
        libelfin/elf/elf.cc
        libelfin/elf/mmap_loader.cc
        libelfin/elf/to_hex.hh
        libelfin/elf/to_string.cc)
target_include_directories(libelfin-elf PUBLIC libelfin/elf)

add_library(libelfin-dwarf STATIC
        libelfin/dwarf/abbrev.cc
        libelfin/dwarf/attrs.cc
        libelfin/dwarf/cursor.cc
        libelfin/dwarf/data.hh
        libelfin/dwarf/die.cc
        libelfin/dwarf/die_str_map.cc
        libelfin/dwarf/dwarf++.hh
        libelfin/dwarf/dwarf.cc
        libelfin/dwarf/elf.cc
        libelfin/dwarf/expr.cc
        libelfin/dwarf/internal.hh
        libelfin/dwarf/line.cc
        libelfin/dwarf/rangelist.cc
        libelfin/dwarf/small_vector.hh
        libelfin/dwarf/value.cc
        libelfin/dwarf/to_string.cc)
target_link_libraries(libelfin-dwarf PUBLIC libelfin-elf)
target_include_directories(libelfin-dwarf PUBLIC libelfin/dwarf)