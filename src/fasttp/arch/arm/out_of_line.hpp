#ifndef DYNTRACE_FASTTP_ARCH_ARM_OUT_OF_LINE_HPP_
#define DYNTRACE_FASTTP_ARCH_ARM_OUT_OF_LINE_HPP_

#include "../../buffer_writer.hpp"

namespace dyntrace::fasttp
{
    class out_of_line
    {
    public:
        out_of_line(code_ptr insn);

        size_t size() const;

        void write(buffer_writer w);

    private:
        code_ptr _code;
        uint32_t _insns[4];
        size_t _n;
    };
}

#endif