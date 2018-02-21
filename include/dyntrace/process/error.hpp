#ifndef DYNTRACE_PROCESS_ERROR_HPP_
#define DYNTRACE_PROCESS_ERROR_HPP_

#include "dyntrace/util/error.hpp"

#include <unistd.h>

namespace dyntrace::process
{
    DYNTRACE_CREATE_ERROR(process_error);
}

#endif