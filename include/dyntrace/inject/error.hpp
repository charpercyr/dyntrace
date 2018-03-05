#ifndef DYNTRACE_INJECT_ERROR_HPP_
#define DYNTRACE_INJECT_ERROR_HPP_

#include "dyntrace/util/error.hpp"

#include <unistd.h>

namespace dyntrace::inject
{
    DYNTRACE_CREATE_ERROR(inject_error);
}

#endif