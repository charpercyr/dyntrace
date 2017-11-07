#include "injector.hpp"

using namespace dyntrace::inject::_detail;

extern "C" void* do_dlopen(clone_args<dlopen_args>* args)
{
    args->ret = args->args.dlopen(args->args.name, args->args.mode);
    return NULL;
}

extern "C" void* do_dlclose(clone_args<dlclose_args>* args)
{
    args->args.dlclose(args->args.handle);
    return NULL;
}