#include "ketamine/memory.h"

void Initalize()
{

}

bool __stdcall DllMain(unsigned __int64 instance, int reason, void* reserved)
{
    if (reason == 1)
        Initalize();

    return true;
}