#include "pch.h"
#include "EtwEntropy.h"

extern "C" __declspec(dllexport) ICEtwEntropy* EEGetInstance()
{
    return CEtwEntropy::GetInstance();
}

extern "C" __declspec(dllexport) void EEReleaseInstance()
{
    CEtwEntropy::ReleaseInstance();
}