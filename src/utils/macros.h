#pragma once

#if defined(__clang__)
#define MIDAS_UNREACHABLE std::unreachable();
#elif defined(__GNUC__) || defined(__GNUG__)
#define MIDAS_UNREACHABLE __builtin_unreachable();
#endif