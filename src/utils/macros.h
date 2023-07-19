#pragma once

#if defined(__clang__)
#define DEAL_WITH_SHITTY_GCC
#elif defined(__GNUC__) || defined(__GNUG__)
#define DEAL_WITH_SHITTY_GCC return {};
#endif