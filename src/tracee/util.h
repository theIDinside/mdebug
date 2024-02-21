#pragma once
#include <typedefs.h>

struct user_regs_struct;

u64 get_register(user_regs_struct *regs, int reg_number) noexcept;