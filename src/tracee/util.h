#pragma once
#include <string>
#include <typedefs.h>

struct user_regs_struct;

u64 *register_by_number(user_regs_struct *regs, int reg_number) noexcept;
u64 get_register(user_regs_struct *regs, int reg_number) noexcept;

std::string process_exe_path(Pid pid) noexcept;

u32 SystemVectorExtensionSize() noexcept;