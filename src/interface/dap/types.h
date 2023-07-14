#pragma once
#include "../../common.h"
#include <string_view>
namespace ui::dap {

struct SourceBreakpoint
{
  int line;
  std::optional<int> column;
  std::optional<std::string> condition;
  std::optional<std::string> hit_condition;
  std::optional<std::string> logMessage;
};

struct FunctionBreakpoint
{
  std::string name;
  std::optional<std::string> condition;
  std::optional<std::string> hit_condition;
};

struct InstructionBreakpoint
{
};

struct Source
{
  std::string_view name;
  std::string_view path;
};

// comments describe the name of the field in the protocl
struct Breakpoint
{
  // id
  u32 id;
  // verified
  bool verified;
  // instructionReference
  TPtr<void> addr;

  std::string serialize() const noexcept;
};

struct DataBreakpoint
{
  std::string data_id;
  std::string_view access_type;
  std::string condition;
  std::string hit_condition;
};

}; // namespace ui::dap