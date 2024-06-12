#pragma once

#include "../../symbolication/block.h"
#include "../ui_result.h"
#include "bp.h"
#include "dap_defs.h"
#include "types.h"
#include <nlohmann/json_fwd.hpp>
#include <typedefs.h>

enum class SharedObjectSymbols : u8;
struct SharedObject;

namespace ui::dap {

enum ChangeEvent : u8
{
  New = 0,
  Changed = 1,
  Removed = 2,
};

struct InitializedEvent final : public ui::UIResult
{
  InitializedEvent() noexcept = default;
  ~InitializedEvent() noexcept final = default;
  std::string serialize(int seq) const noexcept final;
};

struct TerminatedEvent final : public ui::UIResult
{
  TerminatedEvent() noexcept = default;
  ~TerminatedEvent() noexcept final = default;
  std::string serialize(int seq) const noexcept final;
};

static constexpr std::string_view reasons[3]{"new", "changed", "removed"};
// Module event: https://microsoft.github.io/debug-adapter-protocol/specification#Events_Module
struct ModuleEvent final : public ui::UIResult
{
  ModuleEvent(std::string_view id, std::string_view reason, std::string &&name, Path &&path,
              std::optional<std::string> &&symbol_file_path, std::optional<std::string> &&version,
              AddressRange range, SharedObjectSymbols so_sym_info) noexcept;

  ModuleEvent(std::string_view reason, const SharedObject &shared_object) noexcept;
  ModuleEvent(std::string_view reason, const ObjectFile &object_file) noexcept;
  ModuleEvent(std::string_view reason, const SymbolFile &symbol_file) noexcept;
  std::string_view objfile_id;
  std::string_view reason;
  std::string name;
  Path path;
  AddressRange addr_range;
  SharedObjectSymbols sym_info;
  std::optional<std::string> symbol_file_path;
  std::optional<std::string> version;

  std::string serialize(int seq) const noexcept final;
};

struct ContinuedEvent final : public ui::UIResult
{
  // threadId
  int thread_id;
  // allThreadsContinued
  bool all_threads_continued;
  ContinuedEvent(Tid tid, bool all_threads) noexcept;
  std::string serialize(int seq) const noexcept final;
};

struct Process final : public ui::UIResult
{
  std::string name;
  bool is_local;
  Process(std::string name, bool is_local) noexcept;
  std::string serialize(int seq) const noexcept final;
};

struct ExitedEvent final : public ui::UIResult
{
  // exitCode
  int exit_code;
  ExitedEvent(int exit_code) noexcept;
  std::string serialize(int seq) const noexcept final;
};

struct ThreadEvent final : public ui::UIResult
{
  ThreadEvent(ThreadReason reason, Tid tid) noexcept;
  ~ThreadEvent() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  ThreadReason reason;
  Tid tid;
};

struct StoppedEvent final : public ui::UIResult
{
  ~StoppedEvent() noexcept override = default;
  StoppedEvent(StoppedReason reason, std::string_view description, Tid tid, std::vector<int> bps,
               std::string_view text, bool all_stopped) noexcept;
  StoppedReason reason;
  // static description
  std::string_view description;
  Tid tid;
  std::vector<int> bp_ids;
  // static additional information, name of exception for instance
  std::string_view text;
  bool all_threads_stopped;
  std::string serialize(int seq) const noexcept final;
};

struct BreakpointEvent final : public ui::UIResult
{
  std::string_view reason;
  std::optional<std::string> message;
  const UserBreakpoint *breakpoint;
  BreakpointEvent(std::string_view reason, std::optional<std::string> message,
                  const UserBreakpoint *breakpoint) noexcept;
  ~BreakpointEvent() override = default;
  std::string serialize(int seq) const noexcept final;
};

struct OutputEvent final : public ui::UIResult
{
  ~OutputEvent() noexcept override = default;
  OutputEvent(std::string_view category, std::string &&output) noexcept;

  std::string_view category; // static category strings exist, we always pass literals to this
  std::string output;
  std::string serialize(int seq) const noexcept final;
};

}; // namespace ui::dap