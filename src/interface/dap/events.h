#pragma once

#include "../../common.h"
#include "../ui_result.h"
#include "dap_defs.h"
#include "types.h"
#include <nlohmann/json_fwd.hpp>

namespace ui::dap {

struct ContinuedEvent final : public ui::UIResult
{
  // threadId
  int thread_id;
  // allThreadsContinued
  bool all_threads_continued;
  ContinuedEvent(Tid tid, bool all_threads) noexcept;
  std::string serialize(int seq) const noexcept override final;
};

struct ExitedEvent final : public ui::UIResult
{
  // exitCode
  int exit_code;
  ExitedEvent(int exit_code) noexcept;
  std::string serialize(int seq) const noexcept override final;
};

struct ThreadEvent final : public ui::UIResult
{
  ThreadEvent(ThreadReason reason, Tid tid) noexcept;
  virtual ~ThreadEvent() noexcept = default;
  std::string serialize(int seq) const noexcept override final;
  ThreadReason reason;
  Tid tid;
};

struct StoppedEvent final : public ui::UIResult
{
  virtual ~StoppedEvent() noexcept = default;
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
  std::string serialize(int seq) const noexcept override final;
};

struct BreakpointEvent final : public ui::UIResult
{
  ui::dap::Breakpoint breakpoint;
  std::string serialize(int seq) const noexcept override final;
};

struct OutputEvent final : public ui::UIResult
{
  virtual ~OutputEvent() noexcept = default;
  OutputEvent(std::string_view category, std::string &&output) noexcept;

  std::string_view category; // static category strings exist, we always pass literals to this
  std::string output;
  std::string serialize(int seq) const noexcept override final;
};

}; // namespace ui::dap