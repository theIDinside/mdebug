#pragma once

#include "../../common.h"
#include "dap_defs.h"
#include <nlohmann/json_fwd.hpp>

namespace ui::dap {

struct SerializedProtocolMessage
{
  std::string header;
  std::string payload;
};

struct ProtocolMessage
{
  std::string header(const std::string &payload) noexcept;
};

struct Event : public ProtocolMessage
{
  virtual ~Event() noexcept = default;

  virtual SerializedProtocolMessage serialize(int seq) noexcept = 0;
};

struct ThreadEvent : public Event
{
  ThreadEvent(ThreadReason reason, Tid tid) noexcept;
  virtual ~ThreadEvent() noexcept = default;
  SerializedProtocolMessage serialize(int seq) noexcept override final;
  ThreadReason reason;
  Tid tid;
};

struct StoppedEvent final : public Event
{
  virtual ~StoppedEvent() noexcept = default;
  StoppedEvent(StoppedReason reason, std::string_view description, std::vector<int> bps) noexcept;
  StoppedReason reason;
  std::string_view description;
  std::vector<int> bp_ids;
  SerializedProtocolMessage serialize(int seq) noexcept override final;
};

struct BreakpointEvent final : public Event
{
  std::vector<int> bp_ids;
  SerializedProtocolMessage serialize(int seq) noexcept override final;
};

struct OutputEvent final : public Event
{
  virtual ~OutputEvent() noexcept = default;
  OutputEvent(std::string_view category, std::string &&output) noexcept;

  std::string_view category; // static category strings exist, we always pass literals to this
  std::string output;
  SerializedProtocolMessage serialize(int seq) noexcept override final;
};

}; // namespace ui::dap