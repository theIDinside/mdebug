#pragma once
#include "../common.h"

class Tracer;
namespace cmd {

class Command
{
public:
  Command() noexcept = default;
  virtual ~Command() noexcept = default;
  // Performs this command - bool reports "success"
  virtual bool execute(Tracer *tracer) const noexcept = 0;
};

class Continue final : public Command
{
public:
  Continue() = default;
  Continue(Tid thread_id, bool continue_all) noexcept;
  bool execute(Tracer *tracer) const noexcept override final;
  Tid thread_id;
  bool continue_all;
};
}; // namespace cmd