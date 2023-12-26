#pragma once
#include <cstdint>
#include <string_view>

class Tracer;

namespace ui {
struct UIResult;
using UIResultPtr = const UIResult *;

#if defined(MDB_DEBUG) and MDB_DEBUG == 1
#define DEFINE_NAME(Type)                                                                                         \
  constexpr std::string_view name() noexcept override final { return #Type; }
#else
#define DEFINE_NAME(Type)
#endif

struct UICommand
{
public:
  explicit UICommand(std::uint64_t seq) noexcept : seq(seq) {}
  virtual ~UICommand() = default;

  /* Executes the command. This is always performed in the Tracer thread (where all tracee controller actions are
   * performed. )*/
  virtual UIResultPtr execute(Tracer *tracer) noexcept = 0;

  std::uint64_t seq;
#if defined(MDB_DEBUG) and MDB_DEBUG == 1
  constexpr virtual std::string_view name() noexcept = 0;
#endif
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UICommandPtr = UICommand *;
}; // namespace ui