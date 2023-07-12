#pragma once
#include "ui_result.h"

class Tracer;

namespace ui {
#if defined(MDB_DEBUG)
#define DEFINE_NAME(Type)                                                                                         \
  constexpr std::string_view name() noexcept override final                                                       \
  {                                                                                                               \
    return #Type;                                                                                                 \
  }
#else
#define DEFINE_NAME
#endif

struct UICommand
{
public:
  virtual ~UICommand() = default;
  virtual UIResultPtr execute(Tracer *tracer) noexcept = 0;

#if defined(MDB_DEBUG)
  constexpr virtual std::string_view name() noexcept = 0;
#endif
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UICommandPtr = UICommand *;
}; // namespace ui