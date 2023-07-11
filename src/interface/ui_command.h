#pragma once
#include "ui_result.h"

class Tracer;

namespace ui {
struct UICommand
{
public:
  virtual UIResultPtr execute(Tracer *tracer) noexcept = 0;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UICommandPtr = UICommand *;
}; // namespace ui