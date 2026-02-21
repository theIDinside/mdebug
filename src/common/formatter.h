/** LICENSE TEMPLATE */
#pragma once

#include <format> // IWYU pragma: keep

#define BASIC_PARSE                                                                                               \
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }