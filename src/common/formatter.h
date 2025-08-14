/** LICENSE TEMPLATE */
#pragma once

#include <format>

#define BASIC_PARSE                                                                                               \
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }