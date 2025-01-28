#pragma once

#include "js/ErrorReport.h"
#include "js/SourceText.h"
#include <utils/expected.h>
#include <utils/util.h>

mdb::Expected<JS::SourceText<mozilla::Utf8Unit>, std::string> SourceFromString(JSContext *context,
                                                                               std::string_view str) noexcept;

template <> struct fmt::formatter<JSErrorReport> : public Default<JSErrorReport>
{
  template <typename FormatContext>
  auto
  format(const JSErrorReport &report, FormatContext &ctx) const
  {
    auto it = ctx.out();
    if (report.errorMessageName) {
      it = fmt::format_to(it, "[{}] ", report.errorMessageName);
    }
    if (report.filename) {
      it = fmt::format_to(it, "{}:", report.filename);
    }
    if (report.lineno) {
      it = fmt::format_to(it, "{}:{}", report.lineno, report.column.oneOriginValue());
    }

    return fmt::format_to(it, "{}", report.message().c_str());
  }
};