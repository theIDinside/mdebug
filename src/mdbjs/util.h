/** LICENSE TEMPLATE */
#pragma once

#include "js/ErrorReport.h"
#include "js/SourceText.h"
#include "js/TypeDecls.h"
#include <utils/expected.h>
#include <utils/util.h>
namespace mdb::js {
mdb::Expected<JS::SourceText<mozilla::Utf8Unit>, std::string> SourceFromString(JSContext *context,
                                                                               std::string_view str) noexcept;

mdb::Expected<JS::UniqueChars, std::string_view> ToString(JSContext *cx,
                                                          JS::Handle<JSString *> stringObject) noexcept;

bool ToStdString(JSContext *cx, JS::HandleString string, std::string &writeBuffer) noexcept;

} // namespace mdb::js
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