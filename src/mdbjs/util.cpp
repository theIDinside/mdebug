#include "./util.h"

mdb::Expected<JS::SourceText<mozilla::Utf8Unit>, std::string>
SourceFromString(JSContext *context, std::string_view str) noexcept
{
  JS::SourceText<mozilla::Utf8Unit> source;
  if (!source.init(context, str.data(), str.length(), JS::SourceOwnership::Borrowed)) {
    return mdb::unexpected<std::string>("Failed to initialize source text.");
  }

  return mdb::expected(std::move(source));
}