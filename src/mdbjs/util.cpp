/** LICENSE TEMPLATE */
#include "./util.h"
#include "js/Conversions.h"
#include "js/String.h"
#include "js/Value.h"
namespace mdb::js {
mdb::Expected<JS::SourceText<mozilla::Utf8Unit>, std::string>
SourceFromString(JSContext *context, std::string_view str) noexcept
{
  JS::SourceText<mozilla::Utf8Unit> source;
  if (!source.init(context, str.data(), str.length(), JS::SourceOwnership::Borrowed)) {
    return mdb::unexpected<std::string>("Failed to initialize source text.");
  }

  return mdb::expected(std::move(source));
}

mdb::Expected<JS::UniqueChars, std::string_view>
ToString(JSContext *cx, JS::Handle<JS::Value> stringObject) noexcept
{
  JS::RootedString rootedJsString(cx, JS::ToString(cx, stringObject));
  if (rootedJsString) {
    JS::UniqueChars utf8String = ::JS_EncodeStringToUTF8(cx, rootedJsString);

    if (utf8String) {
      return expected(std::move(utf8String));
    }
  }
  return mdb::unexpected<std::string_view>("failed to convert to string");
}

bool
ToStdString(JSContext *cx, JS::HandleString string, std::pmr::string &writeBuffer) noexcept
{
  bool success = false;
  if (string) {
    success = true;
    JS::Rooted<JSString *> str{cx, string};
    auto stringLength = JS_GetStringEncodingLength(cx, str);

    writeBuffer.resize_and_overwrite(stringLength, [cx, &str, &success](char *ptr, size_t size) -> size_t {
      if (!JS_EncodeStringToBuffer(cx, str, ptr, size)) {
        success = false;
      }
      for (auto it = ptr; it < ptr + size; ++it) {
        if (*it == 0) {
          return std::distance(ptr, it);
        }
      }
      return size;
    });
  }
  return success;
}

bool
ToStdString(JSContext *cx, JS::HandleString string, std::string &writeBuffer) noexcept
{
  bool success = false;
  if (string) {
    success = true;
    auto stringLength = JS_GetStringEncodingLength(cx, string);

    writeBuffer.resize_and_overwrite(stringLength, [cx, string, &success](char *ptr, size_t size) {
      if (!JS_EncodeStringToBuffer(cx, string, ptr, size)) {
        success = false;
      }
      return size;
    });
  }
  return success;
}

JSString *
PrepareString(JSContext *cx, std::string_view string) noexcept
{
  JSString *jsString = JS_NewStringCopyN(cx, string.data(), string.size());

  if (!jsString) {
    return nullptr;
  }
  return jsString;
}
} // namespace mdb::js