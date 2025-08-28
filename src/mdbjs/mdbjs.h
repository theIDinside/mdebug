/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/macros.h>
#include <mdbjs/util.h>
#include <utils/expected.h>
#include <utils/log_channel.h>

// std
#include <expected>
#include <memory_resource>
#include <mutex>
#include <utility>

// system
#include <limits>
#include <optional>
#include <string>

// dependency
#include <mdbjs/include-quickjs.h>

class Tracer;

template <std::size_t N>
consteval std::array<char, N>
ToUppercase(const char (&str)[N])
{
  std::array<char, N> result{};
  for (std::size_t i = 0; i < N; ++i) {
    result[i] = std::toupper(static_cast<unsigned char>(str[i]));
  }
  return result;
}

enum class StaticAtom : JSAtom
{
  __JS_ATOM_NULL = JS_ATOM_NULL,
#define DEF(name, str) JS##name,
#include "quickjs-atom.h"
#undef DEF
  JS_ATOM_END,
};

namespace mdb::js {

// Todo: In the future this interface will probably change
// where we instead return some structured data for the exception that happened in js-land.
// For now, if this returns a non-none value, it means an exception happened (and we consumed it).
std::optional<std::string> ConsumePendingException(JSContext *context) noexcept;
bool ConsumePendingException(JSContext *context, std::pmr::string &writeToBuffer) noexcept;

class EventDispatcher;

#define FN_SPAN(...) std::span<std::string_view>({ __VA_ARGS__ })

#define FN_ARGS(...) std::to_array<std::string_view>({ __VA_ARGS__ })
#define EMPTY_ARGS()                                                                                              \
  std::span<std::string_view> {}

#define FOR_EACH_GLOBAL_FN(FNDESC)                                                                                \
  FNDESC(Log, "log", 1, "Log message to the 'interpreter' channel (interpreter.log file output).")                \
  FNDESC(GetSupervisor, "getSupervisor", 1, "Get the supervisor that has the provided pid")                       \
  FNDESC(GetTask, "getThread", 1, "Get the thread that has `tid | dbgId`. `useDbgId=true` searches by dbgId")     \
  FNDESC(PrintThreads, "listThreads", 0, "List all threads in this debug session")                                \
  FNDESC(PrintProcesses, "procs", 0, "List all processes supervisor info")                                        \
  FNDESC(Help, "help", 1, "Show this help message.")

using JsFunction = JSValue (*)(JSContext *ctx, JSValueConst thisValue, int argCount, JSValueConst *argv);

struct FunctionDescriptor
{
  JsFunction mFn;
  std::string_view mName;
  int mArgCount;
  std::string_view mHelpMessage;
};

#define Desc(Fn, Name, ArgCount, HelpMessage) FunctionDescriptor{ &Fn, Name, ArgCount, HelpMessage },

struct JavascriptException
{
  std::string mExceptionMessage;
  std::string mStackTrace;
  std::string mFileName;
  // -1 = has no information
  i32 mLineNumber{ -1 };
  i32 mColumn{ -1 };

  static std::optional<JavascriptException> GetException(JSContext *context) noexcept;
};

class Scripting
{
private:
  static Scripting *sInstance;
  JSRuntime *mRuntime;
  JSContext *mContext;

  Scripting(JSRuntime *runtime, JSContext *context) noexcept : mRuntime(runtime), mContext(context) {}

  static JSValue GetSupervisor(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) noexcept;
  static JSValue Log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) noexcept;
  static JSValue GetTask(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) noexcept;
  static JSValue PrintThreads(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) noexcept;
  static JSValue PrintProcesses(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) noexcept;
  static JSValue Help(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) noexcept;

  void InitializeTypes() noexcept;
  void InitializeMdbModule() noexcept;
  void InitModuleConstants(JSValue globalObject) noexcept;

  static constexpr auto
  FunctionDescriptors() noexcept -> std::span<const FunctionDescriptor>
  {
    static constexpr auto descriptors = std::to_array<const FunctionDescriptor>({
      FunctionDescriptor{ &Log, "log", 2, "Log to one of the debug logging channels" },
      FunctionDescriptor{ &GetSupervisor, "getSupervisor", 1, "Get the supervisor that has the provided pid" },
      FunctionDescriptor{
        &GetTask, "getThread", 1, "Get the thread that has `tid | dbgId`. `useDbgId=true` searches by dbgId" },
      FunctionDescriptor{ &PrintThreads, "listThreads", 0, "List all threads in this debug session" },
      FunctionDescriptor{ &PrintProcesses, "procs", 0, "List all processes supervisor info" },
      FunctionDescriptor{ &Help, "help", 1, "Show this help message." },
    });
    return std::span<const FunctionDescriptor>{ descriptors };
  }

public:
  static Scripting *Create() noexcept;
  static Scripting &Get() noexcept;

  constexpr JSContext *
  GetContext() noexcept
  {
    return mContext;
  }
  void Shutdown() noexcept;

  std::pmr::string *ReplEvaluate(Allocator *allocator, std::string_view input) noexcept;

  static constexpr auto
  HelpMessage(std::string_view fn) noexcept -> std::string_view
  {
    for (const auto &desc : FunctionDescriptors()) {
      if (desc.mName == fn) {
        return desc.mHelpMessage;
      }
    }

    std::unreachable();
  }
};

/** Calls function `functionValue` and then frees the arguments in `arguments`. */
std::expected<JSValue, JavascriptException> CallFunction(
  JSContext *context, JSValue functionValue, JSValue thisValue, std::span<JSValue> consumedArguments);
} // namespace mdb::js