/** LICENSE TEMPLATE */
#include "framejs.h"

// mdb
#include <mdbjs/variablejs.h>
#include <symbolication/callstack.h>
#include <symbolication/objfile.h>
#include <utils/logger.h>

namespace mdb {

bool
FrameLookupHandle::IsValid() noexcept
{
  return !mTask->VariableReferenceIsStale(mFrame.FrameId());
}

} // namespace mdb

namespace mdb::js {

static constexpr auto FrameNotAliveErrorMessage = "Frame handle was null (frame no longer alive)";

JSValue
JsFrame::Id(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *handle = GetThisOrReturnException(handle, FrameNotAliveErrorMessage);
  return JS_NewUint32(cx, static_cast<u32>(handle->mFrame.FrameId()));
}

static JSValue
GetArrayOfVariables(
  JSContext *cx, SymbolFile *symbolFile, tc::SupervisorState *supervisor, sym::Frame &frame, sym::VariableSet set)
{
  auto arrayObject = JS_NewArray(cx);
  auto variables = symbolFile->GetVariables(*supervisor, frame, set);
  for (auto &&[index, variable] : std::ranges::views::enumerate(variables)) {
    auto jsValue = JsVariable::CreateValue(cx, std::move(variable));
    JS_SetPropertyUint32(cx, arrayObject, index, jsValue);
  }

  return arrayObject;
}

JSValue
JsFrame::Locals(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  PROFILE_SCOPE("Frame::Arguments", logging::kInterpreter);
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");

  if (!frame->IsValid()) {
    return JS_ThrowReferenceError(cx,
      "Frame is no longer valid for %s. Request new stack frames adn variables",
      frame->mFrame.CStringName().value_or("<unknown frame name>"));
  }
  SymbolFile *symbolFile = frame->mFrame.GetSymbolFile();
  MDB_ASSERT(symbolFile, "No symbol file for frame!");
  tc::SupervisorState *supervisor = frame->mTask->GetSupervisor();
  MDB_ASSERT(supervisor, "Could not get supervisor from task!");

  return GetArrayOfVariables(cx, symbolFile, supervisor, frame->mFrame, sym::VariableSet::Locals);
};

JSValue
JsFrame::Arguments(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  PROFILE_SCOPE("Frame::Arguments", logging::kInterpreter);
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");

  if (!frame->IsValid()) {
    return JS_ThrowReferenceError(cx,
      "Frame is no longer valid for %s. Request new stack frames adn variables",
      frame->mFrame.CStringName().value_or("<unknown frame name>"));
  }
  SymbolFile *symbolFile = frame->mFrame.GetSymbolFile();
  MDB_ASSERT(symbolFile, "No symbol file for frame!");
  tc::SupervisorState *supervisor = frame->mTask->GetSupervisor();
  MDB_ASSERT(supervisor, "Could not get supervisor from task!");

  return GetArrayOfVariables(cx, symbolFile, supervisor, frame->mFrame, sym::VariableSet::Arguments);
};

JSValue
JsFrame::Caller(JSContext *cx, [[maybe_unused]] JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  return JS_ThrowTypeError(cx,
    "Caller"
    " method not implemented");
};

JSValue
JsFrame::Name(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");
  return JS_NewStringLen(cx, frame->mFrame.Name()->data(), frame->mFrame.Name()->length());
}

} // namespace mdb::js
