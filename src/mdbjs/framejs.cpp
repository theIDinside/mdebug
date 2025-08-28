/** LICENSE TEMPLATE */
#include "framejs.h"

// mdb
#include <mdbjs/jsobject.h>
#include <mdbjs/variablejs.h>
#include <supervisor.h>
#include <symbolication/callstack.h>
#include <symbolication/objfile.h>

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
Frame::Id(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *handle = GetThisOrReturnException(handle, FrameNotAliveErrorMessage);
  return JS_NewUint32(context, static_cast<u32>(handle->mFrame.FrameId()));
}

static JSValue
GetArrayOfVariables(JSContext *context,
  SymbolFile *symbolFile,
  TraceeController *supervisor,
  sym::Frame &frame,
  sym::VariableSet set)
{
  auto arrayObject = JS_NewArray(context);
  MDB_ASSERT(JS_IsArray(context, arrayObject), "wtf");
  auto variables = symbolFile->GetVariables(*supervisor, frame, set);
  for (auto &&[index, variable] : std::ranges::views::enumerate(variables)) {
    auto jsValue = JsVariable::CreateValue(context, std::move(variable));
    JS_SetPropertyUint32(context, arrayObject, index, jsValue);
  }

  return arrayObject;
}

JSValue
Frame::Locals(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  PROFILE_SCOPE("Frame::Arguments", logging::kInterpreter);
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");

  if (!frame->IsValid()) {
    return JS_ThrowReferenceError(context,
      "Frame is no longer valid for %s. Request new stack frames adn variables",
      frame->mFrame.CStringName().value_or("<unknown frame name>"));
  }
  auto symbolFile = frame->mFrame.GetSymbolFile();
  MDB_ASSERT(symbolFile, "No symbol file for frame!");
  auto supervisor = frame->mTask->GetSupervisor();
  MDB_ASSERT(supervisor, "Could not get supervisor from task!");

  return GetArrayOfVariables(context, symbolFile, supervisor, frame->mFrame, sym::VariableSet::Locals);
};

JSValue
Frame::Arguments(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  PROFILE_SCOPE("Frame::Arguments", logging::kInterpreter);
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");

  if (!frame->IsValid()) {
    return JS_ThrowReferenceError(context,
      "Frame is no longer valid for %s. Request new stack frames adn variables",
      frame->mFrame.CStringName().value_or("<unknown frame name>"));
  }
  auto symbolFile = frame->mFrame.GetSymbolFile();
  MDB_ASSERT(symbolFile, "No symbol file for frame!");
  auto supervisor = frame->mTask->GetSupervisor();
  MDB_ASSERT(supervisor, "Could not get supervisor from task!");

  return GetArrayOfVariables(context, symbolFile, supervisor, frame->mFrame, sym::VariableSet::Arguments);
};

JSValue
Frame::Caller(JSContext *context, [[maybe_unused]] JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  return JS_ThrowTypeError(context,
    "Caller"
    " method not implemented");
};

JSValue
Frame::Name(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");
  return JS_NewStringLen(context, frame->mFrame.Name()->data(), frame->mFrame.Name()->length());
}

} // namespace mdb::js
