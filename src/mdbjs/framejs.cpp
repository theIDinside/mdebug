#include "framejs.h"
#include "js/AllocPolicy.h"
#include "js/Array.h"
#include "js/ErrorReport.h"
#include "js/TypeDecls.h"
#include "mdbjs/util.h"
#include "mdbjs/variablejs.h"
#include "utils/debug_value.h"
#include "utils/logger.h"
#include <symbolication/objfile.h>

namespace mdb {

bool
FrameLookupHandle::IsValid() noexcept
{
  return !mTask->VariableReferenceIsStale(mFrame.FrameId());
}

} // namespace mdb

namespace mdb::js {
/* static */
bool
Frame::js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS ::CallArgs args = JS ::CallArgsFromVp(argc, vp);
  JS ::RootedObject callee(cx, &args.thisv().toObject());
  auto frameJs = Get(callee.get());
  args.rval().setInt32(static_cast<int>(frameJs->mFrame.FrameId()));
  return true;
}

/* static */
bool
Frame::js_locals(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS ::CallArgs args = JS ::CallArgsFromVp(argc, vp);
  JS ::RootedObject callee(cx, &args.thisv().toObject());
  auto frameJs = Get(callee.get());
  if (!frameJs->IsValid()) {
    JS_ReportErrorASCII(cx, "frame liveness not guaranteed for %s. Request new stack frames & variables.",
                        frameJs->mFrame.CStringName().value_or("<unknown frame name>"));
    return false;
  }
  auto symbolFile = frameJs->mFrame.GetSymbolFile();
  auto variables =
    symbolFile->GetVariables(*frameJs->mTask->GetSupervisor(), frameJs->mFrame, sym::VariableSet::Locals);

  JS::Rooted<JSObject *> arrayObject{cx, JS::NewArrayObject(cx, variables.size())};

  for (auto i = 0u; i < variables.size(); ++i) {
    JS::Rooted<JSObject *> jsVariable{cx, mdb::js::Variable::Create(cx, variables[i])};
    JS_SetElement(cx, arrayObject, i, jsVariable);
  }

  args.rval().setObject(*arrayObject);
  return true;
}

/* static */
bool
Frame::js_arguments(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS ::CallArgs args = JS ::CallArgsFromVp(argc, vp);
  JS ::RootedObject callee(cx, &args.thisv().toObject());
  auto frameJs = Get(callee.get());

  auto symbolFile = frameJs->mFrame.GetSymbolFile();
  auto variables =
    symbolFile->GetVariables(*frameJs->mTask->GetSupervisor(), frameJs->mFrame, sym::VariableSet::Arguments);

  JS::Rooted<JSObject *> arrayObject{cx, JS::NewArrayObject(cx, variables.size())};

  for (auto i = 0u; i < variables.size(); ++i) {
    JS::Rooted<JSObject *> jsVariable{cx, mdb::js::Variable::Create(cx, variables[i])};
    JS_SetElement(cx, arrayObject, i, jsVariable);
  }

  args.rval().setObject(*arrayObject);
  return true;
}

/* static */
bool
Frame::js_caller(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  TODO(__PRETTY_FUNCTION__);
}

/* static */
bool
Frame::js_name(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS ::CallArgs args = JS ::CallArgsFromVp(argc, vp);
  JS ::RootedObject callee(cx, &args.thisv().toObject());
  auto frameJs = Get(callee.get());
  auto frameName = frameJs->mFrame.Name().and_then([cx](auto view) -> std::optional<JSString *> {
    auto js = PrepareString(cx, view);
    if (js) {
      return std::optional{js};
    }
    return {};
  });

  if (!frameName) {
    JS_ReportOutOfMemory(cx);
    return false;
  }
  args.rval().setString(frameName.value());
  return true;
}

} // namespace mdb::js
