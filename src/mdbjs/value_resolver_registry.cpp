/** LICENSE TEMPLATE */
#include "value_resolver_registry.h"
#include "task.h"

// mdb
#include <mdbjs/mdbjs.h>
#include <mdbjs/util.h>
#include <mdbjs/variablejs.h>
#include <symbolication/objfile.h>
#include <symbolication/type.h>
#include <tracer.h>
#include <utils/log_channel.h>
#include <utils/logger.h>

// std
#include <algorithm>

namespace mdb::js {

std::vector<Ref<sym::Value>>
Resolver::Resolve(const VariableContext &context, sym::ValueRange valueRange) noexcept
{
  auto resolvedValues = Resolve(context.GetValue(), valueRange.start.value_or(0), valueRange.count.value_or(0));

  for (auto &value : resolvedValues) {
    sym::Type *type = value->EnsureTypeResolved();
    auto variableContext =
      type->IsPrimitive() ? VariableContext::CloneFrom(0, context) : Tracer::CloneFromVariableContext(context);

    if (variableContext->mId > 0) {
      variableContext->mTask->CacheValueObject(variableContext->mId, value);
    }
  }
  return resolvedValues;
}

Resolver::Resolver(JSContext *cx, std::string name, std::string pattern, JSValue function)
    : mResolverName(std::move(name)), mResolverPattern(std::move(pattern)), mResolverFn(JS_DupValue(cx, function)),
      mContext(cx)
{
}

Resolver::~Resolver() { JS_FreeValue(mContext, mResolverFn); }

std::vector<Ref<sym::Value>>
Resolver::Resolve(Ref<sym::Value> baseValue, u32 offset, u32 count) const
{
  // Convert baseValue to JSValue (JsVariable)
  StackValue jsVariable = StackValue::Wrap(mContext, JsVariable::CreateValue(mContext, std::move(baseValue)));

  // Convert offset and count to JSValue
  StackValue jsOffset = StackValue::NewUint32(mContext, offset);
  StackValue jsCount = StackValue::NewUint32(mContext, count);

  // Call the JS resolver function with arguments: (jsvariable, offset, count)
  JSValue args[] = { jsVariable, jsOffset, jsCount };
  JSValue thisValue = JS_UNDEFINED;
  auto callResult = CallFunction(mContext, mResolverFn, thisValue, args);

  // Check if the call was successful
  if (!callResult) {
    DBGLOG(core, "Failed to call resolver function '{}': {}", mResolverName, callResult.error().mExceptionMessage);
    return {};
  }

  StackValue returnValue = StackValue::Wrap(mContext, callResult.value());

  // Ensure the return value is an array
  if (!JS_IsArray(mContext, returnValue)) {
    DBGLOG(core, "Resolver function '{}' did not return an array", mResolverName);
    return {};
  }

  // Get the array length
  StackValue lengthValue = StackValue::GetPropertyString(mContext, returnValue, "length");
  u32 arrayLength = 0;
  JS_ToUint32(mContext, &arrayLength, lengthValue);

  // Extract each JsVariable from the array and convert to Ref<sym::Value>
  std::vector<Ref<sym::Value>> result;
  result.reserve(arrayLength);

  for (u32 i = 0; i < arrayLength; ++i) {
    StackValue element = returnValue.GetPropertyUint32(i);
    // Extract the native sym::Value* from the JsVariable
    sym::Value *nativeValue = JsVariable::GetNative(mContext, element);

    if (nativeValue) {
      // Increase reference count and add to result
      result.push_back(Ref<sym::Value>{ nativeValue });
    } else {
      DBGLOG(core, "Element {} in resolver '{}' result is not a valid JsVariable", i, mResolverName);
    }
  }

  return result;
}

ResolverRegistry::ResolverRegistry(JSContext *ctx) noexcept : mContext(ctx), mCache{}
{
  // Initialize cache with null entries
  for (auto &entry : mCache) {
    entry.mType = nullptr;
    entry.mResolver = nullptr;
  }
}

void
ResolverRegistry::SetResolverFor(sym::Type *type, ResolverEntry resolver)
{
  DBGLOG(core, "Adding resolver {} for type {}", resolver->mResolverName, type->mName);
  mTypeToResolver.emplace(type, std::move(resolver));
}

/* static */
ResolverRegistry *
ResolverRegistry::Init(JSContext *ctx)
{
  return new ResolverRegistry{ ctx };
}

Resolver *
ResolverRegistry::GetResolver(sym::Type *type)
{
  for (size_t i = 0; i < mCache.size(); ++i) {
    if (mCache[i].mType == type) {
      if (i > 0) {
        TypeResolver found = mCache[i];
        std::copy_backward(mCache.begin(), mCache.begin() + i, mCache.begin() + i + 1);
        mCache[0] = found;
      }
      return mCache[0].mResolver;
    }
  }

  auto iterator = mTypeToResolver.find(type);
  if (iterator != std::end(mTypeToResolver)) {
    Resolver *resolver = iterator->second.get();
    std::copy_backward(mCache.begin(), mCache.begin() + mCache.size() - 1, mCache.end());
    mCache[0] = TypeResolver{ .mType = type, .mResolver = resolver };
    return resolver;
  }

  return nullptr;
}

void
ResolverRegistry::OnNewSymbolFile(SymbolFile *symbolFile)
{
  for (const auto &resolver : mResolvers) {
    symbolFile->ForEachTypeMatching(
      resolver->mResolverPattern, false, [&](sym::Type *matchedType) { SetResolverFor(matchedType, resolver); });
  }
}

void
ResolverRegistry::RegisterResolver(std::string resolverName, std::string resolverPattern, JSValue resolverFn)
{
  auto entry =
    std::make_shared<Resolver>(mContext, std::move(resolverName), std::move(resolverPattern), resolverFn);

  Tracer::ForEachObjectFile([&](ObjectFile &obj) {
    DBGLOG(core, "Register resolver {} with {}", entry->mResolverName, obj.GetPathString());
    obj.ForEachTypeMatching(
      entry->mResolverPattern, false, [&](sym::Type *matchedType) { SetResolverFor(matchedType, entry); });
    return true;
  });

  mResolvers.push_back(std::move(entry));
}

} // namespace mdb::js
