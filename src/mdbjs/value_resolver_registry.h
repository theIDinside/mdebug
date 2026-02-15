/** LICENSE TEMPLATE */
#pragma once

// mdb
#include "symbolication/value_visualizer.h"
#include "utils/smartptr.h"
#include <lib/string_map.h>
#include <mdbjs/include-quickjs.h>

// std
#include <string>
#include <unordered_map>
#include <vector>

namespace mdb {
class SymbolFile;
}

namespace mdb::sym {
class Type;
class Value;
} // namespace mdb::sym

namespace mdb::js {

struct Resolver final : public sym::IValueContentsResolver
{
  std::string mResolverName;
  std::string mResolverPattern;

  JSValue mResolverFn;
  JSContext *mContext;

  Resolver(JSContext *cx, std::string name, std::string pattern, JSValue function);
  ~Resolver();

  std::vector<Ref<sym::Value>> Resolve(Ref<sym::Value> baseValue, u32 offset, u32 count) const;
  virtual std::vector<Ref<sym::Value>> Resolve(
    const VariableContext &context, sym::ValueRange valueRange = {}) noexcept override;
};

struct TypeResolver
{
  sym::Type *mType;
  Resolver *mResolver;
};

class ResolverRegistry
{
  using ResolverEntry = std::shared_ptr<Resolver>;
  using Cache = std::array<TypeResolver, 8>;
  std::unordered_map<sym::Type *, ResolverEntry> mTypeToResolver;
  std::vector<ResolverEntry> mResolvers;
  JSContext *mContext;
  Cache mCache;

  ResolverRegistry(JSContext *ctx) noexcept;
  void SetResolverFor(sym::Type *type, ResolverEntry resolver);

public:
  static ResolverRegistry *Init(JSContext *ctx);
  Resolver *GetResolver(sym::Type *type);
  void RegisterResolver(std::string resolverName, std::string resolverPattern, JSValue resolverFn);
  void OnNewSymbolFile(SymbolFile *symbolFile);
};

} // namespace mdb::js
