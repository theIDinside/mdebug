/** LICENSE TEMPLATE */
#pragma once
#include "utils/immutable.h"
#include <common.h>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utils/indexing.h>

class ObjectFile;
class TypeStorage;
namespace sym::dw {

class UnitData;

struct DieNameRef
{
  UnitData *cu;
  u64 die_index;
};

struct DieNameReference
{
  union
  {
    struct
    {
      UnitData *cu;
      u64 die_index;
    };
    // Collision variant - if two identical exists, but refer to different DIE's, this DieNameReference signals
    // that
    struct
    {
      u64 collision_displacement_index; // where in the collision container, other die references that has the same
                                        // name is stored at (`non_unique_names` in `NameIndex`)
      u64 unique; // unique is true iff unique != 0xff'ff'ff'ff, meaning, die_index != 0xff'ff'ff'ff
    };
  };

  DieNameReference() noexcept : cu(nullptr), die_index(0) {}
  DieNameReference(UnitData *cu, u64 die_index) noexcept : cu(cu), die_index(die_index) {}

  bool IsValid() const;
  bool IsUnique() const noexcept;
  void SetAsCollisionVariant(u64 index) noexcept;
  void SetNotUnique() noexcept;
  void SetCollisionIndex(u64 index) noexcept;
};

class UnitData;

class NameIndex
{
public:
  using NameDieTuple = std::tuple<const char *, u64, UnitData *>;
  using NameTypeDieTuple = std::tuple<const char *, u64, UnitData *, u64>;
  struct FindResult
  {
    DieNameReference *dies;
    u32 count;
    bool
    is_some() const noexcept
    {
      return dies != nullptr;
    }

    bool
    is_none() const noexcept
    {
      return dies == nullptr;
    }
  };

  NameIndex(std::string_view name) noexcept;
  std::optional<std::span<const DieNameReference>> Search(std::string_view name) const noexcept;
  FindResult GetDies(std::string_view name) noexcept;
  void Merge(const std::vector<NameDieTuple> &parsed_die_name_references) noexcept;
  void MergeTypes(NonNullPtr<TypeStorage> objfile,
                  const std::vector<NameTypeDieTuple> &parsed_die_name_references) noexcept;

private:
  void AddName(const char *name, u64 die_index, UnitData *cu) noexcept;
  void ConvertToCollisionVariant(DieNameReference &elem, u64 die_index, UnitData *cu) noexcept;
  // The mutex only guars insert operations, because when the user is going to use query operations (finding a die
  // by it's name) the entire name index should be fully built.
  std::string_view index_name;
  std::mutex mutex;
  std::unordered_map<std::string_view, DieNameReference> mapping;
  std::vector<std::vector<DieNameReference>> colliding_die_name_refs;
};

struct ObjectFileNameIndex
{
  // backlink to the object file owning this name index
  NameIndex mFreeFunctions{"free functions"};
  NameIndex mMethods{"methods"};
  NameIndex mTypes{"types"};
  NameIndex mGlobalVariables{"global variables"};
  NameIndex mNamespaces{"namespaces"};

  template <typename Fn>
  void
  ForEachFn(std::string_view name, Fn &&f) const noexcept
  {
    if (const auto ff_res = mFreeFunctions.Search(name); ff_res) {
      auto &res = ff_res.value();
      for (auto &item : res) {
        f(item);
      }
    }

    if (const auto mf_res = mMethods.Search(name); mf_res) {
      auto &res = mf_res.value();
      for (auto &item : res) {
        f(item);
      }
    }
  }

  template <typename Fn>
  void
  RegexForEachFn(const std::string &regex_pattern, Fn &&f) const noexcept
  {
    if (const auto ff_res = mFreeFunctions.Search(regex_pattern); ff_res) {
      auto &res = ff_res.value();
      for (auto &item : res) {
        f(item);
      }
    }

    if (const auto mf_res = mMethods.Search(regex_pattern); mf_res) {
      auto &res = mf_res.value();
      for (auto &item : res) {
        f(item);
      }
    }
  }
};
} // namespace sym::dw