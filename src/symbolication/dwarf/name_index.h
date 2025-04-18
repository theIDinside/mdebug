/** LICENSE TEMPLATE */
#pragma once
#include "utils/immutable.h"
#include <common.h>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utils/indexing.h>
namespace mdb {
class ObjectFile;
class TypeStorage;
} // namespace mdb
namespace mdb::sym::dw {

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
  // The sharding adds additional overhead during lookups, because we now have to do N lookups per search value
  // instead of just 1. But it also decreases indexing time by T/N, which can be fairly substantial for large
  // projects (like browsers, which is the test bed for this debugger). That additional overhead, which worst case
  // is N times longer, ish, for N shards, I wager is acceptable because it won't be noticable during run time.
  // Will the user notice a 5-25ms extra overhead for an operation that may take 150ms normally, or will the user
  // notice the 40 sec/16 shards (down to 2.5 seconds) drop? Probably the latter.
  struct NameIndexShard
  {
    std::unordered_map<std::string_view, DieNameReference> mMap{};
    std::vector<std::vector<DieNameReference>> mCollidingNames{};

    std::span<const DieNameReference> Search(std::string_view name) const noexcept;
    void AddName(const char *name, u64 die_index, UnitData *cu) noexcept;
    void ConvertToCollisionVariant(DieNameReference &elem, u64 die_index, UnitData *cu) noexcept;
  };

  std::vector<std::unique_ptr<NameIndexShard>> mNameIndexShards{};

public:
  using NameDieTuple = std::tuple<const char *, u64, UnitData *>;
  using NameTypeDieTuple = std::tuple<const char *, u64, UnitData *, u64>;

  explicit NameIndex(std::string_view name) noexcept;

  std::optional<std::vector<DieNameReference>> Search(std::string_view name) const noexcept;
  NameIndexShard *CreateShard() noexcept;
  void Merge(const std::vector<NameDieTuple> &nameToDieReferences) noexcept;
  void MergeTypes(NonNullPtr<TypeStorage> objfile,
                  const std::vector<NameTypeDieTuple> &nameToDieReferences) noexcept;

private:
  // The mutex only guars insert operations, because when the user is going to use query operations (finding a die
  // by it's name) the entire name index should be fully built.
  std::string_view mName;
  std::mutex mMutex;
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
  ForEachType(std::string_view name, Fn &&fn) const noexcept
  {
    if (const auto searchResult = mTypes.Search(name); searchResult) {
      auto &res = searchResult.value();
      for (auto &item : res) {
        fn(item);
      }
    }
  }

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
};
} // namespace mdb::sym::dw