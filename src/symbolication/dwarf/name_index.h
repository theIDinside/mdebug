#pragma once
#include <common.h>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utils/indexing.h>

class ObjectFile;
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

  bool is_valid() const;
  bool is_unique() const noexcept;
  void set_as_collision_variant(u64 index) noexcept;
  void set_not_unique() noexcept;
  void set_collision_index(u64 index) noexcept;
};

class UnitData;

class NameIndex
{
public:
  using NameDieTuple = std::tuple<const char*, u64, UnitData *>;
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
  std::optional<std::span<const DieNameReference>> search(std::string_view name) const noexcept;
  FindResult get_dies(std::string_view name) noexcept;
  void merge(const std::vector<NameDieTuple> &parsed_die_name_references) noexcept;
  void merge_types(ObjectFile *objfile, const std::vector<NameDieTuple> &parsed_die_name_references) noexcept;

private:
  void add_name(const char* name, u64 die_index, UnitData *cu) noexcept;
  void convert_to_collision_variant(DieNameReference &elem, u64 die_index, UnitData *cu) noexcept;
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
  NameIndex free_functions{"free functions"};
  NameIndex methods{"methods"};
  NameIndex types{"types"};
  NameIndex global_variables{"global variables"};
  NameIndex namespaces{"namespaces"};

  template <typename Fn>
  void
  for_each_fn(std::string_view name, Fn &&f) const noexcept
  {
    if (const auto ff_res = free_functions.search(name); ff_res) {
      auto &res = ff_res.value();
      for (auto &item : res) {
        f(item);
      }
    }

    if (const auto mf_res = methods.search(name); mf_res) {
      auto &res = mf_res.value();
      for (auto &item : res) {
        f(item);
      }
    }
  }

  template <typename Fn>
  void
  regex_for_each_fn(const std::string &regex_pattern, Fn &&f) const noexcept
  {
    if (const auto ff_res = free_functions.search(regex_pattern); ff_res) {
      auto &res = ff_res.value();
      for (auto &item : res) {
        f(item);
      }
    }

    if (const auto mf_res = methods.search(regex_pattern); mf_res) {
      auto &res = mf_res.value();
      for (auto &item : res) {
        f(item);
      }
    }
  }
};
} // namespace sym::dw