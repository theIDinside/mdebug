/** LICENSE TEMPLATE */
#include "name_index.h"
#include "die.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "utils/logger.h"
#include "utils/thread_pool.h"
#include <symbolication/objfile.h>

namespace mdb::sym::dw {

bool
DieNameReference::IsValid() const
{
  if (cu == nullptr) {
    return die_index != 0;
  }
  return true;
}

bool
DieNameReference::IsUnique() const noexcept
{
  return unique != 0xff'ff'ff'ff;
}

void
DieNameReference::SetAsCollisionVariant(u64 index) noexcept
{
  unique = 0xff'ff'ff'ff;
  collision_displacement_index = index;
  MDB_ASSERT(IsValid(), "We fucked up our own invariants");
}

void
DieNameReference::SetNotUnique() noexcept
{
  unique = 0xff'ff'ff'ff;
}

void
DieNameReference::SetCollisionIndex(u64 index) noexcept
{
  collision_displacement_index = index;
}

NameIndex::NameIndex(std::string_view name) noexcept : mName(name)
{
  mNameIndexShards.reserve(mdb::ThreadPool::GetGlobalPool()->WorkerCount());
}

std::span<const DieNameReference>
NameIndex::NameIndexShard::Search(std::string_view name) const noexcept
{
  auto it = mMap.find(name);
  if (it == std::end(mMap)) {
    return {};
  }

  if (it->second.IsUnique()) {
    return std::span{ &(it->second), 1 };
  }

  const auto collision_index = it->second.collision_displacement_index;
  const auto &dies = mCollidingNames[collision_index];
  return std::span{ dies };
}

void
NameIndex::NameIndexShard::AddName(const char *name, u64 die_index, UnitData *cu) noexcept
{
  auto &elem = mMap[name];
  if (elem.IsValid()) {
    if (elem.IsUnique()) {
      ConvertToCollisionVariant(elem, die_index, cu);
    } else {
      auto &collisions = mCollidingNames[elem.collision_displacement_index];
      collisions.push_back(DieNameReference{ cu, die_index });
    }
  } else {
    elem.cu = cu;
    elem.die_index = die_index;
  }
}

void
NameIndex::NameIndexShard::ConvertToCollisionVariant(DieNameReference &elem, u64 die_index, UnitData *cu) noexcept
{
  const auto index = mCollidingNames.size();
  mCollidingNames.emplace_back();
  auto &collisions = mCollidingNames.back();
  collisions.emplace_back(elem.cu, elem.die_index);
  collisions.emplace_back(cu, die_index);
  elem.SetAsCollisionVariant(index);
}

NameIndex::NameIndexShard *
NameIndex::CreateShard() noexcept
{
  std::lock_guard lock(mMutex);
  DBGLOG(core, "Creating name index shard {} for {}", mNameIndexShards.size(), mName)
  auto &last = mNameIndexShards.emplace_back(std::make_unique<NameIndexShard>());
  return last.get();
}

void
NameIndex::Merge(const std::vector<NameIndex::NameDieTuple> &nameToDieReferences) noexcept
{
  PROFILE_SCOPE("NameIndex::Merge", "indexing");
  auto &shard = *CreateShard();
  DBGLOG(dwarf, "[name index: {}] Adding {} names", mName, nameToDieReferences.size());
  for (const auto &[name, idx, cu] : nameToDieReferences) {
    shard.AddName(name, idx, cu);
  }
}

void
NameIndex::MergeTypes(
  NonNullPtr<TypeStorage> typeStorage, const std::vector<NameTypeDieTuple> &nameToDieReferences) noexcept
{
  PROFILE_SCOPE_ARGS("NameIndex::MergeTypes", "indexing", PEARG("types", nameToDieReferences.size()));
  DBGLOG(dwarf, "[name index: {}] Adding {} names", mName, nameToDieReferences.size());
  auto &shard = *CreateShard();
  for (const auto &[name, idx, cu, hash] : nameToDieReferences) {
    shard.AddName(name, idx, cu);
    const auto dieRef = cu->GetDieByCacheIndex(idx);
    const DieMetaData *thisDie = dieRef.GetDie();
    if (thisDie->mTag == DwarfTag::DW_TAG_typedef || thisDie->mTag == DwarfTag::DW_TAG_array_type) {
      continue;
    }
    const auto offs = Offset{ dieRef.GetDie()->mSectionOffset };
    const auto possibleSize = dieRef.ReadAttribute(Attribute::DW_AT_byte_size);
    MDB_ASSERT(possibleSize.has_value(),
      "Expected a 'root' die for a type to have a byte size cu={}, die=0x{:x}, objfile={}",
      cu->SectionOffset(),
      dieRef.GetDie()->mSectionOffset,
      cu->GetObjectFile()->GetObjectFileId());

    Type *type = typeStorage->CreateNewType(
      thisDie->mTag, offs, IndexedDieReference{ cu, idx }, possibleSize->AsUnsignedValue(), name);
    if (dieRef.GetDie()->mTag == DwarfTag::DW_TAG_base_type) {
      UnitReader reader{ cu };
      reader.SeekDie(*dieRef.GetDie());
      auto attr = dieRef.ReadAttribute(Attribute::DW_AT_encoding);
      MDB_ASSERT(attr.has_value(),
        "Failed to read encoding of base type. cu={}, die=0{:x}, objfile={}",
        cu->SectionOffset(),
        dieRef.GetDie()->mSectionOffset,
        cu->GetObjectFile()->GetObjectFileId());
      auto encoding = attr.and_then(
        [](const auto &val) { return std::optional{ static_cast<BaseTypeEncoding>(val.AsUnsignedValue()) }; });
      type->SetBaseTypeEncoding(encoding.value());
    }
  }
}

std::optional<std::vector<DieNameReference>>
NameIndex::Search(std::string_view name) const noexcept
{
  // TODO: Implement a least recently used caching algorithm set to some arbitrary size (32, 64, whatever)
  //  based on an (speculation) assumption that searching for N, usually is followed by a search for N some time
  //  later (for instance turning a function breakpoint on / off a couple of times in a row, for whatever reason)
  std::vector<DieNameReference> result;

  for (const auto &shard : mNameIndexShards) {
    for (const auto &r : shard->Search(name)) {
      result.push_back(r);
    }
  }
  return result;
}

} // namespace mdb::sym::dw