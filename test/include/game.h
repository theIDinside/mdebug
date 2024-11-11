#pragma once
// Regular POD structs, enum classes as well as POD unions

enum class NPCKind : unsigned char
{
  Friend,
  Minion,
  Boss
};

struct Friend
{
  const char *name;
  int health;
};

struct Minion
{
  const char *type;
  int health;
  int damage;
  int id;
};

struct Boss
{
  const char *type;
  const char *name;
  int health;
  int damage;
  int id;
  int spells;
};

struct NPC
{
  NPCKind kind;
  union
  {
    Friend buddy;
    Minion critter;
    Boss boss;
  } payload;

  static constexpr NPC
  MakeBoss(const char *t, const char *n, int health, int dmg, int id, int spells)
  {
    return NPC{.kind = NPCKind::Boss, .payload = {.boss = {t, n, health, dmg, id, spells}}}; // BOSS_BP
  }

  static constexpr NPC
  MakeFriend(const char *n, int h)
  {
    return NPC{.kind = NPCKind::Friend, .payload = {.buddy = {n, h}}}; // FRIEND_BP
  }
  static constexpr NPC
  MakeMinion(const char *t, int h, int dmg, int id)
  {
    return NPC{.kind = NPCKind::Minion, .payload = {.critter = {t, h, dmg, id}}}; // MINION_BP
  }
};