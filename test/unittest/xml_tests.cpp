#include "utils/expected.h"
#include <gtest/gtest.h>
#include <set>
#include <string_view>
#include <unordered_set>
#include <utils/util.h>
#include <utils/xml.h>

/**

Hgp11236.1127a

Hgp0.0

!
+
qSupported:multiprocess+;swbreak+;hwbreak+;library+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;QThreadOptions+;no-resumed+;memory-tagging+;xmlRegisters=i386;QNonStop+
+
QThreadEvents:1
+
QNonStop:1
+
QDisableRandomization:1
+
Z0,da1140,0
Z0,4011da,1
+
vCont;c
+
vStopped
+
vCont;c
+
qXfer:threads:read::0,10000


qXfer:features:read:i386:0,10000

*/

static constexpr std::string_view xmlData = R"(<threads>
<thread id="pbbf7.bbf7" core="8" name="fork"/>
<thread id="pbc08.bc08" core="4" name="threads_shared"/>
<thread id="pbc08.bc5b" core="2" name="Foo"/>
<thread id="pbc08.bc5c" core="4" name="Bar"/>
<thread id="pbc08.bc5d" core="14" name="Baz"/>
<thread id="pbc08.bc5e" core="5" name="Quux"/>
<thread id="pbc08.bc5f" core="4" name="420"/>
<thread id="pbc08.bc60" core="12" name="1337"/>
<thread id="pbc08.bc61" core="14" name="MDB"/>
<thread id="pbc08.bc62" core="6" name="DAP"/>
</threads>
)";

TEST(XML, ParseThreads)
{
  mdb::xml::XMLParser parser(xmlData);
  mdb::xml::XMLElementView root = parser.parse();
}

TEST(XML, ParsedThreadValues)
{
  mdb::xml::XMLParser parser(xmlData);
  mdb::xml::XMLElementView root = parser.parse();
  EXPECT_EQ(root.children.size(), 10);
  std::unordered_set<std::string> thread_names{};
  for (const auto &child : root.children) {
    if (const auto thread_name = child->attribute("name"); thread_name) {
      thread_names.emplace(thread_name.value());
    }
  }

  for (const auto &name : {"fork", "threads_shared", "Foo", "Bar", "Baz", "Quux", "420", "1337", "MDB", "DAP"}) {
    EXPECT_TRUE(thread_names.contains(name));
  }
}

TEST(XML, CollectByName)
{
  mdb::xml::XMLParser parser(xmlData);
  mdb::xml::XMLElementView root = parser.parse();
  const auto elems = mdb::xml::collect_by_name(root, "thread", false);
  EXPECT_EQ(root.children.size(), 10);
}