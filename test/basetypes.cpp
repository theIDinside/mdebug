
struct Structure
{
  const char *name;
  int count;
  float fraction;
};

void
structured_byvalue(Structure s)
{
  int add = 10;
  auto clone = s;
  clone.count += add; // BYVAL_BP
  const auto stamped = clone;
}

void
structured_ref(Structure &s)
{
}

void
structured_ptrref(Structure *s)
{
}

void
structured(const char *name, int count, float fr)
{
  Structure structure{name, count, fr};
  structure.count += 1;
  structure.fraction += 0.02; // STRUCT_BP
  structured_byvalue(structure);
  structured_ref(structure);
  structured_ptrref(&structure);
}

void
locals()
{
  int a = 10;
  int b = 20;
  int c = 30;
  double d = 239.234;
  const char *str = "Hello world!";
  auto res = a + b + c; // LOC_BP
}

void
args(int a, float b, long c)
{
  int res_a = a * 2;
  float res_b = b * 4.0;
  long res_c = c * 8; // ARGS_BP
}

int
main(int argc, const char **argv)
{
  locals();
  args(1, 2.0f, 3l);
  structured("foo", 42, 0.39);
}