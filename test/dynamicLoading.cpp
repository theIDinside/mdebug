#include "templated_code/template.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

static void
test_lessthan(void *handle)
{
  // use less_than defined in template.h but in this object file
  const float float_res = less_than<float>(19.2f, 23812.0f);
  const int int_res = less_than<int>(123, 456);
  const double double_res = less_than<double>(123.0f, 932.0f);

  // Use less than in dynamically loaded SO, which also uses the one defined in template.h
  using MinFloat = float (*)(float, float);
  char *error;
  MinFloat min = (MinFloat)dlsym(handle, "min_float");
  if ((error = dlerror()) != NULL) {
    printf("Failed to find min_float\n");
    fputs(error, stderr);
    exit(1);
  }
  float a = 1.23;
  float b = 3.21;
  auto less = (*min)(a, b);
  printf("The less than value of %f and %f was %f\n", a, b, less);
}

static void
perform_dynamic()
{
  using MetricsFn = float (*)(float);

  char *error;

  printf("About to dlopen libmetricsconv.so\n"); // BP_PRE_OPEN
  auto handle = dlopen("./bin/libmetricsconv.so", RTLD_LAZY);
  if (!handle) {
    printf("Failed to dlopen\n");
    fputs(dlerror(), stderr);
    exit(1);
  }

  printf("Attempting to dlsym function\n"); // BP_PRE_DLSYM
  MetricsFn convert_to_km = (MetricsFn)dlsym(handle, "convert_miles_to_kilometers");
  if ((error = dlerror()) != NULL) {
    printf("Failed to find convert_miles_to_kilometers\n");
    fputs(error, stderr);
    exit(1);
  }

  printf("Attempting to call the dynamically loaded function, converting 1 mile to km:\n"); // BP_PRE_CALL
  printf("%f\n", (*convert_to_km)(1.0));

  test_lessthan(handle);

  printf("Closing DL handle\n");
  auto i = 10; // BP_PRE_CLOSE
  dlclose(handle);
}

int
main(int argc, const char **argv)
{
  printf("Starting application..\n");
  perform_dynamic();
}