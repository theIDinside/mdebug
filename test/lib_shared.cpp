#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>

namespace fs = std::filesystem;

class MetricsLibHandle
{
public:
  using MetricsFn = float (*)(float);
  MetricsLibHandle(void *handle) : handle(handle)
  {
    to_celsius = (MetricsFn)dlsym(handle, "convert_fahrenheit_to_celsius");
    if (auto err = dlerror(); err != nullptr) {
      std::printf("could not load symbol 1: %s\n", err);
      exit(-1);
    }
    to_fahrenheit = (MetricsFn)dlsym(handle, "convert_celsius_to_fahrenheit");
    if (auto err = dlerror(); err != nullptr) {
      std::printf("could not load symbol 2: %s\n", err);
      exit(-1);
    }
    to_miles = (MetricsFn)dlsym(handle, "convert_kilometers_to_miles");
    if (auto err = dlerror(); err != nullptr) {
      std::printf("could not load symbol 3: %s\n", err);
      exit(-1);
    }
    to_km = (MetricsFn)dlsym(handle, "convert_miles_to_kilometers");
    if (auto err = dlerror(); err != nullptr) {
      std::printf("could not load symbol 4: %s\n", err);
      exit(-1);
    }
  }

  float
  miles_to_km(float miles)
  {
    return to_km(miles);
  }
  float
  km_to_miles(float km)
  {
    return to_miles(km);
  }

  float
  c_to_f(float celsius)
  {
    return to_fahrenheit(celsius);
  }
  float
  f_to_c(float fahrenheit)
  {
    return to_celsius(fahrenheit);
  }

  ~MetricsLibHandle() { dlclose(handle); }

private:
  void *handle;
  fs::path path;
  MetricsFn to_fahrenheit;
  MetricsFn to_celsius;
  MetricsFn to_miles;
  MetricsFn to_km;
};

int
main(int argc, const char **argv)
{
  if (argc < 2) {
    std::printf("You need to pass the path to the metricsconv shared object.\n");
    exit(-1);
  }
  const auto path = std::filesystem::path{argv[1]};
  if (!fs::exists(path)) {
    std::printf("metricsconv shared object does not exist at %s\n", argv[1]);
  }
  auto handle = dlopen(path.c_str(), RTLD_LAZY);
  if (!handle) {
    std::printf("Could not load library\n");
    exit(-1);
  }
  MetricsLibHandle metrics{handle};

  std::printf("%f fahrenheit = %f celsius", 32.0f, metrics.f_to_c(32.0f));
  std::printf("%f C = %f F", 37.0f, metrics.c_to_f(37.0f));
  std::printf("%f miles = %f km", 1000.0f, metrics.miles_to_km(1000.f));
  std::printf("%f km = %f miles", 1000.0f, metrics.km_to_miles(1000.0f));
}