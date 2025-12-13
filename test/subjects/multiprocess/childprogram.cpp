#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <print>
#include <string>
#include <thread>

namespace fs = std::filesystem;

void
printDirectoryContents(const std::string &path, std::optional<int> sleepPerIteration)
{
  auto iter = 0;
  try {
    auto dirEntryItem = 1ull;
    if (fs::exists(path) && fs::is_directory(path)) {
      for (const auto &entry : fs::directory_iterator(path)) {
        std::println("# {} {}", dirEntryItem, entry.path().string());
        ++dirEntryItem; // #ITERATE_DIR_ENTRY_BP
        if (sleepPerIteration) {
          // Make sure we handle signals properly.
          if (iter == 500) {
            raise(SIGINT);
          }
          std::this_thread::sleep_for(std::chrono::milliseconds{ *sleepPerIteration });
        }
        ++iter;
      }
    } else {
      std::println(stderr, "Error: The path does not exist or is not a directory.");
    }
  } catch (const fs::filesystem_error &e) {
    std::println(stderr, "Filesystem error: {}", e.what());
  } catch (const std::exception &e) {
    std::println(stderr, "General error: {}", e.what());
  }
}

int
main(int argc, char *argv[])
{
  if (argc < 2) {
    std::println(stderr, "argument count was: {}\nUsage: {} <directory_path>", argc, argv[0]);
    return 1;
  }

  std::optional<int> sleepTimeMilliseconds{};
  if (argc > 2) {
    std::string_view sleepArg{ argv[2] };
    int readInValue = 0;
    const auto res = std::from_chars(sleepArg.begin(), sleepArg.end(), readInValue);
    if (res.ec == std::errc()) {
      sleepTimeMilliseconds = readInValue;
    } else {
      std::println(" failed to read sleep arg: {} setting to default value 1ms", sleepArg);
    }
  }

  using ThreadPool = std::vector<std::thread>;
  ThreadPool pool;
  std::mutex stdioLock{};
  static bool keepRunning = true;
  for (auto i = 0; i < 8; i++) {
    pool.emplace_back(std::thread{ [&stdioLock, num = i]() {
      while (keepRunning) {
        std::printf("thread %d going to sleep\n", num);
        std::this_thread::sleep_for(std::chrono::milliseconds{ 400 + num * 30 });
      }
    } });
  }

  atexit([]() { keepRunning = false; });

  std::string directoryPath = argv[1];
  printDirectoryContents(directoryPath, sleepTimeMilliseconds);
  keepRunning = false;
  for (auto &j : pool) {
    j.join();
  }

  return 0;
}
