#include <charconv>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace fs = std::filesystem;

void
printDirectoryContents(const std::string &path, std::optional<int> sleepPerIteration)
{
  try {
    auto dirEntryItem = 1ull;
    if (fs::exists(path) && fs::is_directory(path)) {
      for (const auto &entry : fs::directory_iterator(path)) {
        std::cout << "#" << dirEntryItem << " " << entry.path().string() << std::endl;
        ++dirEntryItem; // #ITERATE_DIR_ENTRY_BP
        if (sleepPerIteration) {
          std::this_thread::sleep_for(std::chrono::milliseconds{*sleepPerIteration});
        }
      }
    } else {
      std::cerr << "Error: The path does not exist or is not a directory." << std::endl;
    }
  } catch (const fs::filesystem_error &e) {
    std::cerr << "Filesystem error: " << e.what() << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "General error: " << e.what() << std::endl;
  }
}

int
main(int argc, char *argv[])
{
  if (argc < 2) {
    std::cerr << "argument count was: " << argc << std::endl;
    std::cerr << "Usage: " << argv[0] << " <directory_path>" << std::endl; // #NO_INPUT_BP
    return 1;
  }

  std::optional<int> sleepTimeMilliseconds{};
  if(argc > 2) {
    std::string_view sleepArg{argv[2]};
    int readInValue = 0;
    const auto res = std::from_chars(sleepArg.begin(), sleepArg.end(), readInValue);
    if(res.ec == std::errc()) {
      sleepTimeMilliseconds = readInValue;
    } else {
      std::cout << " failed to read sleep arg: " << sleepArg << " setting to default value 1ms";
    }
  }

  std::string directoryPath = argv[1];
  printDirectoryContents(directoryPath, sleepTimeMilliseconds);

  return 0;
}
