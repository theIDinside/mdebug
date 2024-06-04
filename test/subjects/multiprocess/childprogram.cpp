#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

void
printDirectoryContents(const std::string &path)
{
  try {
    auto dirEntryItem = 1ull;
    if (fs::exists(path) && fs::is_directory(path)) {
      for (const auto &entry : fs::directory_iterator(path)) {
        std::cout << "#" << dirEntryItem << " " << entry.path().string() << std::endl;
        ++dirEntryItem; // #ITERATE_DIR_ENTRY_BP
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
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <directory_path>" << std::endl; // #NO_INPUT_BP
    return 1;
  }

  std::string directoryPath = argv[1];
  printDirectoryContents(directoryPath);

  return 0;
}
