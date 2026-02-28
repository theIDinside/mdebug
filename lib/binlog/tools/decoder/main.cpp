/** LICENSE TEMPLATE */
#include "decoder.h"
#include <cstring>
#include <iostream>

void
PrintUsage(const char *programName)
{
  std::cout << "Usage: " << programName << " <binary_log_file> --format-def <format_def_file> [options]\n"
            << "\n"
            << "Options:\n"
            << "  --format-def <file>     Format definitions file (log_formats.def) [REQUIRED]\n"
            << "  --channel-names <file>  Channel names definitions file [OPTIONAL]\n"
            << "  --format text|json      Output format (default: text)\n"
            << "  --channel <name>        Filter by channel name\n"
            << "  --help                  Show this help message\n"
            << "\n"
            << "Examples:\n"
            << "  " << programName << " mdb.binlog --format-def log_formats.def\n"
            << "  " << programName << " mdb.binlog --format-def defs/log_formats.def --format json\n"
            << "  " << programName
            << " mdb.binlog --format-def log_formats.def --channel-names channel_names.def\n"
            << "  " << programName << " mdb.binlog --format-def log_formats.def --channel core\n";
}

int
main(int argc, char **argv)
{
  if (argc < 2) {
    std::cerr << "Error: No binary log file specified\n\n";
    PrintUsage(argv[0]);
    return 1;
  }

  const char *logFile = argv[1];

  if (std::strcmp(logFile, "--help") == 0 || std::strcmp(logFile, "-h") == 0) {
    PrintUsage(argv[0]);
    return 0;
  }

  // Find required --format-def argument
  const char *formatDefFile = nullptr;
  for (int i = 2; i < argc; ++i) {
    if (std::strcmp(argv[i], "--format-def") == 0) {
      if (i + 1 >= argc) {
        std::cerr << "Error: --format-def requires an argument\n";
        return 1;
      }
      formatDefFile = argv[i + 1];
      break;
    }
  }

  if (!formatDefFile) {
    std::cerr << "Error: --format-def <file> is required\n\n";
    PrintUsage(argv[0]);
    return 1;
  }

  // Find optional --channel-names argument
  const char *channelNamesFile = nullptr;
  for (int i = 2; i < argc; ++i) {
    if (std::strcmp(argv[i], "--channel-names") == 0) {
      if (i + 1 >= argc) {
        std::cerr << "Error: --channel-names requires an argument\n";
        return 1;
      }
      channelNamesFile = argv[i + 1];
      break;
    }
  }

  try {
    logdecode::LogDecoder decoder(logFile, formatDefFile, channelNamesFile ? channelNamesFile : "");

    // Parse options
    for (int i = 2; i < argc; ++i) {
      if (std::strcmp(argv[i], "--format-def") == 0) {
        // Skip --format-def and its argument
        ++i;
        continue;
      } else if (std::strcmp(argv[i], "--channel-names") == 0) {
        // Skip --channel-names and its argument
        ++i;
        continue;
      } else if (std::strcmp(argv[i], "--format") == 0) {
        if (i + 1 >= argc) {
          std::cerr << "Error: --format requires an argument\n";
          return 1;
        }

        const char *format = argv[++i];
        if (std::strcmp(format, "json") == 0) {
          decoder.SetOutputFormat(logdecode::LogDecoder::OutputFormat::JSON);
        } else if (std::strcmp(format, "text") == 0) {
          decoder.SetOutputFormat(logdecode::LogDecoder::OutputFormat::Text);
        } else {
          std::cerr << "Error: Unknown format '" << format << "'\n";
          return 1;
        }
      } else if (std::strcmp(argv[i], "--channel") == 0) {
        if (i + 1 >= argc) {
          std::cerr << "Error: --channel requires an argument\n";
          return 1;
        }

        const char *channelName = argv[++i];

        // Map channel name to ID
        static const std::unordered_map<std::string, logdecode::u8> channelMap = { { "core", 0 },
          { "control", 1 },
          { "dap", 2 },
          { "dwarf", 3 },
          { "awaiter", 4 },
          { "eh", 5 },
          { "remote", 6 },
          { "warning", 7 },
          { "interpreter", 8 } };

        auto it = channelMap.find(channelName);
        if (it == channelMap.end()) {
          std::cerr << "Error: Unknown channel '" << channelName << "'\n";
          return 1;
        }

        decoder.SetChannelFilter(it->second);
      } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
        PrintUsage(argv[0]);
        return 0;
      } else {
        std::cerr << "Error: Unknown option '" << argv[i] << "'\n\n";
        PrintUsage(argv[0]);
        return 1;
      }
    }

    // Decode and output
    decoder.Decode(std::cout);

    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << '\n';
    return 1;
  }
}
