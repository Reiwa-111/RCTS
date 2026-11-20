#include "entry.hpp"

#include <vector>

namespace fs = std::filesystem;

#ifndef _WIN32
namespace {
std::vector<fs::path> collect_arguments(int argc, char** argv) {
    std::vector<fs::path> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) arguments.emplace_back(argv[i]);
    return arguments;
}
} // namespace

int main(int argc, char** argv) {
    const std::vector<fs::path> arguments = collect_arguments(argc, argv);
    return rcts::run_cli(argc, arguments.data());
}
#else
namespace {
std::vector<fs::path> collect_arguments(int argc, wchar_t** argv) {
    std::vector<fs::path> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) arguments.emplace_back(argv[i]);
    return arguments;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    const std::vector<fs::path> arguments = collect_arguments(argc, argv);
    return rcts::run_cli(argc, arguments.data());
}
#endif
