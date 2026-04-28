#pragma once

// Per-file readability aliases. INCLUDE ONLY FROM .cpp FILES.
// Never include this from another header -- the using declarations
// would leak into every translation unit that pulls that header in.

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using std::array;
using std::atomic;
using std::byte;
using std::error_code;
using std::exception;
using std::int8_t;
using std::invalid_argument;
using std::make_shared;
using std::make_unique;
using std::memory_order_relaxed;
using std::nullopt;
using std::optional;
using std::ostringstream;
using std::pair;
using std::runtime_error;
using std::scoped_lock;
using std::shared_ptr;
using std::size_t;
using std::span;
using std::string;
using std::string_view;
using std::system_error;
using std::to_integer;
using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::unique_lock;
using std::unique_ptr;
using std::vector;
namespace fs = std::filesystem;
namespace chrono = std::chrono;
