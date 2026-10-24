#include "neural/ComponentManifest.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <mutex>
#include <system_error>

#include "core/Sha256.h"
#include "core/Utf8.h"
#include "neural/RuntimeManifest.h"

namespace fs = std::filesystem;

namespace sidecar {
namespace {

struct KnownBuild {
  const char* fileName;   // lowercase
  const char* sha256;     // lowercase
};

// The builds the 0.6.0 release bundle carries, digested from that bundle
// (dlss5-wow-sidecar-v0.6.0.zip, SHA-256 6eda271b...094c).
//
// dxgi.dll reports ReShade 6.8.0.2155 by crosire. It is unsigned, as the
// add-on-enabled ReShade builds are, so pinning it here records what shipped;
// matching it against crosire's own installer is a separate step and is
// recorded in the project notes, not assumed.
//
// nvngx_dlssnr.dll is not listed: RuntimeManifest owns those digests, and a
// second copy here could only drift from it.
constexpr std::array<KnownBuild, 3> kKnownBuilds{{
    {"dxgi.dll", "0cee63f9c9f13f3ac909c5b4903f4dbb4b719a7ab3b4f13b0deaf83c814b94f7"},
    {"renodx-dlss5.addon64",
     "e1c28fde0922b12fc10734e58c3d24a36808e575247f4fd4f36226540d7ee023"},
    // Valid NVIDIA Authenticode signature.
    {"nvngx_dlss.dll", "c85f971ce023c9f3492fc7455f0b01a24ba18ea39636407a846902c4360b0b7e"},
}};

constexpr const char* kNeuralRuntime = "nvngx_dlssnr.dll";

std::string Lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

// What Windows will map as code from this folder: DLLs, and ReShade add-ons,
// which are DLLs under another extension (.addon64 for 64-bit hosts, .addon for
// either).
bool IsLoadable(const fs::path& path) {
  const std::string ext = Lower(Utf8FromPath(path.extension()));
  return ext == ".dll" || ext == ".addon64" || ext == ".addon";
}

struct CachedDigest {
  uintmax_t size = 0;
  fs::file_time_type stamp{};
  std::string sha256;
};

std::string Digest(const fs::path& path, DigestReuse reuse) {
  std::error_code sizeEc, timeEc;
  const auto size = fs::file_size(path, sizeEc);
  const auto stamp = fs::last_write_time(path, timeEc);
  const bool stampable = !sizeEc && !timeEc;

  // Bounded by the number of distinct loadable files ever seen in a folder,
  // which is a handful; it is never a cache of arbitrary input.
  static std::mutex mutex;
  static std::map<fs::path, CachedDigest> cache;

  if (reuse == DigestReuse::ReuseUnchanged && stampable) {
    std::lock_guard<std::mutex> lock(mutex);
    if (const auto it = cache.find(path);
        it != cache.end() && it->second.size == size && it->second.stamp == stamp) {
      return it->second.sha256;
    }
  }

  std::string sha256 = Sha256File(path);
  if (stampable && !sha256.empty()) {
    std::lock_guard<std::mutex> lock(mutex);
    if (cache.size() > 64) cache.clear();
    cache[path] = CachedDigest{size, stamp, sha256};
  }
  return sha256;
}

void Check(const fs::path& path, const std::string& shownAs, DigestReuse reuse,
           std::vector<ComponentProblem>& problems) {
  const std::string name = Lower(Utf8FromPath(path.filename()));

  const bool nameKnown =
      name == kNeuralRuntime ||
      std::any_of(kKnownBuilds.begin(), kKnownBuilds.end(),
                  [&](const KnownBuild& build) { return name == build.fileName; });
  if (!nameKnown) {
    problems.push_back({shownAs, "is not a file this project ships, and the folder it is in "
                                 "is one the overlay loads code from.", {}});
    return;
  }

  const std::string sha256 = Digest(path, reuse);
  if (sha256.empty()) {
    problems.push_back({shownAs, "could not be read, so it could not be checked.", {}});
    return;
  }
  if (!IsKnownComponent(name, sha256)) {
    problems.push_back({shownAs, "is not a build this project knows.", sha256});
  }
}

}  // namespace

bool IsKnownComponent(std::string_view fileName, std::string_view sha256Hex) {
  const std::string name = Lower(fileName);
  const std::string digest = Lower(sha256Hex);
  if (name == kNeuralRuntime) return LookupRuntime(digest).has_value();
  return std::any_of(kKnownBuilds.begin(), kKnownBuilds.end(), [&](const KnownBuild& build) {
    return name == build.fileName && digest == build.sha256;
  });
}

std::string ComponentDigest(const fs::path& path, DigestReuse reuse) {
  return Digest(path, reuse);
}

std::vector<ComponentProblem> VerifyComponents(const fs::path& folder, DigestReuse reuse,
                                               ComponentScope scope) {
  std::vector<ComponentProblem> problems;

  const auto scan = [&](const fs::path& dir, const std::string& prefix, bool runtimeSlot) {
    std::error_code ec;
    if (!fs::is_directory(dir, ec) || ec) return;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
      if (ec) break;
      std::error_code typeEc;
      if (!entry.is_regular_file(typeEc) || typeEc) continue;
      if (!IsLoadable(entry.path())) continue;
      const std::string shownAs = prefix + Utf8FromPath(entry.path().filename());
      // A slot holds the neural runtime and nothing else; the overlay copies it
      // out and the NGX path list never points into the slot itself.
      if (runtimeSlot && Lower(Utf8FromPath(entry.path().filename())) != kNeuralRuntime) {
        problems.push_back({shownAs, "does not belong in a runtime slot.", {}});
        continue;
      }
      Check(entry.path(), shownAs, reuse, problems);
    }
  };

  scan(folder, "", false);
  if (scope == ComponentScope::LoadedAtLaunch) return problems;
  for (const char* slot : {"latest", "compatible"}) {
    scan(folder / "runtimes" / slot, std::string("runtimes\\") + slot + "\\", true);
  }
  return problems;
}

}  // namespace sidecar
