#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace sidecar {

// The sidecar's folder is the one place third-party native code runs from:
// ReShade arrives as dxgi.dll, which wowsidecar.exe loads at start-up because it
// imports DXGI; ReShade then loads every add-on it finds there, and the add-on
// maps the NGX runtimes. None of them is built here, and all of them run inside
// the sidecar with the user's rights.
//
// So the folder is held to an allow-list. A loadable file -- a .dll, .addon64
// or .addon -- is accepted only when its name is one this project ships and its
// SHA-256 is a build it has seen. Anything else is reported, and the overlay
// refuses to start: an unknown add-on, a swapped dxgi.dll, or a DLL named after
// one of the executables' own imports (d3d12.dll, version.dll, ...) planted to
// be picked up ahead of the system copy.
//
// None of this reaches Wow.exe. It reads files in the sidecar's own folder and
// nothing else.

struct ComponentProblem {
  std::string file;     // relative to the folder checked
  std::string reason;   // one sentence, English; callers translate the template
  std::string sha256;   // empty when the file could not be read
};

// Whether a name+digest pair is a build this project knows. Exposed for the
// manager's installer, which checks a file before copying it in.
bool IsKnownComponent(std::string_view fileName, std::string_view sha256Hex);

// Every loadable file in `folder` and in its runtimes\latest and
// runtimes\compatible slots, checked against the allow-list. Empty means the
// folder holds nothing it should not.
//
// Hashing is the cost: the runtimes are 160 and 266 MB. With `reuseDigests` a
// digest is reused while the file's size and write time are unchanged, which is
// what lets the manager's Checks page run this on its own thread of control
// without a half-second stall each time. Both are under the control of whoever
// can write the file, so the last check before anything is launched passes
// false and hashes every byte.
enum class DigestReuse { Fresh, ReuseUnchanged };
std::vector<ComponentProblem> VerifyComponents(const std::filesystem::path& folder,
                                               DigestReuse reuse = DigestReuse::Fresh);

}  // namespace sidecar
