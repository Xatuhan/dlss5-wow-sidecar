#pragma once
#include <filesystem>
#include <string_view>

namespace sidecar {

// Replaces a file's contents so that a reader -- or the next launch after a
// crash -- sees either the old file or the new one, never half of each.
//
// Truncating in place and writing does not have that property: a crash, a full
// disk or a power cut between the truncate and the last write leaves an empty
// or clipped sidecar.toml, and every setting the operator chose is gone. So the
// bytes go to a sibling file first, are flushed to disk, and only then are moved
// over the original in one MoveFileExW.
//
// The sibling sits in the same directory on purpose: a rename is only atomic
// within one volume, and %TEMP% is not guaranteed to be on the same one.
bool WriteFileAtomically(const std::filesystem::path& path, std::string_view bytes);

}  // namespace sidecar
