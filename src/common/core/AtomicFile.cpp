#include "core/AtomicFile.h"

#include <windows.h>

#include <limits>

namespace sidecar {

bool WriteFileAtomically(const std::filesystem::path& path, std::string_view bytes) {
  if (bytes.size() > std::numeric_limits<DWORD>::max()) return false;

  std::filesystem::path staging = path;
  staging += L".saving";

  // CREATE_ALWAYS over a stale sibling left by an earlier crash, and no sharing:
  // nothing else has any business reading a file that is half written.
  HANDLE file = CreateFileW(staging.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;

  DWORD written = 0;
  const bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written,
                            nullptr) != 0 &&
                  written == bytes.size() && FlushFileBuffers(file) != 0;
  CloseHandle(file);

  if (!ok || !MoveFileExW(staging.c_str(), path.c_str(),
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(staging.c_str());
    return false;
  }
  return true;
}

}  // namespace sidecar
