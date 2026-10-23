#include <catch2/catch_test_macros.hpp>

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include "core/AtomicFile.h"
#include "core/Config.h"
#include "core/ControlChannel.h"
#include "core/Sha256.h"
#include "neural/AddonSettings.h"
#include "neural/ComponentManifest.h"

using namespace sidecar;
namespace fs = std::filesystem;

namespace {

fs::path ScratchDir(const char* name) {
  auto dir = fs::temp_directory_path() / "sidecar_hardening_tests" / name;
  fs::remove_all(dir);
  fs::create_directories(dir);
  return dir;
}

void Write(const fs::path& path, std::string_view contents) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << contents;
}

std::string Read(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

bool Mentions(const std::vector<ComponentProblem>& problems, const std::string& file) {
  for (const auto& p : problems) {
    if (p.file == file) return true;
  }
  return false;
}

}  // namespace

// --- Component allow-list -------------------------------------------------
//
// What these prove that running the app cannot: that a planted file is caught
// for every way it can be planted, including the ones nobody would think to
// try by hand.

TEST_CASE("an empty sidecar folder has nothing to object to", "[unit]") {
  const auto dir = ScratchDir("empty");
  CHECK(VerifyComponents(dir).empty());
  fs::remove_all(dir);
}

TEST_CASE("files that are not loadable are not the allow-list's business", "[unit]") {
  const auto dir = ScratchDir("inert");
  Write(dir / "sidecar.toml", "theme = \"stormwind\"");
  Write(dir / "README.md", "#");
  Write(dir / "ReShade.ini", "[ADDON]");
  CHECK(VerifyComponents(dir).empty());
  fs::remove_all(dir);
}

TEST_CASE("a DLL named after one of the executables' imports is refused", "[unit]") {
  // version.dll and d3d12.dll are not KnownDLLs, so Windows looks beside the
  // executable first: this is the classic way to get code into a program.
  const auto dir = ScratchDir("planted");
  Write(dir / "version.dll", "MZ");
  Write(dir / "d3d12.dll", "MZ");
  const auto problems = VerifyComponents(dir);
  CHECK(Mentions(problems, "version.dll"));
  CHECK(Mentions(problems, "d3d12.dll"));
  fs::remove_all(dir);
}

TEST_CASE("an unknown ReShade add-on is refused, under either extension", "[unit]") {
  const auto dir = ScratchDir("addon");
  Write(dir / "extra.addon64", "MZ");
  Write(dir / "extra.addon", "MZ");
  const auto problems = VerifyComponents(dir);
  CHECK(Mentions(problems, "extra.addon64"));
  CHECK(Mentions(problems, "extra.addon"));
  fs::remove_all(dir);
}

TEST_CASE("a shipped file name with the wrong contents is refused, with its digest",
          "[unit]") {
  const auto dir = ScratchDir("swapped");
  Write(dir / "dxgi.dll", "not ReShade");
  Write(dir / "renodx-dlss5.addon64", "not the add-on");
  const auto problems = VerifyComponents(dir);
  REQUIRE(problems.size() == 2);
  for (const auto& p : problems) {
    CHECK(p.sha256.size() == 64);
  }
  CHECK(problems[0].sha256 == Sha256Hex(problems[0].file == "dxgi.dll"
                                            ? std::string("not ReShade")
                                            : std::string("not the add-on")));
  fs::remove_all(dir);
}

TEST_CASE("names are compared the way Windows compares them", "[unit]") {
  const auto dir = ScratchDir("case");
  Write(dir / "DXGI.DLL", "not ReShade");
  CHECK(Mentions(VerifyComponents(dir), "DXGI.DLL"));
  fs::remove_all(dir);
}

TEST_CASE("a runtime slot holds the neural runtime and nothing else", "[unit]") {
  const auto dir = ScratchDir("slot");
  fs::create_directories(dir / "runtimes" / "latest");
  Write(dir / "runtimes" / "latest" / "dxgi.dll", "MZ");
  Write(dir / "runtimes" / "latest" / "nvngx_dlssnr.dll", "not a runtime");
  const auto problems = VerifyComponents(dir);
  CHECK(Mentions(problems, "runtimes\\latest\\dxgi.dll"));
  CHECK(Mentions(problems, "runtimes\\latest\\nvngx_dlssnr.dll"));
  fs::remove_all(dir);
}

TEST_CASE("the shipped builds are known by name and digest together", "[unit]") {
  constexpr const char* kReshade =
      "0cee63f9c9f13f3ac909c5b4903f4dbb4b719a7ab3b4f13b0deaf83c814b94f7";
  CHECK(IsKnownComponent("dxgi.dll", kReshade));
  CHECK(IsKnownComponent("DXGI.dll", "0CEE63F9C9F13F3AC909C5B4903F4DBB4B719A7AB3B4F13B0DEAF83C814B94F7"));
  // The right digest under the wrong name is still not a shipped file.
  CHECK_FALSE(IsKnownComponent("version.dll", kReshade));
  // The neural runtime defers to RuntimeManifest: the stock 310.9.16 build.
  CHECK(IsKnownComponent("nvngx_dlssnr.dll",
                         "2bc19bc09a7b89dd44f73e2ac0108fcc586e2154bdd0830f242f4f040e28789f"));
  CHECK_FALSE(IsKnownComponent("nvngx_dlssnr.dll", std::string(64, 'c')));
}

TEST_CASE("a reused digest is dropped when the file changes", "[unit]") {
  const auto dir = ScratchDir("reuse");
  Write(dir / "dxgi.dll", "first");
  const auto before = VerifyComponents(dir, DigestReuse::ReuseUnchanged);
  REQUIRE(before.size() == 1);
  Write(dir / "dxgi.dll", "second, and longer");
  const auto after = VerifyComponents(dir, DigestReuse::ReuseUnchanged);
  REQUIRE(after.size() == 1);
  CHECK(after[0].sha256 == Sha256Hex("second, and longer"));
  fs::remove_all(dir);
}

// --- Atomic saves ----------------------------------------------------------

TEST_CASE("an atomic write replaces the file and leaves nothing beside it", "[unit]") {
  const auto dir = ScratchDir("atomic");
  const auto path = dir / "sidecar.toml";
  Write(path, "old contents that are longer than the new ones");
  REQUIRE(WriteFileAtomically(path, "new"));
  CHECK(Read(path) == "new");
  CHECK_FALSE(fs::exists(dir / "sidecar.toml.saving"));
  fs::remove_all(dir);
}

TEST_CASE("an atomic write into a missing folder fails without side effects", "[unit]") {
  const auto dir = ScratchDir("atomic-missing");
  CHECK_FALSE(WriteFileAtomically(dir / "nowhere" / "sidecar.toml", "x"));
  CHECK_FALSE(fs::exists(dir / "nowhere"));
  fs::remove_all(dir);
}

// --- Config escaping and bounds -------------------------------------------

TEST_CASE("a string setting cannot break out of its TOML value", "[unit]") {
  // Before the fix these two were written between bare quotes, so a value
  // holding a quote and a newline injected a key of its own into the file.
  Config config;
  config.neuralPass = "reshade\"\nwow_dir = \"C:\\\\evil";
  config.dlssPreset = "cnn-f\"";
  std::vector<std::string> warnings;
  const auto reread = ParseConfig(SerializeConfig(config), warnings);
  CHECK(reread.neuralPass == config.neuralPass);
  CHECK(reread.dlssPreset == config.dlssPreset);
  CHECK(reread.wowDir.empty());
}

TEST_CASE("the UI mask is capped, with a warning", "[unit]") {
  std::string toml;
  for (int i = 0; i < 100; ++i) {
    toml += "[[ui_mask]]\nleft = 0\ntop = 0\nright = 10\nbottom = 10\n";
  }
  std::vector<std::string> warnings;
  const auto config = ParseConfig(toml, warnings);
  CHECK(config.uiMaskRects.size() == 64);
  CHECK_FALSE(warnings.empty());
}

TEST_CASE("a mask edge outside int32 is clamped, not wrapped", "[unit]") {
  std::vector<std::string> warnings;
  const auto config = ParseConfig(
      "[[ui_mask]]\nleft = -9999999999\ntop = 0\nright = 9999999999\nbottom = 10\n",
      warnings);
  REQUIRE(config.uiMaskRects.size() == 1);
  CHECK(config.uiMaskRects[0].left == -(1 << 20));
  CHECK(config.uiMaskRects[0].right == (1 << 20));
}

TEST_CASE("an oversized config file is refused before it is read", "[unit]") {
  const auto dir = ScratchDir("big-config");
  const auto path = dir / "sidecar.toml";
  Write(path, std::string(2 * 1024 * 1024, '#'));
  std::vector<std::string> warnings;
  CHECK_FALSE(LoadConfig(path, warnings).has_value());
  CHECK_FALSE(warnings.empty());
  fs::remove_all(dir);
}

// --- ReShade.ini ------------------------------------------------------------

TEST_CASE("ReShade's post-screenshot command is pinned empty", "[unit]") {
  const std::string planted =
      "[SCREENSHOT]\r\n"
      "PostSaveCommand=C:\\Users\\Public\\payload.bat\r\n"
      "PostSaveCommandArguments=-x\r\n"
      "JPEGQuality=90\r\n";
  const std::string after = ApplyNeuralSettings(planted, NeuralSettings{});
  CHECK(after.find("payload.bat") == std::string::npos);
  CHECK(after.find("PostSaveCommand=\r\n") != std::string::npos);
  CHECK(after.find("PostSaveCommandArguments=\r\n") != std::string::npos);
  // Everything else in the section is ReShade's, and stays.
  CHECK(after.find("JPEGQuality=90") != std::string::npos);
}

TEST_CASE("a fresh ReShade.ini gains the empty post-screenshot command", "[unit]") {
  const std::string ini = ApplyNeuralSettings("", NeuralSettings{});
  CHECK(ini.find("[SCREENSHOT]") != std::string::npos);
  CHECK(ini.find("PostSaveCommand=") != std::string::npos);
}

// --- Control channel ----------------------------------------------------------

TEST_CASE("the manager reads status the overlay published", "[unit]") {
  auto server = ControlServer::Create([](SidecarCommand) {});
  REQUIRE(server);
  SidecarStatus status;
  status.frames = 1234;
  server->Publish(status);
  const auto read = control::Read();
  REQUIRE(read.has_value());
  CHECK(read->frames == 1234);
  CHECK(read->processId == GetCurrentProcessId());
}

TEST_CASE("a status mapping squatted before the overlay starts is not trusted", "[unit]") {
  // Something else creates the name first. The overlay must not publish into a
  // section another process holds, and the manager must not believe it.
  HANDLE squatter = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                       sizeof(SidecarStatus), L"Local\\DLSS5SidecarStatus");
  REQUIRE(squatter);
  {
    auto server = ControlServer::Create([](SidecarCommand) {});
    REQUIRE(server);
    SidecarStatus status;
    status.frames = 99;
    server->Publish(status);
    CHECK_FALSE(control::Read().has_value());
  }
  CloseHandle(squatter);
}
