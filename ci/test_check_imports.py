import pytest
from check_imports import forbidden_imports

def test_flags_process_memory_access():
    found = forbidden_imports({"KERNEL32.dll!ReadProcessMemory", "KERNEL32.dll!CreateFileW"})
    assert found == ["KERNEL32.dll!ReadProcessMemory"]

def test_flags_remote_thread_and_alloc():
    found = forbidden_imports({
        "KERNEL32.dll!CreateRemoteThread",
        "KERNEL32.dll!VirtualAllocEx",
        "KERNEL32.dll!VirtualProtectEx",
    })
    assert sorted(found) == [
        "KERNEL32.dll!CreateRemoteThread",
        "KERNEL32.dll!VirtualAllocEx",
        "KERNEL32.dll!VirtualProtectEx",
    ]

def test_flags_windows_hook():
    assert forbidden_imports({"USER32.dll!SetWindowsHookExW"}) == ["USER32.dll!SetWindowsHookExW"]

def test_flags_synthetic_input_per_i6():
    found = forbidden_imports({"USER32.dll!SendInput", "USER32.dll!mouse_event"})
    assert sorted(found) == ["USER32.dll!SendInput", "USER32.dll!mouse_event"]

def test_flags_networking_per_i10():
    found = forbidden_imports({"WS2_32.dll!socket", "WINHTTP.dll!WinHttpOpen"})
    assert sorted(found) == ["WINHTTP.dll!WinHttpOpen", "WS2_32.dll!socket"]

def test_elevation_check_rejects_admin_manifest(tmp_path):
    from check_imports import check_no_elevation_manifest
    fake = tmp_path / "fake.exe"
    fake.write_bytes(b"MZ...<requestedExecutionLevel level='requireAdministrator'/>")
    assert check_no_elevation_manifest(str(fake)) is False


def test_elevation_check_accepts_plain_manifest(tmp_path):
    from check_imports import check_no_elevation_manifest
    fake = tmp_path / "fake.exe"
    fake.write_bytes(b"MZ...<requestedExecutionLevel level='asInvoker'/>")
    assert check_no_elevation_manifest(str(fake)) is True


def test_allows_legitimate_imports():
    assert forbidden_imports({
        "USER32.dll!SetWinEventHook",
        "USER32.dll!GetWindowLongW",
        "d3d12.dll!D3D12CreateDevice",
        "dcomp.dll!DCompositionCreateDevice",
    }) == []


def test_flags_any_handle_to_another_process():
    found = forbidden_imports({
        "KERNEL32.dll!OpenProcess",
        "KERNEL32.dll!OpenThread",
        "ntdll.dll!NtReadVirtualMemory",
        "KERNEL32.dll!GetProcessId",
    })
    assert found == [
        "KERNEL32.dll!OpenProcess",
        "KERNEL32.dll!OpenThread",
        "ntdll.dll!NtReadVirtualMemory",
    ]


def test_mitigations_all_present():
    from check_imports import missing_mitigations
    assert missing_mitigations(0x0020 | 0x0040 | 0x0100 | 0x4000 | 0x8000) == []


def test_mitigations_reports_missing_cfg():
    from check_imports import missing_mitigations
    # What the 0.6.0 executables actually carried.
    assert missing_mitigations(0x0020 | 0x0040 | 0x0100 | 0x8000) == ["GUARD_CF"]
