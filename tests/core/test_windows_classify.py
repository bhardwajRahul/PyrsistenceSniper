"""Tests for LOLBin, built-in, and OS directory classification of executables."""

from __future__ import annotations

from pyrsistencesniper.core.windows import (
    extract_launcher_from_cmdline,
    is_builtin,
    is_in_os_directory,
    is_lolbin,
)


def test_is_lolbin_mshta() -> None:
    """A signed Microsoft binary is still flagged when it can run arbitrary code."""
    assert is_lolbin("C:\\Windows\\System32\\mshta.exe") is True


def test_is_lolbin_certutil() -> None:
    """certutil ships with Windows yet downloads and decodes payloads, so it counts."""
    assert is_lolbin("C:\\Windows\\System32\\certutil.exe") is True


def test_is_lolbin_notepad_is_not() -> None:
    """An ordinary System32 binary stays unflagged, so the list keeps its signal."""
    assert is_lolbin("C:\\Windows\\System32\\notepad.exe") is False


def test_is_lolbin_case_insensitive() -> None:
    """Registry values are written in any casing, so matching cannot depend on it."""
    assert is_lolbin("C:\\Windows\\System32\\MSHTA.EXE") is True


def test_is_builtin_explorer() -> None:
    """explorer.exe is the expected Winlogon shell, so it must read as a built-in."""
    assert is_builtin("C:\\Windows\\explorer.exe") is True


def test_is_builtin_svchost() -> None:
    """svchost.exe hosts most services, so the genuine name must read as built-in."""
    assert is_builtin("C:\\Windows\\System32\\svchost.exe") is True


def test_is_builtin_random_exe() -> None:
    """An unlisted executable gets no built-in standing, so the flag stays useful."""
    assert is_builtin("C:\\Tools\\malware.exe") is False


def test_is_builtin_case_insensitive() -> None:
    """A bare name in mixed case still matches; casing carries no meaning on NTFS."""
    assert is_builtin("Explorer.EXE") is True


def test_is_in_os_directory_direct_child() -> None:
    """System32 itself counts as an OS directory, the baseline the rest builds on."""
    assert is_in_os_directory("C:\\Windows\\System32\\svchost.exe") is True


def test_is_in_os_directory_subdirectory() -> None:
    """Drivers live one level down, so the check cannot be an exact directory match."""
    assert is_in_os_directory("C:\\Windows\\System32\\drivers\\srv.sys") is True


def test_is_in_os_directory_deep_subdirectory() -> None:
    """Depth is unbounded: wbem sits well below System32 and still counts."""
    assert is_in_os_directory("C:\\Windows\\System32\\wbem\\wmiprvse.exe") is True


def test_is_in_os_directory_windows_temp_not_matched() -> None:
    """Windows\\Temp is writable by anyone, so it must not inherit System32's trust."""
    assert is_in_os_directory("C:\\Windows\\Temp\\evil.exe") is False


def test_is_in_os_directory_program_files_not_matched() -> None:
    """Program Files is vendor territory; only System32 and SysWOW64 count as OS."""
    assert is_in_os_directory("C:\\Program Files\\Vendor\\app.exe") is False


def test_is_in_os_directory_user_path_not_matched() -> None:
    """A user profile path never counts as OS, whatever binary it holds."""
    assert is_in_os_directory("C:\\Users\\test\\malware.exe") is False


def test_is_in_os_directory_systemroot_prefix() -> None:
    """Driver ImagePath values use the \\SystemRoot form and must still match."""
    assert is_in_os_directory("\\SystemRoot\\System32\\drivers\\srv.sys") is True


def test_is_in_os_directory_bare_system32() -> None:
    """A path starting at System32 with no Windows prefix is still an OS path."""
    assert is_in_os_directory("System32\\svchost.exe") is True


def test_is_lolbin_includes_powershell() -> None:
    """LOLBAS omits the shells by design, but a payload run through one still counts."""
    assert (
        is_lolbin(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") is True
    )


def test_is_lolbin_includes_pwsh() -> None:
    """PowerShell 7 ships under its own name and is the same launcher."""
    assert is_lolbin(r"C:\Program Files\PowerShell\7\pwsh.exe") is True


def test_launcher_reported_for_proxied_payload() -> None:
    """rundll32 running a DLL is the technique, so the launcher must be recoverable."""
    launcher = extract_launcher_from_cmdline(
        r"rundll32.exe C:\Users\Public\evil.dll,Start"
    )
    assert launcher == "rundll32.exe"


def test_launcher_reported_for_powershell_payload() -> None:
    """A hidden PowerShell one-liner is the commonest launcher form in the wild."""
    launcher = extract_launcher_from_cmdline(
        r"powershell.exe -w hidden -File C:\Users\Public\evil.ps1"
    )
    assert launcher == "powershell.exe"


def test_bare_lolbin_reports_no_launcher() -> None:
    """A LOLBin with no payload is the executable itself, not its own launcher."""
    assert extract_launcher_from_cmdline("mshta.exe") == ""


def test_ordinary_binary_reports_no_launcher() -> None:
    """An ordinary program with arguments must not be described as proxying."""
    assert extract_launcher_from_cmdline(r"C:\Program Files\App\app.exe --flag") == ""
