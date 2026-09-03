"""Tests for Windows path normalization and environment variable expansion."""

from __future__ import annotations

from pyrsistencesniper.core.windows import (
    canonicalize_windows_path,
    expand_env_vars,
    normalize_windows_path,
)


def test_expand_windir() -> None:
    """%windir% expands from the static table, not the host's own environment."""
    result = expand_env_vars("%windir%\\system32\\cmd.exe")
    assert result == "Windows\\system32\\cmd.exe"


def test_expand_systemroot() -> None:
    """%SystemRoot% and %windir% name the same directory and must expand alike."""
    assert expand_env_vars("%SystemRoot%\\notepad.exe") == "Windows\\notepad.exe"


def test_expand_programfiles() -> None:
    """Expansion yields an image-relative path, with no drive letter to strip later."""
    result = expand_env_vars("%ProgramFiles%\\app\\app.exe")
    assert result == "Program Files\\app\\app.exe"


def test_expand_userprofile_with_username() -> None:
    """A per-user hive is scanned as its owner, so the profile path takes that name."""
    result = expand_env_vars("%USERPROFILE%\\Desktop", username="Alice")
    assert result == "Users\\Alice\\Desktop"


def test_expand_userprofile_default_when_no_username() -> None:
    """No known owner gives a placeholder profile rather than an unexpanded variable."""
    result = expand_env_vars("%USERPROFILE%\\Desktop")
    assert result == "Users\\DEFAULT\\Desktop"


def test_expand_localappdata_with_username() -> None:
    """%LOCALAPPDATA% expands to the full AppData branch, not just the profile root."""
    result = expand_env_vars("%LOCALAPPDATA%\\Microsoft", username="hx")
    assert result == "Users\\hx\\AppData\\Local\\Microsoft"


def test_expand_unknown_var_left_as_is() -> None:
    """An unrecognized variable is left verbatim so the raw value stays reviewable."""
    result = expand_env_vars("%UNKNOWN_VAR%\\foo")
    assert result == "%UNKNOWN_VAR%\\foo"


def test_expand_multiple_vars() -> None:
    """Every occurrence is substituted, not just the first."""
    result = expand_env_vars("%windir%\\%windir%")
    assert result == "Windows\\Windows"


def test_normalize_forward_slashes() -> None:
    """Forward slashes are legal in Windows paths but break naive string comparison."""
    assert normalize_windows_path("C:/Windows/System32") == "C:\\Windows\\System32"


def test_normalize_mixed_slashes() -> None:
    """A path mixing both separators normalizes whole, not just its first segment."""
    result = normalize_windows_path("C:\\Windows/System32\\cmd.exe")
    assert result == "C:\\Windows\\System32\\cmd.exe"


def test_normalize_preserves_clean_path() -> None:
    """Normalizing is idempotent, so a path may pass through it more than once."""
    assert normalize_windows_path("C:\\Windows\\System32") == "C:\\Windows\\System32"


def test_canonicalize_windows_path_drive_c() -> None:
    """The drive letter goes so the rest can be joined to the mounted image root."""
    assert canonicalize_windows_path("C:\\Windows\\System32") == "Windows\\System32"


def test_canonicalize_windows_path_drive_d() -> None:
    """Any drive letter is stripped, since the image may not have been mounted as C."""
    assert canonicalize_windows_path("D:\\Tools\\app.exe") == "Tools\\app.exe"


def test_canonicalize_windows_path_forward_slash() -> None:
    """Separators are fixed inside canonicalization, so callers need no pre-pass."""
    assert canonicalize_windows_path("C:/Windows/System32") == "Windows\\System32"


def test_canonicalize_windows_path_mixed_slash() -> None:
    """A half-converted path would resolve to nothing on the mounted image."""
    result = canonicalize_windows_path("C:\\Windows/System32\\cmd.exe")
    assert result == "Windows\\System32\\cmd.exe"


def test_canonicalize_windows_path_no_drive() -> None:
    """A value that is already image-relative must not be mangled a second time."""
    result = canonicalize_windows_path("Windows\\System32\\cmd.exe")
    assert result == "Windows\\System32\\cmd.exe"


def test_canonicalize_windows_path_leading_backslash() -> None:
    """The result is root-relative, so joining it never escapes the image root."""
    assert canonicalize_windows_path("\\Windows\\System32") == "Windows\\System32"


def test_canonicalize_windows_path_double_quotes() -> None:
    """Registry values often ship quoted; the quotes are not part of the path."""
    assert canonicalize_windows_path('"C:\\Windows\\System32"') == "Windows\\System32"


def test_canonicalize_windows_path_single_quotes() -> None:
    """Script-written values quote with apostrophes, which strip the same way."""
    assert canonicalize_windows_path("'C:\\Windows\\System32'") == "Windows\\System32"


def test_canonicalize_windows_path_device_unc_question() -> None:
    """The long-path prefix is an addressing detail, not part of the location."""
    result = canonicalize_windows_path("\\\\?\\C:\\Windows\\System32")
    assert result == "Windows\\System32"


def test_canonicalize_windows_path_device_dos() -> None:
    """Driver ImagePath values carry the NT object form and must still resolve."""
    result = canonicalize_windows_path("\\??\\C:\\Windows\\System32")
    assert result == "Windows\\System32"


def test_canonicalize_windows_path_device_dot() -> None:
    """The device namespace spelling reaches the same file as the drive spelling."""
    result = canonicalize_windows_path("\\\\.\\C:\\Windows\\System32")
    assert result == "Windows\\System32"


def test_canonicalize_windows_path_unc_named() -> None:
    """A remote share is not on the image, so it canonicalizes to nothing."""
    assert canonicalize_windows_path("\\\\server\\share\\file.txt") == ""


def test_canonicalize_windows_path_unc_ip() -> None:
    """A share addressed by IP is still remote, not a drive-letter path to strip."""
    assert canonicalize_windows_path("\\\\192.168.1.1\\c$\\Windows") == ""


def test_canonicalize_windows_path_empty() -> None:
    """An empty value is an absence, not a path to hunt for on the image."""
    assert canonicalize_windows_path("") == ""


def test_canonicalize_windows_path_whitespace() -> None:
    """A value of only spaces is empty too, so no lookup is attempted for it."""
    assert canonicalize_windows_path("   ") == ""


def test_canonicalize_windows_path_bare_filename() -> None:
    """A bare name gains no invented directory; where it lives is decided elsewhere."""
    assert canonicalize_windows_path("cmd.exe") == "cmd.exe"


def test_canonicalize_windows_path_systemroot_prefix() -> None:
    """The SystemRoot prefix is how a driver ImagePath spells the Windows directory."""
    result = canonicalize_windows_path("\\SystemRoot\\System32\\drivers\\srv.sys")
    assert result == "Windows\\System32\\drivers\\srv.sys"


def test_canonicalize_windows_path_systemroot_case_insensitive() -> None:
    """The registry stores the prefix in any case, so matching cannot be exact."""
    result = canonicalize_windows_path("\\SYSTEMROOT\\System32\\cmd.exe")
    assert result == "Windows\\System32\\cmd.exe"


def test_canonicalize_windows_path_bare_system32() -> None:
    """A relative System32 path is anchored under Windows, where the loader looks."""
    result = canonicalize_windows_path("System32\\svchost.exe")
    assert result == "Windows\\System32\\svchost.exe"


def test_canonicalize_windows_path_bare_syswow64() -> None:
    """SysWOW64 is anchored the same way, so 32-bit entries resolve too."""
    result = canonicalize_windows_path("SysWOW64\\ntdll.dll")
    assert result == "Windows\\SysWOW64\\ntdll.dll"


def test_canonicalize_windows_path_system32_with_leading_backslash() -> None:
    """A leading separator does not hide the System32 prefix from the anchor step."""
    result = canonicalize_windows_path("\\System32\\svchost.exe")
    assert result == "Windows\\System32\\svchost.exe"
