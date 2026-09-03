"""Tests for extracting the executable target out of a Windows command line."""

from __future__ import annotations

from pyrsistencesniper.core.windows import extract_executable_from_cmdline


def test_extract_simple_exe() -> None:
    """A bare program name is already the target and passes through unchanged."""
    assert extract_executable_from_cmdline("notepad.exe") == "notepad.exe"


def test_extract_path_with_args() -> None:
    """Arguments are dropped so what remains is a path the resolver can look up."""
    result = extract_executable_from_cmdline("C:\\app.exe --verbose")
    assert result == "C:\\app.exe"


def test_extract_empty() -> None:
    """An absent command line yields an empty target rather than an error."""
    assert extract_executable_from_cmdline("") == ""


def test_extract_whitespace_only() -> None:
    """A registry value holding only padding is as empty as one holding nothing."""
    assert extract_executable_from_cmdline("   ") == ""


def test_extract_quoted_path_with_spaces_keeps_full_path() -> None:
    """A quoted program path containing spaces must survive tokenization intact."""
    result = extract_executable_from_cmdline('"C:\\Program Files\\app.exe" --flag')
    assert result == "C:\\Program Files\\app.exe"


def test_extract_unquoted_path_with_spaces() -> None:
    """CreateProcess runs to the executable extension, not to the first space."""
    result = extract_executable_from_cmdline("C:\\Program Files\\evil\\evil.exe --run")
    assert result == "C:\\Program Files\\evil\\evil.exe"


def test_extract_unquoted_path_with_spaces_no_args() -> None:
    """An unquoted spaced path without arguments resolves to the full path."""
    result = extract_executable_from_cmdline(
        "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"
    )
    assert (
        result == "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"
    )


def test_extract_unquoted_spaced_path_without_extension_keeps_first_token() -> None:
    """Without an executable extension there is no join boundary to trust."""
    result = extract_executable_from_cmdline("C:\\Program Files\\evil --run")
    assert result == "C:\\Program"


def test_extract_quoted_path_without_args() -> None:
    """The closing quote ends the path even with no arguments after it."""
    result = extract_executable_from_cmdline('"C:\\Program Files\\app.exe"')
    assert result == "C:\\Program Files\\app.exe"


def test_extract_cmd_c() -> None:
    """cmd is the launcher, so the batch file it runs is the target of interest."""
    result = extract_executable_from_cmdline("cmd.exe /c script.bat")
    assert result == "script.bat"


def test_extract_cmd_k() -> None:
    """/k keeps the console open but selects the program the same way /c does."""
    assert extract_executable_from_cmdline("cmd.exe /k netstat.exe") == "netstat.exe"


def test_extract_rundll32() -> None:
    """The DLL before the comma is the file on disk; the export name is not."""
    result = extract_executable_from_cmdline("rundll32.exe shell32.dll,Control_RunDLL")
    assert result == "shell32.dll"


def test_extract_rundll32_full_path() -> None:
    """A fully qualified rundll32 is still recognized, so its DLL argument wins."""
    result = extract_executable_from_cmdline(
        "C:\\Windows\\System32\\rundll32.exe advpack.dll,LaunchINFSection"
    )
    assert result == "advpack.dll"


def test_extract_powershell_file_flag() -> None:
    """The script named by -File is the payload, not powershell.exe itself."""
    result = extract_executable_from_cmdline("powershell.exe -File script.ps1")
    assert result == "script.ps1"


def test_extract_powershell_skips_execution_policy_value() -> None:
    """The value consumed by -ExecutionPolicy must not be taken as the target."""
    cmdline = "powershell.exe -ExecutionPolicy Bypass script.ps1"
    assert extract_executable_from_cmdline(cmdline) == "script.ps1"


def test_extract_powershell_skips_window_style_value() -> None:
    """Hidden is a value bound to -WindowStyle, not a script name to report."""
    cmdline = "powershell.exe -WindowStyle Hidden -File payload.ps1"
    assert extract_executable_from_cmdline(cmdline) == "payload.ps1"


def test_extract_powershell_switch_flags_only_returns_interpreter() -> None:
    """With no script argument the interpreter itself is the only target left."""
    result = extract_executable_from_cmdline(
        "powershell.exe -NoProfile -NonInteractive"
    )
    assert result == "powershell.exe"


def test_extract_powershell_command_flag_returns_command() -> None:
    """An inline -Command has no file on disk, so its first token stands in."""
    result = extract_executable_from_cmdline("powershell.exe -Command Get-Process")
    assert result == "Get-Process"


def test_extract_wscript() -> None:
    """A script host takes its script as a bare argument, with no flag to key on."""
    result = extract_executable_from_cmdline("wscript.exe C:\\scripts\\evil.vbs")
    assert result == "C:\\scripts\\evil.vbs"


def test_extract_cscript_skips_double_slash_flag() -> None:
    """Script host flags use a // prefix and must not be taken as the target."""
    result = extract_executable_from_cmdline("cscript.exe //nologo script.js")
    assert result == "script.js"


def test_extract_mshta() -> None:
    """An inline vbscript: URI is reported as-is; there is no file to name."""
    result = extract_executable_from_cmdline("mshta.exe vbscript:Execute(code)")
    assert result == "vbscript:Execute(code)"


def test_extract_script_host_ignores_argument_placeholder() -> None:
    """A registered handler's %1 placeholder is not a target, so the host wins."""
    cmdline = r'"%SystemRoot%\System32\WScript.exe" "%1" %*'
    assert extract_executable_from_cmdline(cmdline) == (
        r"%SystemRoot%\System32\WScript.exe"
    )


def test_extract_mshta_handler_ignores_argument_placeholder() -> None:
    """An mshta file association resolves to mshta itself, not to %1."""
    cmdline = r'"C:\Windows\System32\mshta.exe" "%1" %*'
    assert extract_executable_from_cmdline(cmdline) == r"C:\Windows\System32\mshta.exe"


def test_extract_powershell_ignores_argument_placeholder() -> None:
    """A PowerShell handler taking -File %1 resolves to the interpreter."""
    result = extract_executable_from_cmdline("powershell.exe -File %1")
    assert result == "powershell.exe"


def test_extract_script_host_prefers_real_script_over_placeholder() -> None:
    """A real script argument still wins when one is present."""
    cmdline = r'wscript.exe "%1" C:\scripts\evil.vbs'
    assert extract_executable_from_cmdline(cmdline) == r"C:\scripts\evil.vbs"


def test_extract_powershell_abbreviated_execution_policy() -> None:
    """PowerShell binds -exec to -ExecutionPolicy, so its value is not the target."""
    cmdline = r"powershell.exe -nop -exec bypass -File C:\evil.ps1"
    assert extract_executable_from_cmdline(cmdline) == r"C:\evil.ps1"


def test_extract_powershell_two_letter_execution_policy() -> None:
    """The shortest unambiguous spelling -ex is handled like the full name."""
    cmdline = r"powershell.exe -ex bypass -File C:\evil.ps1"
    assert extract_executable_from_cmdline(cmdline) == r"C:\evil.ps1"


def test_extract_powershell_abbreviated_window_style() -> None:
    """-win binds to -WindowStyle and consumes its value."""
    cmdline = r"powershell.exe -win hidden -File C:\evil.ps1"
    assert extract_executable_from_cmdline(cmdline) == r"C:\evil.ps1"


def test_extract_powershell_abbreviated_version() -> None:
    """-v binds to -Version and consumes its value."""
    cmdline = r"powershell.exe -v 2 -File C:\evil.ps1"
    assert extract_executable_from_cmdline(cmdline) == r"C:\evil.ps1"


def test_extract_cmd_skips_leading_switches() -> None:
    """cmd /q /c resolves to the program, not to the /q switch."""
    cmdline = r'cmd.exe /q /c del /q "C:\Users\x\OneDriveSetup.exe"'
    assert extract_executable_from_cmdline(cmdline) == "del"


def test_extract_cmd_doubled_quote_form() -> None:
    """cmd's doubled-quote form still yields the quoted program path."""
    cmdline = r'cmd.exe /c ""C:\Windows\System32\sethc.exe""'
    assert extract_executable_from_cmdline(cmdline) == r"C:\Windows\System32\sethc.exe"
