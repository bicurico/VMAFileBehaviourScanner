# VMA File Behaviour Scanner

Free source-available static behaviour scanner for one Windows file at a time.

This is **not** an antivirus and does not claim that a file is clean or malicious. It gives a local second opinion by explaining static indicators that may cause antivirus or reputation systems to flag a file.

## Features

- VB.NET WinForms, .NET Framework 4.8
- Local-only single-file scan
- MD5 and SHA256
- PE header parsing
- x86/x64/ARM64 machine identification
- .NET CLR header detection
- PE section entropy
- executable+writable section detection
- overlay detection
- import table behaviour classification
- suspicious string extraction with conservative scoring
- evidence clusters for stronger findings, for example registry path plus registry-write API
- self-scan suppression so the scanner does not score its own embedded rule strings
- registry, persistence, filesystem, network, process execution, process injection, anti-debug and anti-VM indicators
- TXT report export
- VAXD-style JSON xref export
- clickable VAXD website link in the report window

## Safety behaviour

The scanner does **not**:

- execute the analysed file
- upload the file
- contact URLs found in the file
- delete files
- quarantine files
- modify the analysed file

## Command line

```text
VMAFileBehaviourScanner.exe --file "C:\sample\file.exe"
```

## VAXD xref JSON

The JSON export uses this format:

```json
{
  "Format": "VMA_SECURITY_XREFS",
  "Version": 1,
  "TargetFile": "sample.exe",
  "Sha256": "...",
  "Findings": [
    {
      "Severity": "High",
      "Category": "Persistence",
      "Title": "String indicator found",
      "Evidence": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Api": null,
      "Rva": null,
      "FileOffset": "1234",
      "SuggestedAction": "Review this finding in VAXD or another disassembler. Static indicators are not proof of malware."
    }
  ]
}
```

Future VAXD versions can import this file and jump to the flagged RVA or file offset.

## License

This project no longer uses the MIT license. It uses a custom non-commercial attribution source license.

In practical terms:

- people may download, inspect, build and modify the source code;
- people may redistribute the original or modified project free of charge;
- attribution to Vitor Martins Augusto must remain;
- VAXD references and the VAXD website link must not be removed;
- the project, modified versions, and redistributed binaries may not be sold.

See `LICENSE.txt` for the full terms.

## Build

Open `VMAFileBehaviourScanner.sln` in Visual Studio and build as .NET Framework 4.8.


## Scoring policy

Individual strings are weak evidence. For example, a file may contain `powershell`, `wallet.dat`, or registry paths because they are help text, rule text, logs, documentation, or UI strings.

Therefore, string-only findings are deliberately scored lower than API clusters or PE structure findings. Stronger findings are created when different evidence types appear together, for example:

- autorun registry path + registry write/create API
- URL or domain-like evidence + network API
- PowerShell + encoded/dynamic execution markers
- OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread

When the program scans its own executable, embedded scanner rule strings are suppressed because they are part of the scanner itself, not behaviour of an analysed sample.
