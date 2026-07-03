# VMA File Behaviour Scanner

VMA File Behaviour Scanner is a free source-available static behaviour scanner for individual Windows EXE/DLL files.

It performs local static analysis only. It does not upload, execute, delete, quarantine or modify files.

The scanner helps users understand why a file may look suspicious by analysing:

- hashes
- PE metadata and sections
- import table behaviour
- suspicious strings
- registry indicators
- filesystem indicators
- network indicators
- process execution indicators
- entropy
- VAXD-style XREF JSON export

This tool is not an antivirus and does not claim that a file is clean or malicious. It provides a second opinion for manual review.

For deeper reverse-engineering analysis, see VAXD:
https://vma-broadcast.com/vaxd-vma-executable-disassembler/
