Imports System
Imports System.Collections.Generic
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.RegularExpressions

Public Class ScanEngine

    Private ReadOnly _apiPatterns As Dictionary(Of String, ApiPattern)
    Private ReadOnly _stringPatterns As List(Of StringPattern)

    Private Class ApiPattern
        Public Property Category As BehaviourCategory
        Public Property Level As SuspicionLevel
        Public Property Score As Integer
        Public Property Description As String
    End Class

    Private Class StringPattern
        Public Property SearchText As String
        Public Property Category As BehaviourCategory
        Public Property Level As SuspicionLevel
        Public Property Score As Integer
        Public Property Description As String
    End Class

    Public Sub New()
        _apiPatterns = BuildApiPatterns()
        _stringPatterns = BuildStringPatterns()
    End Sub

    Public Function ScanFile(filePath As String) As SecurityScanResult
        Dim result As New SecurityScanResult()
        result.TargetFilePath = filePath

        If Not System.IO.File.Exists(filePath) Then
            Throw New System.IO.FileNotFoundException("The selected file does not exist.", filePath)
        End If

        Dim fileInfo As New System.IO.FileInfo(filePath)
        result.FileSize = fileInfo.Length
        result.Md5 = ComputeHash(filePath, MD5.Create())
        result.Sha256 = ComputeHash(filePath, SHA256.Create())

        Dim allBytes As Byte() = System.IO.File.ReadAllBytes(filePath)
        result.FileEntropy = CalculateEntropy(allBytes, 0, allBytes.Length)
        result.PeDetails = PeParser.Parse(filePath)
        result.ExtractedStrings = ExtractStrings(allBytes, 5)

        AddFileIdentityIndicators(result)
        AddPeIndicators(result)
        AddImportIndicators(result)
        AddImportClusterIndicators(result)

        If IsSelfScan(filePath) Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.Info,
                .Category = BehaviourCategory.Strings,
                .Title = "Self-scan rule strings suppressed",
                .Description = "The scanner executable contains its own detection words as normal program strings. These embedded rule strings were not scored as suspicious behaviour.",
                .Evidence = "Scanning this scanner executable",
                .Score = 0
            })
        Else
            AddStringIndicators(result)
            AddStringClusterIndicators(result)
        End If

        result.Indicators = result.Indicators.OrderByDescending(Function(indicatorItem) indicatorItem.Level).ThenByDescending(Function(indicatorItem) indicatorItem.Score).ThenBy(Function(indicatorItem) indicatorItem.Category.ToString()).ToList()
        Return result
    End Function

    Private Shared Function IsSelfScan(filePath As String) As Boolean
        Try
            Dim selectedFullPath As String = System.IO.Path.GetFullPath(filePath)
            Dim currentFullPath As String = System.IO.Path.GetFullPath(System.Reflection.Assembly.GetExecutingAssembly().Location)
            Return String.Equals(selectedFullPath, currentFullPath, StringComparison.OrdinalIgnoreCase)
        Catch
            Return False
        End Try
    End Function

    Private Shared Function ComputeHash(filePath As String, algorithm As HashAlgorithm) As String
        Using hashAlgorithm As HashAlgorithm = algorithm
            Using stream As System.IO.FileStream = System.IO.File.OpenRead(filePath)
                Dim hashBytes As Byte() = hashAlgorithm.ComputeHash(stream)
                Dim builder As New StringBuilder()
                For Each byteValue As Byte In hashBytes
                    builder.Append(byteValue.ToString("x2"))
                Next
                Return builder.ToString()
            End Using
        End Using
    End Function

    Private Shared Function CalculateEntropy(allBytes As Byte(), offsetValue As Long, countValue As Long) As Double
        If allBytes Is Nothing OrElse allBytes.Length = 0 OrElse countValue <= 0 Then Return 0
        Dim safeCount As Long = Math.Min(countValue, allBytes.Length - offsetValue)
        If safeCount <= 0 Then Return 0
        Dim counters(255) As Long
        For byteIndex As Long = offsetValue To offsetValue + safeCount - 1
            counters(allBytes(CInt(byteIndex))) += 1
        Next
        Dim entropyValue As Double = 0
        For counterIndex As Integer = 0 To 255
            If counters(counterIndex) > 0 Then
                Dim probability As Double = counters(counterIndex) / CDbl(safeCount)
                entropyValue -= probability * Math.Log(probability, 2)
            End If
        Next
        Return entropyValue
    End Function

    Private Shared Function ExtractStrings(allBytes As Byte(), minimumLength As Integer) As List(Of ExtractedStringInfo)
        Dim output As New List(Of ExtractedStringInfo)()
        ExtractAsciiStrings(allBytes, minimumLength, output)
        ExtractUnicodeStrings(allBytes, minimumLength, output)
        Return output
    End Function

    Private Shared Sub ExtractAsciiStrings(allBytes As Byte(), minimumLength As Integer, output As List(Of ExtractedStringInfo))
        Dim builder As New StringBuilder()
        Dim startOffset As Long = 0
        For byteIndex As Integer = 0 To allBytes.Length - 1
            Dim byteValue As Byte = allBytes(byteIndex)
            If byteValue >= 32 AndAlso byteValue <= 126 Then
                If builder.Length = 0 Then startOffset = byteIndex
                builder.Append(ChrW(byteValue))
            Else
                If builder.Length >= minimumLength Then
                    output.Add(New ExtractedStringInfo With {.TextValue = builder.ToString(), .FileOffset = startOffset, .IsUnicode = False})
                End If
                builder.Clear()
            End If
        Next
        If builder.Length >= minimumLength Then
            output.Add(New ExtractedStringInfo With {.TextValue = builder.ToString(), .FileOffset = startOffset, .IsUnicode = False})
        End If
    End Sub

    Private Shared Sub ExtractUnicodeStrings(allBytes As Byte(), minimumLength As Integer, output As List(Of ExtractedStringInfo))
        Dim builder As New StringBuilder()
        Dim startOffset As Long = 0
        Dim byteIndex As Integer = 0
        While byteIndex + 1 < allBytes.Length
            Dim firstByte As Byte = allBytes(byteIndex)
            Dim secondByte As Byte = allBytes(byteIndex + 1)
            If firstByte >= 32 AndAlso firstByte <= 126 AndAlso secondByte = 0 Then
                If builder.Length = 0 Then startOffset = byteIndex
                builder.Append(ChrW(firstByte))
                byteIndex += 2
            Else
                If builder.Length >= minimumLength Then
                    output.Add(New ExtractedStringInfo With {.TextValue = builder.ToString(), .FileOffset = startOffset, .IsUnicode = True})
                End If
                builder.Clear()
                byteIndex += 1
            End If
        End While
        If builder.Length >= minimumLength Then
            output.Add(New ExtractedStringInfo With {.TextValue = builder.ToString(), .FileOffset = startOffset, .IsUnicode = True})
        End If
    End Sub

    Private Sub AddFileIdentityIndicators(result As SecurityScanResult)
        result.Indicators.Add(New BehaviourIndicator With {
            .Level = SuspicionLevel.Info,
            .Category = BehaviourCategory.FileIdentity,
            .Title = "File identity calculated",
            .Description = "MD5 and SHA256 were calculated locally. No file was uploaded.",
            .Evidence = "SHA256: " & result.Sha256,
            .Score = 0
        })

        If result.FileEntropy >= 7.2 Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.Medium,
                .Category = BehaviourCategory.Obfuscation,
                .Title = "High whole-file entropy",
                .Description = "The file has high entropy. This can indicate packing, compression or encryption. It is not proof of malware.",
                .Evidence = result.FileEntropy.ToString("0.00"),
                .Score = 10
            })
        End If
    End Sub

    Private Sub AddPeIndicators(result As SecurityScanResult)
        If result.PeDetails Is Nothing OrElse Not result.PeDetails.IsPe Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.Low,
                .Category = BehaviourCategory.PeStructure,
                .Title = "Not a valid PE file",
                .Description = "The selected file is not a standard Windows PE EXE/DLL file, so PE import and section analysis is limited.",
                .Evidence = "PE header not found",
                .Score = 1
            })
            Return
        End If

        If result.PeDetails.IsDotNet Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.Info,
                .Category = BehaviourCategory.DotNet,
                .Title = ".NET executable detected",
                .Description = "The file contains a .NET CLR header. Future versions can add IL call and ldstr analysis.",
                .Evidence = ".NET / CLR data directory present",
                .Score = 0
            })
        End If

        If result.PeDetails.OverlayOffset.HasValue Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.Low,
                .Category = BehaviourCategory.PeStructure,
                .Title = "Overlay data found",
                .Description = "Data exists after the last PE section. This is common in installers, self-extractors and protected files, but can also hide payload data.",
                .Evidence = "Overlay starts at file offset 0x" & result.PeDetails.OverlayOffset.Value.ToString("X"),
                .FileOffset = result.PeDetails.OverlayOffset.Value,
                .Score = 5
            })
        End If

        For Each sectionItem As PeSectionInfo In result.PeDetails.Sections
            If sectionItem.IsExecutable AndAlso sectionItem.IsWritable Then
                result.Indicators.Add(New BehaviourIndicator With {
                    .Level = SuspicionLevel.High,
                    .Category = BehaviourCategory.PeStructure,
                    .Title = "Executable and writable section",
                    .Description = "A section is both executable and writable. This may indicate a packer, protector or self-modifying code.",
                    .Evidence = sectionItem.SectionLabel,
                    .SectionLabel = sectionItem.SectionLabel,
                    .Rva = sectionItem.VirtualAddress,
                    .FileOffset = sectionItem.RawPointer,
                    .Score = 25
                })
            End If

            If sectionItem.IsExecutable AndAlso sectionItem.Entropy >= 7.2 Then
                result.Indicators.Add(New BehaviourIndicator With {
                    .Level = SuspicionLevel.Medium,
                    .Category = BehaviourCategory.Obfuscation,
                    .Title = "High entropy executable section",
                    .Description = "An executable section has high entropy. This can indicate packing, compression or encryption.",
                    .Evidence = sectionItem.SectionLabel & " entropy " & sectionItem.Entropy.ToString("0.00"),
                    .SectionLabel = sectionItem.SectionLabel,
                    .Rva = sectionItem.VirtualAddress,
                    .FileOffset = sectionItem.RawPointer,
                    .Score = 15
                })
            End If

            Dim lowerSectionLabel As String = sectionItem.SectionLabel.ToLowerInvariant()
            If lowerSectionLabel.Contains("upx") OrElse lowerSectionLabel.Contains("mpress") OrElse lowerSectionLabel.Contains("aspack") OrElse lowerSectionLabel.Contains("vmp") Then
                result.Indicators.Add(New BehaviourIndicator With {
                    .Level = SuspicionLevel.Medium,
                    .Category = BehaviourCategory.Obfuscation,
                    .Title = "Packer/protector-like section name",
                    .Description = "The section name resembles a known packer/protector marker. This can be legitimate or suspicious depending on context.",
                    .Evidence = sectionItem.SectionLabel,
                    .SectionLabel = sectionItem.SectionLabel,
                    .Rva = sectionItem.VirtualAddress,
                    .FileOffset = sectionItem.RawPointer,
                    .Score = 15
                })
            End If
        Next
    End Sub

    Private Sub AddImportIndicators(result As SecurityScanResult)
        If result.PeDetails Is Nothing Then Return
        Dim seenKeys As New HashSet(Of String)(StringComparer.OrdinalIgnoreCase)

        For Each importItem As ImportedApiInfo In result.PeDetails.ImportedApis
            Dim apiKey As String = NormalizeApiLabel(importItem.ApiLabel)
            If _apiPatterns.ContainsKey(apiKey) Then
                Dim pattern As ApiPattern = _apiPatterns(apiKey)
                Dim uniqueKey As String = pattern.Category.ToString() & ":" & apiKey
                If Not seenKeys.Contains(uniqueKey) Then
                    seenKeys.Add(uniqueKey)
                    Dim findingRva As Nullable(Of Long) = importItem.ImportRva
                    Dim findingOffset As Nullable(Of Long) = importItem.ImportFileOffset
                    Dim locationText As String = "IAT/import table"
                    If importItem.CallSiteRvas.Count > 0 Then
                        findingRva = importItem.CallSiteRvas(0)
                        findingOffset = importItem.CallSiteFileOffsets(0)
                        locationText = "call site RVA 0x" & findingRva.Value.ToString("X")
                    End If
                    result.Indicators.Add(New BehaviourIndicator With {
                        .Level = pattern.Level,
                        .Category = pattern.Category,
                        .Title = "Suspicious API call/import found",
                        .Description = pattern.Description,
                        .Evidence = importItem.DllLabel & "!" & importItem.ApiLabel & " (" & locationText & ")",
                        .ApiLabel = importItem.ApiLabel,
                        .Rva = findingRva,
                        .FileOffset = findingOffset,
                        .Score = pattern.Score
                    })
                End If
            End If
        Next
    End Sub

    Private Sub AddImportClusterIndicators(result As SecurityScanResult)
        If result.PeDetails Is Nothing Then Return
        Dim apiSet As New HashSet(Of String)(StringComparer.OrdinalIgnoreCase)
        For Each importItem As ImportedApiInfo In result.PeDetails.ImportedApis
            apiSet.Add(NormalizeApiLabel(importItem.ApiLabel))
        Next

        If apiSet.Contains("OpenProcess") AndAlso apiSet.Contains("VirtualAllocEx") AndAlso apiSet.Contains("WriteProcessMemory") AndAlso (apiSet.Contains("CreateRemoteThread") OrElse apiSet.Contains("NtCreateThreadEx")) Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.High,
                .Category = BehaviourCategory.ProcessInjection,
                .Title = "Remote process injection API cluster",
                .Description = "The import table contains a common remote process injection API combination. This is high-value evidence but not proof of malware.",
                .Evidence = "OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread/NtCreateThreadEx",
                .Score = 35
            })
        End If

        If (apiSet.Contains("WinHttpOpen") OrElse apiSet.Contains("InternetOpen") OrElse apiSet.Contains("URLDownloadToFile")) AndAlso (apiSet.Contains("CreateProcess") OrElse apiSet.Contains("ShellExecute") OrElse apiSet.Contains("WinExec")) Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.Medium,
                .Category = BehaviourCategory.Network,
                .Title = "Network plus process execution APIs",
                .Description = "The file imports both network and process execution APIs. This may indicate updater, installer, downloader or suspicious behaviour.",
                .Evidence = "Network API + process execution API",
                .Score = 20
            })
        End If
    End Sub

    Private Sub AddStringIndicators(result As SecurityScanResult)
        Dim seenEvidence As New HashSet(Of String)(StringComparer.OrdinalIgnoreCase)
        Dim patternHitCounts As New Dictionary(Of String, Integer)(StringComparer.OrdinalIgnoreCase)

        For Each stringItem As ExtractedStringInfo In result.ExtractedStrings
            For Each pattern As StringPattern In _stringPatterns
                If IsStringPatternMatch(stringItem.TextValue, pattern.SearchText) Then
                    Dim currentCount As Integer = 0
                    If patternHitCounts.ContainsKey(pattern.SearchText) Then currentCount = patternHitCounts(pattern.SearchText)

                    If currentCount < 3 Then
                        Dim uniqueKey As String = pattern.SearchText & ":" & stringItem.FileOffset.ToString()
                        If Not seenEvidence.Contains(uniqueKey) Then
                            seenEvidence.Add(uniqueKey)
                            patternHitCounts(pattern.SearchText) = currentCount + 1
                            result.Indicators.Add(New BehaviourIndicator With {
                                .Level = pattern.Level,
                                .Category = pattern.Category,
                                .Title = "String indicator found",
                                .Description = pattern.Description & " A string alone is weak evidence and does not prove that the behaviour is executed.",
                                .Evidence = ShortenEvidence(stringItem.TextValue, 240),
                                .FileOffset = stringItem.FileOffset,
                                .Score = pattern.Score
                            })
                        End If
                    End If
                End If
            Next

            If LooksLikeUrl(stringItem.TextValue) Then
                Dim uniqueKey As String = "url:" & stringItem.FileOffset.ToString()
                If Not seenEvidence.Contains(uniqueKey) Then
                    seenEvidence.Add(uniqueKey)
                    result.Indicators.Add(New BehaviourIndicator With {
                        .Level = SuspicionLevel.Low,
                        .Category = BehaviourCategory.Network,
                        .Title = "URL or web endpoint found",
                        .Description = "The file contains a URL-like string. The scanner does not contact this address. A URL alone is weak evidence.",
                        .Evidence = ShortenEvidence(stringItem.TextValue, 240),
                        .FileOffset = stringItem.FileOffset,
                        .Score = 5
                    })
                End If
            End If

            If LooksLikeIpv4(stringItem.TextValue) Then
                Dim uniqueKey As String = "ipv4:" & stringItem.FileOffset.ToString()
                If Not seenEvidence.Contains(uniqueKey) Then
                    seenEvidence.Add(uniqueKey)
                    result.Indicators.Add(New BehaviourIndicator With {
                        .Level = SuspicionLevel.Low,
                        .Category = BehaviourCategory.Network,
                        .Title = "IPv4 address-like string found",
                        .Description = "The file contains an IPv4 address-like string. This can be configuration, logging, telemetry or network behaviour.",
                        .Evidence = ShortenEvidence(stringItem.TextValue, 240),
                        .FileOffset = stringItem.FileOffset,
                        .Score = 2
                    })
                End If
            End If
        Next
    End Sub

    Private Sub AddStringClusterIndicators(result As SecurityScanResult)
        Dim hasRegistryPersistenceString As Boolean = ContainsAnyExtractedString(result, New String() {
            "Software\Microsoft\Windows\CurrentVersion\Run",
            "Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "SYSTEM\CurrentControlSet\Services"
        })

        Dim hasRegistryWriteApi As Boolean = HasImportedApi(result, New String() {
            "RegSetValueEx",
            "RegCreateKeyEx",
            "SHSetValue",
            "RegDeleteValue",
            "RegDeleteKey"
        })

        If hasRegistryPersistenceString AndAlso hasRegistryWriteApi Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.High,
                .Category = BehaviourCategory.Persistence,
                .Title = "Registry persistence evidence cluster",
                .Description = "The file contains an autorun/service registry string and imports registry write/create APIs. This is stronger than a string match alone, but still not proof of malware.",
                .Evidence = "Autorun/service registry string + registry write/create API",
                .Score = 25
            })
        End If

        Dim hasNetworkString As Boolean = ContainsUrlExtractedString(result) OrElse ContainsAnyExtractedString(result, New String() {".onion"})
        Dim hasNetworkApi As Boolean = HasImportedApi(result, New String() {
            "InternetOpen",
            "InternetConnect",
            "HttpSendRequest",
            "URLDownloadToFile",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "WSAStartup",
            "connect"
        })

        If hasNetworkString AndAlso hasNetworkApi Then
            result.Indicators.Add(New BehaviourIndicator With {
                .Level = SuspicionLevel.Medium,
                .Category = BehaviourCategory.Network,
                .Title = "Network endpoint plus network API evidence cluster",
                .Description = "The file contains a network endpoint string and imports network APIs. This may be normal update/licensing/telemetry behaviour or suspicious communication.",
                .Evidence = "URL/domain-like evidence + network API",
                .Score = 15
            })
        End If

        Dim hasPowerShellString As Boolean = ContainsAnyExtractedString(result, New String() {"powershell"})
        Dim hasPowerShellObfuscationString As Boolean = ContainsAnyExtractedString(result, New String() {"-enc", "FromBase64String", "Invoke-Expression"})

        If hasPowerShellString AndAlso hasPowerShellObfuscationString Then
            Dim clusterLevel As SuspicionLevel = SuspicionLevel.Medium
            Dim clusterScore As Integer = 15
            If HasImportedApi(result, New String() {"CreateProcess", "ShellExecute", "WinExec"}) Then
                clusterLevel = SuspicionLevel.High
                clusterScore = 25
            End If

            result.Indicators.Add(New BehaviourIndicator With {
                .Level = clusterLevel,
                .Category = BehaviourCategory.ProcessExecution,
                .Title = "PowerShell execution evidence cluster",
                .Description = "The file contains PowerShell plus encoded/dynamic execution markers. This is stronger than a single string match, but it still requires manual review.",
                .Evidence = "powershell + encoded/dynamic execution marker",
                .Score = clusterScore
            })
        End If
    End Sub

    Private Shared Function IsStringPatternMatch(textValue As String, searchTextValue As String) As Boolean
        If String.IsNullOrEmpty(textValue) OrElse String.IsNullOrEmpty(searchTextValue) Then Return False

        If searchTextValue.Length <= 3 Then
            Return Regex.IsMatch(textValue, "(?<![A-Za-z0-9_])" & Regex.Escape(searchTextValue) & "(?![A-Za-z0-9_])", RegexOptions.IgnoreCase)
        End If

        Return textValue.IndexOf(searchTextValue, StringComparison.OrdinalIgnoreCase) >= 0
    End Function

    Private Shared Function ContainsAnyExtractedString(result As SecurityScanResult, searchValues As String()) As Boolean
        If result Is Nothing OrElse result.ExtractedStrings Is Nothing Then Return False
        For Each stringItem As ExtractedStringInfo In result.ExtractedStrings
            For Each searchTextValue As String In searchValues
                If IsStringPatternMatch(stringItem.TextValue, searchTextValue) Then Return True
            Next
        Next
        Return False
    End Function

    Private Shared Function ContainsUrlExtractedString(result As SecurityScanResult) As Boolean
        If result Is Nothing OrElse result.ExtractedStrings Is Nothing Then Return False
        For Each stringItem As ExtractedStringInfo In result.ExtractedStrings
            If LooksLikeUrl(stringItem.TextValue) Then Return True
        Next
        Return False
    End Function

    Private Shared Function HasImportedApi(result As SecurityScanResult, apiLabels As String()) As Boolean
        If result Is Nothing OrElse result.PeDetails Is Nothing OrElse result.PeDetails.ImportedApis Is Nothing Then Return False
        For Each importItem As ImportedApiInfo In result.PeDetails.ImportedApis
            Dim normalizedApi As String = NormalizeApiLabel(importItem.ApiLabel)
            For Each apiLabel As String In apiLabels
                If String.Equals(normalizedApi, apiLabel, StringComparison.OrdinalIgnoreCase) Then Return True
            Next
        Next
        Return False
    End Function

    Private Shared Function LooksLikeUrl(textValue As String) As Boolean
        Return Regex.IsMatch(textValue, "https?://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+", RegexOptions.IgnoreCase)
    End Function

    Private Shared Function LooksLikeIpv4(textValue As String) As Boolean
        Return Regex.IsMatch(textValue, "\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b")
    End Function

    Private Shared Function ShortenEvidence(textValue As String, maxLength As Integer) As String
        If String.IsNullOrEmpty(textValue) Then Return ""
        Dim cleanText As String = textValue.Replace(vbCr, " ").Replace(vbLf, " ").Replace(vbTab, " ")
        If cleanText.Length <= maxLength Then Return cleanText
        Return cleanText.Substring(0, maxLength) & "..."
    End Function

    Private Shared Function NormalizeApiLabel(apiLabel As String) As String
        If String.IsNullOrEmpty(apiLabel) Then Return ""
        Dim cleanApi As String = apiLabel.Trim()
        If cleanApi.EndsWith("A", StringComparison.OrdinalIgnoreCase) OrElse cleanApi.EndsWith("W", StringComparison.OrdinalIgnoreCase) Then
            Dim baseApi As String = cleanApi.Substring(0, cleanApi.Length - 1)
            Select Case baseApi
                Case "RegOpenKeyEx", "RegCreateKeyEx", "RegSetValueEx", "RegDeleteValue", "RegDeleteKey", "CreateFile", "DeleteFile", "CopyFile", "MoveFile", "GetWindowsDirectory", "GetSystemDirectory", "SHGetFolderPath", "InternetOpen", "InternetConnect", "HttpSendRequest", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "CreateProcess", "ShellExecute", "OutputDebugString", "SetWindowsHookEx", "DnsQuery", "CreateService", "OpenSCManager", "StartService"
                    Return baseApi
            End Select
        End If
        Return cleanApi
    End Function

    Private Shared Function BuildApiPatterns() As Dictionary(Of String, ApiPattern)
        Dim patterns As New Dictionary(Of String, ApiPattern)(StringComparer.OrdinalIgnoreCase)
        AddApi(patterns, "RegOpenKeyEx", BehaviourCategory.Registry, SuspicionLevel.Low, 5, "Opens a Windows registry key.")
        AddApi(patterns, "RegCreateKeyEx", BehaviourCategory.Registry, SuspicionLevel.Medium, 10, "Creates or opens a Windows registry key.")
        AddApi(patterns, "RegSetValueEx", BehaviourCategory.Registry, SuspicionLevel.Medium, 10, "Writes a value to the Windows registry.")
        AddApi(patterns, "RegDeleteValue", BehaviourCategory.Registry, SuspicionLevel.Medium, 10, "Deletes a value from the Windows registry.")
        AddApi(patterns, "RegDeleteKey", BehaviourCategory.Registry, SuspicionLevel.Medium, 10, "Deletes a Windows registry key.")
        AddApi(patterns, "CreateFile", BehaviourCategory.FileSystem, SuspicionLevel.Low, 5, "Opens or creates files/devices. Sensitive when combined with Windows/System32/AppData paths.")
        AddApi(patterns, "WriteFile", BehaviourCategory.FileSystem, SuspicionLevel.Low, 5, "Writes data to a file/device.")
        AddApi(patterns, "DeleteFile", BehaviourCategory.FileSystem, SuspicionLevel.Medium, 10, "Deletes a file.")
        AddApi(patterns, "CopyFile", BehaviourCategory.FileSystem, SuspicionLevel.Low, 5, "Copies files.")
        AddApi(patterns, "MoveFile", BehaviourCategory.FileSystem, SuspicionLevel.Low, 5, "Moves or renames files.")
        AddApi(patterns, "GetWindowsDirectory", BehaviourCategory.FileSystem, SuspicionLevel.Low, 5, "Obtains the Windows directory path.")
        AddApi(patterns, "GetSystemDirectory", BehaviourCategory.FileSystem, SuspicionLevel.Low, 5, "Obtains the Windows System32 directory path.")
        AddApi(patterns, "InternetOpen", BehaviourCategory.Network, SuspicionLevel.Medium, 10, "Initializes WinINet network access.")
        AddApi(patterns, "InternetConnect", BehaviourCategory.Network, SuspicionLevel.Medium, 10, "Connects to a network server using WinINet.")
        AddApi(patterns, "HttpSendRequest", BehaviourCategory.Network, SuspicionLevel.Medium, 10, "Sends an HTTP request using WinINet.")
        AddApi(patterns, "URLDownloadToFile", BehaviourCategory.Network, SuspicionLevel.Medium, 15, "Downloads a URL to a local file.")
        AddApi(patterns, "WinHttpOpen", BehaviourCategory.Network, SuspicionLevel.Medium, 10, "Initializes WinHTTP network access.")
        AddApi(patterns, "WinHttpConnect", BehaviourCategory.Network, SuspicionLevel.Medium, 10, "Connects to a network server using WinHTTP.")
        AddApi(patterns, "WinHttpSendRequest", BehaviourCategory.Network, SuspicionLevel.Medium, 10, "Sends an HTTP request using WinHTTP.")
        AddApi(patterns, "WSAStartup", BehaviourCategory.Network, SuspicionLevel.Low, 5, "Initializes Winsock networking.")
        AddApi(patterns, "socket", BehaviourCategory.Network, SuspicionLevel.Low, 5, "Creates a network socket.")
        AddApi(patterns, "connect", BehaviourCategory.Network, SuspicionLevel.Medium, 10, "Connects a socket to a remote endpoint.")
        AddApi(patterns, "send", BehaviourCategory.Network, SuspicionLevel.Low, 5, "Sends data over a socket.")
        AddApi(patterns, "recv", BehaviourCategory.Network, SuspicionLevel.Low, 5, "Receives data over a socket.")
        AddApi(patterns, "OpenProcess", BehaviourCategory.ProcessInjection, SuspicionLevel.Medium, 10, "Opens another process. Sensitive when combined with memory-write and thread-creation APIs.")
        AddApi(patterns, "VirtualAllocEx", BehaviourCategory.ProcessInjection, SuspicionLevel.High, 20, "Allocates memory in another process.")
        AddApi(patterns, "WriteProcessMemory", BehaviourCategory.ProcessInjection, SuspicionLevel.High, 20, "Writes memory into another process.")
        AddApi(patterns, "CreateRemoteThread", BehaviourCategory.ProcessInjection, SuspicionLevel.High, 25, "Creates a thread in another process.")
        AddApi(patterns, "NtCreateThreadEx", BehaviourCategory.ProcessInjection, SuspicionLevel.High, 25, "Creates a thread through the NT native API.")
        AddApi(patterns, "QueueUserAPC", BehaviourCategory.ProcessInjection, SuspicionLevel.High, 20, "Queues an APC, which can be used for code injection.")
        AddApi(patterns, "VirtualAlloc", BehaviourCategory.ProcessExecution, SuspicionLevel.Low, 5, "Allocates process memory. Common in legitimate programs and packers.")
        AddApi(patterns, "VirtualProtect", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 10, "Changes memory protection, often used by packers, JIT engines and shellcode loaders.")
        AddApi(patterns, "CreateProcess", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 10, "Creates a new process.")
        AddApi(patterns, "ShellExecute", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 10, "Runs or opens a file/URL through the shell.")
        AddApi(patterns, "WinExec", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 10, "Runs another program using a legacy API.")
        AddApi(patterns, "OpenSCManager", BehaviourCategory.Persistence, SuspicionLevel.Medium, 10, "Opens the Service Control Manager.")
        AddApi(patterns, "CreateService", BehaviourCategory.Persistence, SuspicionLevel.High, 20, "Creates a Windows service.")
        AddApi(patterns, "StartService", BehaviourCategory.Persistence, SuspicionLevel.Medium, 10, "Starts a Windows service.")
        AddApi(patterns, "IsDebuggerPresent", BehaviourCategory.AntiDebug, SuspicionLevel.Low, 5, "Checks whether the process is being debugged.")
        AddApi(patterns, "CheckRemoteDebuggerPresent", BehaviourCategory.AntiDebug, SuspicionLevel.Low, 5, "Checks whether a process is being debugged.")
        AddApi(patterns, "NtQueryInformationProcess", BehaviourCategory.AntiDebug, SuspicionLevel.Medium, 10, "Can be used for anti-debugging and process inspection.")
        AddApi(patterns, "OutputDebugString", BehaviourCategory.AntiDebug, SuspicionLevel.Low, 3, "Can be used in anti-debugging checks or normal debug logging.")
        Return patterns
    End Function

    Private Shared Sub AddApi(patterns As Dictionary(Of String, ApiPattern), apiLabel As String, categoryValue As BehaviourCategory, levelValue As SuspicionLevel, scoreValue As Integer, descriptionText As String)
        patterns(apiLabel) = New ApiPattern With {.Category = categoryValue, .Level = levelValue, .Score = scoreValue, .Description = descriptionText}
    End Sub

    Private Shared Function BuildStringPatterns() As List(Of StringPattern)
        Dim patterns As New List(Of StringPattern)()
        AddString(patterns, "Software\Microsoft\Windows\CurrentVersion\Run", BehaviourCategory.Persistence, SuspicionLevel.Medium, 8, "Autorun registry key reference. This may indicate startup persistence if used by registry write code.")
        AddString(patterns, "Software\Microsoft\Windows\CurrentVersion\RunOnce", BehaviourCategory.Persistence, SuspicionLevel.Medium, 8, "RunOnce registry key reference. This may indicate startup persistence if used by registry write code.")
        AddString(patterns, "SYSTEM\CurrentControlSet\Services", BehaviourCategory.Persistence, SuspicionLevel.Medium, 8, "Windows services registry path reference. Stronger evidence when combined with service/registry APIs.")
        AddString(patterns, "C:\Windows\System32", BehaviourCategory.FileSystem, SuspicionLevel.Low, 3, "Windows System32 path reference.")
        AddString(patterns, "%SYSTEMROOT%", BehaviourCategory.FileSystem, SuspicionLevel.Low, 2, "Windows root environment variable reference.")
        AddString(patterns, "%WINDIR%", BehaviourCategory.FileSystem, SuspicionLevel.Low, 2, "Windows directory environment variable reference.")
        AddString(patterns, "%APPDATA%", BehaviourCategory.FileSystem, SuspicionLevel.Low, 3, "AppData path reference. Frequently used by legitimate applications and persistence mechanisms.")
        AddString(patterns, "%TEMP%", BehaviourCategory.FileSystem, SuspicionLevel.Low, 2, "Temp path reference.")
        AddString(patterns, "cmd.exe", BehaviourCategory.ProcessExecution, SuspicionLevel.Low, 4, "Command interpreter reference.")
        AddString(patterns, "powershell", BehaviourCategory.ProcessExecution, SuspicionLevel.Low, 4, "PowerShell reference. Stronger evidence only when combined with encoded/dynamic execution markers.")
        AddString(patterns, "-enc", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 8, "Possible PowerShell encoded-command marker.")
        AddString(patterns, "FromBase64String", BehaviourCategory.ProcessExecution, SuspicionLevel.Low, 4, "Base64 decoding marker. Common in both legitimate software and encoded scripts/payloads.")
        AddString(patterns, "Invoke-Expression", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 8, "PowerShell dynamic execution marker.")
        AddString(patterns, "wscript.exe", BehaviourCategory.ProcessExecution, SuspicionLevel.Low, 4, "Windows Script Host reference.")
        AddString(patterns, "cscript.exe", BehaviourCategory.ProcessExecution, SuspicionLevel.Low, 4, "Windows Script Host console reference.")
        AddString(patterns, "mshta.exe", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 8, "MSHTA execution reference.")
        AddString(patterns, "rundll32.exe", BehaviourCategory.ProcessExecution, SuspicionLevel.Low, 4, "Rundll32 execution reference.")
        AddString(patterns, "regsvr32.exe", BehaviourCategory.ProcessExecution, SuspicionLevel.Medium, 8, "Regsvr32 execution reference, sometimes abused for script/proxy execution.")
        AddString(patterns, "schtasks", BehaviourCategory.Persistence, SuspicionLevel.Medium, 8, "Scheduled task command reference.")
        AddString(patterns, ".onion", BehaviourCategory.Network, SuspicionLevel.Medium, 8, "Tor onion address marker.")
        AddString(patterns, "Login Data", BehaviourCategory.Credentials, SuspicionLevel.Medium, 8, "Browser credential database marker.")
        AddString(patterns, "wallet.dat", BehaviourCategory.Credentials, SuspicionLevel.Medium, 8, "Cryptocurrency wallet file marker.")
        AddString(patterns, "x64dbg", BehaviourCategory.AntiDebug, SuspicionLevel.Low, 3, "Analysis/debugging tool marker.")
        AddString(patterns, "ollydbg", BehaviourCategory.AntiDebug, SuspicionLevel.Low, 3, "Analysis/debugging tool marker.")
        AddString(patterns, "ida64", BehaviourCategory.AntiDebug, SuspicionLevel.Low, 3, "IDA Pro marker.")
        AddString(patterns, "procmon", BehaviourCategory.AntiDebug, SuspicionLevel.Low, 2, "Process Monitor marker.")
        AddString(patterns, "vmware", BehaviourCategory.AntiVm, SuspicionLevel.Low, 3, "Virtual machine marker.")
        AddString(patterns, "vbox", BehaviourCategory.AntiVm, SuspicionLevel.Low, 3, "VirtualBox marker.")
        Return patterns
    End Function

    Private Shared Sub AddString(patterns As List(Of StringPattern), searchTextValue As String, categoryValue As BehaviourCategory, levelValue As SuspicionLevel, scoreValue As Integer, descriptionText As String)
        patterns.Add(New StringPattern With {.SearchText = searchTextValue, .Category = categoryValue, .Level = levelValue, .Score = scoreValue, .Description = descriptionText})
    End Sub
End Class
