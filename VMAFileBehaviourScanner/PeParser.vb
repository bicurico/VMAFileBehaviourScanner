Imports System
Imports System.Collections.Generic
Imports System.Text

Public Class PeParser

    Public Shared Function Parse(filePath As String) As PeInfo
        Dim info As New PeInfo()

        If Not System.IO.File.Exists(filePath) Then
            Return info
        End If

        Dim allBytes As Byte() = System.IO.File.ReadAllBytes(filePath)
        If allBytes.Length < &H100 Then Return info

        Using memoryStream As New System.IO.MemoryStream(allBytes)
            Using reader As New System.IO.BinaryReader(memoryStream)
                If ReadUInt16At(reader, 0) <> &H5A4DUS Then Return info

                Dim peHeaderOffset As Integer = CInt(ReadUInt32At(reader, &H3C))
                If peHeaderOffset <= 0 OrElse peHeaderOffset + 24 >= allBytes.Length Then Return info
                If ReadUInt32At(reader, peHeaderOffset) <> &H4550UI Then Return info

                info.IsPe = True
                Dim coffOffset As Integer = peHeaderOffset + 4
                Dim machine As UShort = ReadUInt16At(reader, coffOffset)
                Dim sectionCount As UShort = ReadUInt16At(reader, coffOffset + 2)
                Dim timeStamp As UInteger = ReadUInt32At(reader, coffOffset + 4)
                Dim optionalHeaderSize As UShort = ReadUInt16At(reader, coffOffset + 16)
                Dim optionalOffset As Integer = coffOffset + 20
                Dim magic As UShort = ReadUInt16At(reader, optionalOffset)
                Dim isPe32Plus As Boolean = (magic = &H20BUS)

                info.MachineLabel = MachineToText(machine)
                info.TimeDateStampText = TimeStampToText(timeStamp)
                info.EntryPointRva = ReadUInt32At(reader, optionalOffset + 16)

                If isPe32Plus Then
                    info.ImageBase = CLng(ReadUInt64At(reader, optionalOffset + 24))
                    info.SizeOfImage = ReadUInt32At(reader, optionalOffset + 56)
                    info.SizeOfHeaders = ReadUInt32At(reader, optionalOffset + 60)
                    info.SubsystemLabel = SubsystemToText(ReadUInt16At(reader, optionalOffset + 68))
                Else
                    info.ImageBase = ReadUInt32At(reader, optionalOffset + 28)
                    info.SizeOfImage = ReadUInt32At(reader, optionalOffset + 56)
                    info.SizeOfHeaders = ReadUInt32At(reader, optionalOffset + 60)
                    info.SubsystemLabel = SubsystemToText(ReadUInt16At(reader, optionalOffset + 68))
                End If

                Dim dataDirectoryOffset As Integer = If(isPe32Plus, optionalOffset + 112, optionalOffset + 96)
                Dim importTableRva As UInteger = 0UI
                Dim importTableSize As UInteger = 0UI
                Dim cliHeaderRva As UInteger = 0UI
                If dataDirectoryOffset + 15 * 8 + 8 <= allBytes.Length Then
                    importTableRva = ReadUInt32At(reader, dataDirectoryOffset + 8)
                    importTableSize = ReadUInt32At(reader, dataDirectoryOffset + 12)
                    cliHeaderRva = ReadUInt32At(reader, dataDirectoryOffset + 14 * 8)
                End If
                info.IsDotNet = (cliHeaderRva <> 0UI)

                Dim sectionTableOffset As Integer = optionalOffset + optionalHeaderSize
                For sectionIndex As Integer = 0 To sectionCount - 1
                    Dim sectionOffset As Integer = sectionTableOffset + sectionIndex * 40
                    If sectionOffset + 40 > allBytes.Length Then Exit For

                    Dim sectionLabelBytes(7) As Byte
                    Array.Copy(allBytes, sectionOffset, sectionLabelBytes, 0, 8)
                    Dim sectionLabel As String = Encoding.ASCII.GetString(sectionLabelBytes).Trim(ChrW(0))
                    Dim virtualSize As UInteger = ReadUInt32At(reader, sectionOffset + 8)
                    Dim virtualAddress As UInteger = ReadUInt32At(reader, sectionOffset + 12)
                    Dim rawSize As UInteger = ReadUInt32At(reader, sectionOffset + 16)
                    Dim rawPointer As UInteger = ReadUInt32At(reader, sectionOffset + 20)
                    Dim characteristics As UInteger = ReadUInt32At(reader, sectionOffset + 36)

                    Dim sectionInfo As New PeSectionInfo With {
                        .SectionLabel = sectionLabel,
                        .VirtualAddress = virtualAddress,
                        .VirtualSize = virtualSize,
                        .RawPointer = rawPointer,
                        .RawSize = rawSize,
                        .Characteristics = characteristics,
                        .Entropy = CalculateEntropy(allBytes, CLng(rawPointer), CLng(rawSize))
                    }
                    info.Sections.Add(sectionInfo)
                Next

                Dim highestSectionEnd As Long = 0
                For Each sectionItem As PeSectionInfo In info.Sections
                    Dim sectionEnd As Long = sectionItem.RawPointer + sectionItem.RawSize
                    If sectionEnd > highestSectionEnd Then highestSectionEnd = sectionEnd
                Next
                If highestSectionEnd > 0 AndAlso highestSectionEnd < allBytes.Length Then
                    info.OverlayOffset = highestSectionEnd
                End If

                If importTableRva <> 0UI AndAlso importTableSize <> 0UI Then
                    ReadImports(reader, allBytes, info, importTableRva, isPe32Plus)
                    FindImportedApiCallSites(allBytes, info, isPe32Plus)
                End If
            End Using
        End Using

        Return info
    End Function

    Private Shared Sub ReadImports(reader As System.IO.BinaryReader, allBytes As Byte(), info As PeInfo, importTableRva As UInteger, isPe32Plus As Boolean)
        Dim descriptorOffsetNullable As Nullable(Of Long) = RvaToOffset(info.Sections, importTableRva)
        If Not descriptorOffsetNullable.HasValue Then Return

        Dim descriptorOffset As Long = descriptorOffsetNullable.Value
        Dim descriptorCounter As Integer = 0
        While descriptorOffset + 20 <= allBytes.Length AndAlso descriptorCounter < 512
            Dim lookupRva As UInteger = ReadUInt32At(reader, CLng(descriptorOffset))
            Dim dllNameRva As UInteger = ReadUInt32At(reader, CLng(descriptorOffset + 12))
            Dim addressTableRva As UInteger = ReadUInt32At(reader, CLng(descriptorOffset + 16))

            If lookupRva = 0UI AndAlso dllNameRva = 0UI AndAlso addressTableRva = 0UI Then Exit While

            Dim dllNameOffsetNullable As Nullable(Of Long) = RvaToOffset(info.Sections, dllNameRva)
            Dim dllLabel As String = "unknown.dll"
            If dllNameOffsetNullable.HasValue Then dllLabel = ReadAsciiZero(allBytes, dllNameOffsetNullable.Value, 260)

            Dim thunkRva As UInteger = If(lookupRva <> 0UI, lookupRva, addressTableRva)
            Dim thunkOffsetNullable As Nullable(Of Long) = RvaToOffset(info.Sections, thunkRva)
            If thunkOffsetNullable.HasValue Then
                Dim thunkOffset As Long = thunkOffsetNullable.Value
                Dim thunkIndex As Integer = 0
                While thunkOffset < allBytes.Length AndAlso thunkIndex < 4096
                    Dim importByOrdinal As Boolean = False
                    Dim hintNameRva As ULong
                    If isPe32Plus Then
                        If thunkOffset + 8 > allBytes.Length Then Exit While
                        Dim thunkValue As ULong = ReadUInt64At(reader, thunkOffset)
                        If thunkValue = 0UL Then Exit While
                        importByOrdinal = ((thunkValue And &H8000000000000000UL) <> 0UL)
                        hintNameRva = thunkValue And &H7FFFFFFFFFFFFFFFUL
                        thunkOffset += 8
                    Else
                        If thunkOffset + 4 > allBytes.Length Then Exit While
                        Dim thunkValue32 As UInteger = ReadUInt32At(reader, thunkOffset)
                        If thunkValue32 = 0UI Then Exit While
                        importByOrdinal = ((thunkValue32 And &H80000000UI) <> 0UI)
                        hintNameRva = CULng(thunkValue32 And &H7FFFFFFFUI)
                        thunkOffset += 4
                    End If

                    Dim apiLabel As String = "ordinal"
                    If Not importByOrdinal Then
                        Dim apiNameOffsetNullable As Nullable(Of Long) = RvaToOffset(info.Sections, CUInt(hintNameRva))
                        If apiNameOffsetNullable.HasValue AndAlso apiNameOffsetNullable.Value + 2 < allBytes.Length Then
                            apiLabel = ReadAsciiZero(allBytes, apiNameOffsetNullable.Value + 2, 512)
                        End If
                    End If

                    Dim importItem As New ImportedApiInfo With {
                        .DllLabel = dllLabel,
                        .ApiLabel = apiLabel,
                        .ImportRva = CLng(addressTableRva) + If(isPe32Plus, thunkIndex * 8L, thunkIndex * 4L),
                        .ImportFileOffset = Nothing
                    }
                    Dim importOffsetNullable As Nullable(Of Long) = RvaToOffset(info.Sections, CUInt(importItem.ImportRva.Value))
                    If importOffsetNullable.HasValue Then importItem.ImportFileOffset = importOffsetNullable.Value
                    info.ImportedApis.Add(importItem)

                    thunkIndex += 1
                End While
            End If

            descriptorOffset += 20
            descriptorCounter += 1
        End While
    End Sub


    Private Shared Sub FindImportedApiCallSites(allBytes As Byte(), info As PeInfo, isPe32Plus As Boolean)
        If info Is Nothing OrElse info.ImportedApis Is Nothing OrElse info.ImportedApis.Count = 0 Then Return

        For Each importItem As ImportedApiInfo In info.ImportedApis
            If Not importItem.ImportRva.HasValue Then Continue For
            Dim targetRva As Long = importItem.ImportRva.Value

            For Each sectionItem As PeSectionInfo In info.Sections
                If Not sectionItem.IsExecutable Then Continue For
                If sectionItem.RawPointer < 0 OrElse sectionItem.RawPointer >= allBytes.Length Then Continue For

                Dim sectionLength As Long = Math.Min(sectionItem.RawSize, allBytes.Length - sectionItem.RawPointer)
                If sectionLength < 6 Then Continue For

                Dim startOffset As Long = sectionItem.RawPointer
                Dim endOffset As Long = sectionItem.RawPointer + sectionLength - 6
                Dim byteIndex As Long = startOffset
                While byteIndex <= endOffset
                    If allBytes(CInt(byteIndex)) = &HFF AndAlso allBytes(CInt(byteIndex + 1)) = &H15 Then
                        If isPe32Plus Then
                            Dim relValue As Integer = BitConverter.ToInt32(allBytes, CInt(byteIndex + 2))
                            Dim instructionRva As Long = sectionItem.VirtualAddress + (byteIndex - sectionItem.RawPointer)
                            Dim referencedRva As Long = instructionRva + 6 + relValue
                            If referencedRva = targetRva Then
                                importItem.CallSiteRvas.Add(instructionRva)
                                importItem.CallSiteFileOffsets.Add(byteIndex)
                            End If
                        Else
                            Dim absoluteValue As UInteger = BitConverter.ToUInt32(allBytes, CInt(byteIndex + 2))
                            Dim expectedValue As Long = info.ImageBase + targetRva
                            If CLng(absoluteValue) = expectedValue Then
                                Dim instructionRva As Long = sectionItem.VirtualAddress + (byteIndex - sectionItem.RawPointer)
                                importItem.CallSiteRvas.Add(instructionRva)
                                importItem.CallSiteFileOffsets.Add(byteIndex)
                            End If
                        End If
                    End If
                    byteIndex += 1
                End While
            Next
        Next
    End Sub

    Public Shared Function RvaToOffset(sections As List(Of PeSectionInfo), rva As UInteger) As Nullable(Of Long)
        For Each sectionItem As PeSectionInfo In sections
            Dim sectionStart As Long = sectionItem.VirtualAddress
            Dim sectionEnd As Long = sectionItem.VirtualAddress + Math.Max(sectionItem.VirtualSize, sectionItem.RawSize)
            If CLng(rva) >= sectionStart AndAlso CLng(rva) < sectionEnd Then
                Return sectionItem.RawPointer + (CLng(rva) - sectionStart)
            End If
        Next
        Return Nothing
    End Function

    Private Shared Function CalculateEntropy(allBytes As Byte(), offsetValue As Long, countValue As Long) As Double
        If offsetValue < 0 OrElse offsetValue >= allBytes.Length OrElse countValue <= 0 Then Return 0
        Dim maxCount As Long = Math.Min(countValue, allBytes.Length - offsetValue)
        Dim counters(255) As Long
        For byteIndex As Long = offsetValue To offsetValue + maxCount - 1
            counters(allBytes(CInt(byteIndex))) += 1
        Next
        Dim entropyValue As Double = 0
        For counterIndex As Integer = 0 To 255
            If counters(counterIndex) > 0 Then
                Dim probability As Double = counters(counterIndex) / CDbl(maxCount)
                entropyValue -= probability * Math.Log(probability, 2)
            End If
        Next
        Return entropyValue
    End Function

    Private Shared Function ReadAsciiZero(allBytes As Byte(), offsetValue As Long, maxLength As Integer) As String
        Dim builder As New StringBuilder()
        Dim endOffset As Long = Math.Min(allBytes.Length, offsetValue + maxLength)
        For byteIndex As Long = offsetValue To endOffset - 1
            Dim byteValue As Byte = allBytes(CInt(byteIndex))
            If byteValue = 0 Then Exit For
            If byteValue >= 32 AndAlso byteValue <= 126 Then builder.Append(ChrW(byteValue))
        Next
        Return builder.ToString()
    End Function

    Private Shared Function ReadUInt16At(reader As System.IO.BinaryReader, offsetValue As Long) As UShort
        reader.BaseStream.Position = offsetValue
        Return reader.ReadUInt16()
    End Function

    Private Shared Function ReadUInt32At(reader As System.IO.BinaryReader, offsetValue As Long) As UInteger
        reader.BaseStream.Position = offsetValue
        Return reader.ReadUInt32()
    End Function

    Private Shared Function ReadUInt64At(reader As System.IO.BinaryReader, offsetValue As Long) As ULong
        reader.BaseStream.Position = offsetValue
        Return reader.ReadUInt64()
    End Function

    Private Shared Function MachineToText(machine As UShort) As String
        Select Case machine
            Case &H14CUS
                Return "x86 / I386"
            Case &H8664US
                Return "x64 / AMD64"
            Case &HAA64US
                Return "ARM64"
            Case Else
                Return "0x" & machine.ToString("X4")
        End Select
    End Function

    Private Shared Function SubsystemToText(subsystem As UShort) As String
        Select Case subsystem
            Case 2US
                Return "Windows GUI"
            Case 3US
                Return "Windows Console"
            Case 1US
                Return "Native"
            Case 9US
                Return "Windows CE"
            Case 10US
                Return "EFI Application"
            Case Else
                Return "0x" & subsystem.ToString("X4")
        End Select
    End Function

    Private Shared Function TimeStampToText(timeStamp As UInteger) As String
        If timeStamp = 0UI Then Return "0"
        Try
            Dim epoch As New DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            Return epoch.AddSeconds(timeStamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Catch ex As Exception
            Return timeStamp.ToString()
        End Try
    End Function
End Class
