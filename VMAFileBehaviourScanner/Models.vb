Imports System
Imports System.Collections.Generic

Public Enum SuspicionLevel
    Info = 0
    Low = 1
    Medium = 2
    High = 3
    Severe = 4
End Enum

Public Enum BehaviourCategory
    FileIdentity = 0
    PeStructure = 1
    Registry = 2
    FileSystem = 3
    Network = 4
    ProcessExecution = 5
    ProcessInjection = 6
    Persistence = 7
    AntiDebug = 8
    AntiVm = 9
    Credentials = 10
    Crypto = 11
    Obfuscation = 12
    DotNet = 13
    Strings = 14
    ImportTable = 15
    Other = 99
End Enum

Public Class BehaviourIndicator
    Public Property Level As SuspicionLevel
    Public Property Category As BehaviourCategory
    Public Property Title As String
    Public Property Description As String
    Public Property Evidence As String
    Public Property ApiLabel As String
    Public Property SectionLabel As String
    Public Property Rva As Nullable(Of Long)
    Public Property FileOffset As Nullable(Of Long)
    Public Property Score As Integer
End Class

Public Class ExtractedStringInfo
    Public Property TextValue As String
    Public Property FileOffset As Long
    Public Property IsUnicode As Boolean
End Class

Public Class PeSectionInfo
    Public Property SectionLabel As String
    Public Property VirtualAddress As Long
    Public Property VirtualSize As Long
    Public Property RawPointer As Long
    Public Property RawSize As Long
    Public Property Characteristics As UInteger
    Public Property Entropy As Double

    Public ReadOnly Property IsExecutable As Boolean
        Get
            Return (Characteristics And &H20000000UI) <> 0UI
        End Get
    End Property

    Public ReadOnly Property IsWritable As Boolean
        Get
            Return (Characteristics And &H80000000UI) <> 0UI
        End Get
    End Property
End Class

Public Class ImportedApiInfo
    Public Property DllLabel As String
    Public Property ApiLabel As String
    Public Property ImportRva As Nullable(Of Long)
    Public Property ImportFileOffset As Nullable(Of Long)
    Public Property CallSiteRvas As New List(Of Long)()
    Public Property CallSiteFileOffsets As New List(Of Long)()
End Class

Public Class PeInfo
    Public Property IsPe As Boolean
    Public Property IsDotNet As Boolean
    Public Property MachineLabel As String
    Public Property SubsystemLabel As String
    Public Property TimeDateStampText As String
    Public Property EntryPointRva As Long
    Public Property ImageBase As Long
    Public Property SizeOfImage As Long
    Public Property SizeOfHeaders As Long
    Public Property OverlayOffset As Nullable(Of Long)
    Public Property Sections As New List(Of PeSectionInfo)()
    Public Property ImportedApis As New List(Of ImportedApiInfo)()
End Class

Public Class SecurityScanResult
    Public Property TargetFilePath As String
    Public Property FileSize As Long
    Public Property Md5 As String
    Public Property Sha256 As String
    Public Property FileEntropy As Double
    Public Property PeDetails As PeInfo
    Public Property ExtractedStrings As New List(Of ExtractedStringInfo)()
    Public Property Indicators As New List(Of BehaviourIndicator)()

    Public ReadOnly Property TotalScore As Integer
        Get
            Dim scoreTotal As Integer = 0
            For Each item As BehaviourIndicator In Indicators
                scoreTotal += item.Score
            Next
            Return scoreTotal
        End Get
    End Property

    Public ReadOnly Property AssessmentLabel As String
        Get
            If TotalScore >= 100 Then Return "Many static indicators - manual review strongly recommended"
            If TotalScore >= 70 Then Return "Highly suspicious static indicators"
            If TotalScore >= 40 Then Return "Suspicious static indicators"
            If TotalScore >= 20 Then Return "Mildly suspicious static indicators"
            If TotalScore > 0 Then Return "Low suspicion / weak static indicators"
            Return "No suspicious static indicators found"
        End Get
    End Property
End Class

Public Class VaxdXrefDocument
    Public Property Format As String = "VMA_SECURITY_XREFS"
    Public Property Version As Integer = 1
    Public Property TargetFile As String
    Public Property Sha256 As String
    Public Property Findings As New List(Of VaxdXrefItem)()
End Class

Public Class VaxdXrefItem
    Public Property Severity As String
    Public Property Category As String
    Public Property Title As String
    Public Property Evidence As String
    Public Property Api As String
    Public Property Rva As String
    Public Property FileOffset As String
    Public Property SuggestedAction As String
End Class
