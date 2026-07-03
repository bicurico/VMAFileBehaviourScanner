Imports System
Imports System.Text
Imports System.Web.Script.Serialization

Public Class ReportWriter

    Public Shared Function BuildTextReport(result As SecurityScanResult) As String
        Dim builder As New StringBuilder()
        builder.AppendLine("VMA File Behaviour Scanner Report")
        builder.AppendLine("================================")
        builder.AppendLine()
        builder.AppendLine("This is a static behaviour report. It is not a malware verdict.")
        builder.AppendLine("No file upload, execution, deletion or quarantine was performed.")
        builder.AppendLine()
        builder.AppendLine("File: " & result.TargetFilePath)
        builder.AppendLine("Size: " & result.FileSize.ToString() & " bytes")
        builder.AppendLine("MD5: " & result.Md5)
        builder.AppendLine("SHA256: " & result.Sha256)
        builder.AppendLine("Entropy: " & result.FileEntropy.ToString("0.00"))
        builder.AppendLine("Assessment: " & result.AssessmentLabel)
        builder.AppendLine("Score: " & result.TotalScore.ToString())
        builder.AppendLine()

        If result.PeDetails IsNot Nothing AndAlso result.PeDetails.IsPe Then
            builder.AppendLine("PE details")
            builder.AppendLine("----------")
            builder.AppendLine("Machine: " & result.PeDetails.MachineLabel)
            builder.AppendLine("Subsystem: " & result.PeDetails.SubsystemLabel)
            builder.AppendLine("Timestamp: " & result.PeDetails.TimeDateStampText)
            builder.AppendLine("Entry point RVA: 0x" & result.PeDetails.EntryPointRva.ToString("X"))
            builder.AppendLine("Image base: 0x" & result.PeDetails.ImageBase.ToString("X"))
            builder.AppendLine(".NET: " & If(result.PeDetails.IsDotNet, "Yes", "No"))
            builder.AppendLine()

            builder.AppendLine("Sections")
            builder.AppendLine("--------")
            For Each sectionItem As PeSectionInfo In result.PeDetails.Sections
                builder.AppendLine(sectionItem.SectionLabel & " | RVA 0x" & sectionItem.VirtualAddress.ToString("X") & " | Raw 0x" & sectionItem.RawPointer.ToString("X") & " | Entropy " & sectionItem.Entropy.ToString("0.00") & " | Exec " & sectionItem.IsExecutable.ToString() & " | Write " & sectionItem.IsWritable.ToString())
            Next
            builder.AppendLine()
        End If

        builder.AppendLine("Findings")
        builder.AppendLine("--------")
        If result.Indicators.Count = 0 Then
            builder.AppendLine("No indicators found.")
        Else
            For Each indicatorItem As BehaviourIndicator In result.Indicators
                builder.AppendLine("[" & indicatorItem.Level.ToString() & "] " & indicatorItem.Category.ToString() & " - " & indicatorItem.Title)
                If Not String.IsNullOrEmpty(indicatorItem.Evidence) Then builder.AppendLine("Evidence: " & indicatorItem.Evidence)
                If Not String.IsNullOrEmpty(indicatorItem.ApiLabel) Then builder.AppendLine("API: " & indicatorItem.ApiLabel)
                If indicatorItem.Rva.HasValue Then builder.AppendLine("RVA: 0x" & indicatorItem.Rva.Value.ToString("X"))
                If indicatorItem.FileOffset.HasValue Then builder.AppendLine("File offset: 0x" & indicatorItem.FileOffset.Value.ToString("X"))
                builder.AppendLine("Meaning: " & indicatorItem.Description)
                builder.AppendLine("Score: " & indicatorItem.Score.ToString())
                builder.AppendLine()
            Next
        End If

        builder.AppendLine("VAXD note")
        builder.AppendLine("---------")
        builder.AppendLine("Use the JSON xref export to import flagged offsets/RVAs into VAXD or to manually jump to suspicious locations.")
        Return builder.ToString()
    End Function

    Public Shared Function BuildXrefJson(result As SecurityScanResult) As String
        Dim documentItem As New VaxdXrefDocument()
        documentItem.TargetFile = result.TargetFilePath
        documentItem.Sha256 = result.Sha256

        For Each indicatorItem As BehaviourIndicator In result.Indicators
            If indicatorItem.Level = SuspicionLevel.Info Then Continue For
            Dim xrefItem As New VaxdXrefItem()
            xrefItem.Severity = indicatorItem.Level.ToString()
            xrefItem.Category = indicatorItem.Category.ToString()
            xrefItem.Title = indicatorItem.Title
            xrefItem.Evidence = indicatorItem.Evidence
            xrefItem.Api = indicatorItem.ApiLabel
            xrefItem.Rva = If(indicatorItem.Rva.HasValue, indicatorItem.Rva.Value.ToString("X"), Nothing)
            xrefItem.FileOffset = If(indicatorItem.FileOffset.HasValue, indicatorItem.FileOffset.Value.ToString("X"), Nothing)
            xrefItem.SuggestedAction = "Review this finding in VAXD or another disassembler. Static indicators are not proof of malware."
            documentItem.Findings.Add(xrefItem)
        Next

        Dim serializer As New JavaScriptSerializer()
        serializer.MaxJsonLength = Integer.MaxValue
        Return serializer.Serialize(documentItem)
    End Function

    Public Shared Sub SaveTextReport(result As SecurityScanResult, filePath As String)
        System.IO.File.WriteAllText(filePath, BuildTextReport(result), Encoding.UTF8)
    End Sub

    Public Shared Sub SaveXrefJson(result As SecurityScanResult, filePath As String)
        System.IO.File.WriteAllText(filePath, BuildXrefJson(result), Encoding.UTF8)
    End Sub
End Class
