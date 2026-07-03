Imports System
Imports System.Windows.Forms

Public Class Form1

    Private Const VaxdWebsiteUrl As String = "https://vma-broadcast.com/vaxd-vma-executable-disassembler/"

    Private _currentResult As SecurityScanResult

    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        dgvFindings.Rows.Clear()
        rtbReport.Text = "Select an EXE/DLL file, or drag and drop one file onto this window." & Environment.NewLine & Environment.NewLine &
                         "The scanner performs local static analysis only:" & Environment.NewLine &
                         "- hashes" & Environment.NewLine &
                         "- PE headers and sections" & Environment.NewLine &
                         "- import table behaviour classification" & Environment.NewLine &
                         "- strings and suspicious paths/URLs" & Environment.NewLine &
                         "- VAXD-style XREF JSON export - " & VaxdWebsiteUrl & Environment.NewLine & Environment.NewLine &
                         "VMA Behaviour Scanner does not execute, upload, delete or quarantine files."

        rtbReport.DetectUrls = True

        Dim args As String() = Environment.GetCommandLineArgs()
        For argIndex As Integer = 0 To args.Length - 1
            If args(argIndex).Equals("--file", StringComparison.OrdinalIgnoreCase) AndAlso argIndex + 1 < args.Length Then
                txtFilePath.Text = args(argIndex + 1)
                Exit For
            End If
        Next

        If txtFilePath.TextLength > 0 AndAlso System.IO.File.Exists(txtFilePath.Text) Then
            ScanSelectedFile()
        End If
    End Sub

    Private Sub Form1_DragEnter(sender As Object, e As DragEventArgs) Handles MyBase.DragEnter, txtFilePath.DragEnter, dgvFindings.DragEnter, rtbReport.DragEnter, lblTitle.DragEnter, lblAssessment.DragEnter
        If HasDroppedFile(e) Then
            e.Effect = DragDropEffects.Copy
        Else
            e.Effect = DragDropEffects.None
        End If
    End Sub

    Private Sub Form1_DragDrop(sender As Object, e As DragEventArgs) Handles MyBase.DragDrop, txtFilePath.DragDrop, dgvFindings.DragDrop, rtbReport.DragDrop, lblTitle.DragDrop, lblAssessment.DragDrop
        Dim droppedFilePath As String = GetFirstDroppedFilePath(e)

        If String.IsNullOrEmpty(droppedFilePath) Then
            MessageBox.Show(Me, "Please drop one file, not a folder.", "Invalid drop", MessageBoxButtons.OK, MessageBoxIcon.Information)
            Return
        End If

        txtFilePath.Text = droppedFilePath
        ScanSelectedFile()
    End Sub

    Private Function HasDroppedFile(e As DragEventArgs) As Boolean
        If e Is Nothing OrElse e.Data Is Nothing Then Return False
        If Not e.Data.GetDataPresent(DataFormats.FileDrop) Then Return False

        Dim droppedFilePaths As String() = TryCast(e.Data.GetData(DataFormats.FileDrop), String())
        If droppedFilePaths Is Nothing OrElse droppedFilePaths.Length = 0 Then Return False

        For Each droppedPath As String In droppedFilePaths
            If Not String.IsNullOrWhiteSpace(droppedPath) AndAlso System.IO.File.Exists(droppedPath) Then
                Return True
            End If
        Next

        Return False
    End Function

    Private Function GetFirstDroppedFilePath(e As DragEventArgs) As String
        If e Is Nothing OrElse e.Data Is Nothing Then Return ""
        If Not e.Data.GetDataPresent(DataFormats.FileDrop) Then Return ""

        Dim droppedFilePaths As String() = TryCast(e.Data.GetData(DataFormats.FileDrop), String())
        If droppedFilePaths Is Nothing OrElse droppedFilePaths.Length = 0 Then Return ""

        For Each droppedPath As String In droppedFilePaths
            If Not String.IsNullOrWhiteSpace(droppedPath) AndAlso System.IO.File.Exists(droppedPath) Then
                Return droppedPath
            End If
        Next

        Return ""
    End Function

    Private Sub rtbReport_LinkClicked(sender As Object, e As LinkClickedEventArgs) Handles rtbReport.LinkClicked
        If e Is Nothing OrElse String.IsNullOrWhiteSpace(e.LinkText) Then Return

        Try
            Dim startInfoItem As New System.Diagnostics.ProcessStartInfo()
            startInfoItem.FileName = e.LinkText
            startInfoItem.UseShellExecute = True
            System.Diagnostics.Process.Start(startInfoItem)
        Catch ex As Exception
            MessageBox.Show(Me, "Could not open the link:" & Environment.NewLine & e.LinkText, "Open link failed", MessageBoxButtons.OK, MessageBoxIcon.Warning)
        End Try
    End Sub

    Private Sub btnBrowse_Click(sender As Object, e As EventArgs) Handles btnBrowse.Click
        Using dialogItem As New OpenFileDialog()
            dialogItem.Title = "Select file to analyse"
            dialogItem.Filter = "Executable files (*.exe;*.dll;*.sys;*.scr;*.ocx;*.cpl)|*.exe;*.dll;*.sys;*.scr;*.ocx;*.cpl|All files (*.*)|*.*"
            dialogItem.CheckFileExists = True
            dialogItem.Multiselect = False

            If dialogItem.ShowDialog(Me) = DialogResult.OK Then
                txtFilePath.Text = dialogItem.FileName
            End If
        End Using
    End Sub

    Private Sub btnScan_Click(sender As Object, e As EventArgs) Handles btnScan.Click
        ScanSelectedFile()
    End Sub

    Private Sub btnCopyReport_Click(sender As Object, e As EventArgs) Handles btnCopyReport.Click
        If String.IsNullOrEmpty(rtbReport.Text) Then Return
        Clipboard.SetText(rtbReport.Text)
    End Sub

    Private Sub btnSaveText_Click(sender As Object, e As EventArgs) Handles btnSaveText.Click
        If _currentResult Is Nothing Then
            MessageBox.Show(Me, "Scan a file first.", "No report", MessageBoxButtons.OK, MessageBoxIcon.Information)
            Return
        End If

        Using dialogItem As New SaveFileDialog()
            dialogItem.Title = "Save text report"
            dialogItem.Filter = "Text report (*.txt)|*.txt|All files (*.*)|*.*"
            dialogItem.FileName = BuildDefaultOutputFileName("_security_report.txt")
            If dialogItem.ShowDialog(Me) = DialogResult.OK Then
                ReportWriter.SaveTextReport(_currentResult, dialogItem.FileName)
            End If
        End Using
    End Sub

    Private Sub btnSaveJson_Click(sender As Object, e As EventArgs) Handles btnSaveJson.Click
        If _currentResult Is Nothing Then
            MessageBox.Show(Me, "Scan a file first.", "No xref data", MessageBoxButtons.OK, MessageBoxIcon.Information)
            Return
        End If

        Using dialogItem As New SaveFileDialog()
            dialogItem.Title = "Save VAXD xref JSON"
            dialogItem.Filter = "VAXD security xref (*.json)|*.json|All files (*.*)|*.*"
            dialogItem.FileName = BuildDefaultOutputFileName("_security_xrefs.json")
            If dialogItem.ShowDialog(Me) = DialogResult.OK Then
                ReportWriter.SaveXrefJson(_currentResult, dialogItem.FileName)
            End If
        End Using
    End Sub

    Private Function BuildDefaultOutputFileName(suffixText As String) As String
        If _currentResult Is Nothing OrElse String.IsNullOrEmpty(_currentResult.TargetFilePath) Then Return "report" & suffixText
        Dim baseLabel As String = System.IO.Path.GetFileNameWithoutExtension(_currentResult.TargetFilePath)
        If String.IsNullOrEmpty(baseLabel) Then baseLabel = "report"
        Return baseLabel & suffixText
    End Function

    Private Sub ScanSelectedFile()
        Dim selectedFilePath As String = txtFilePath.Text.Trim()
        If String.IsNullOrEmpty(selectedFilePath) Then
            MessageBox.Show(Me, "Please select one file first.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information)
            Return
        End If

        If Not System.IO.File.Exists(selectedFilePath) Then
            MessageBox.Show(Me, "The selected file does not exist.", "File not found", MessageBoxButtons.OK, MessageBoxIcon.Warning)
            Return
        End If

        Try
            UseWaitCursor = True
            btnScan.Enabled = False
            lblAssessment.Text = "Scanning locally..."
            dgvFindings.Rows.Clear()
            rtbReport.Clear()
            Application.DoEvents()

            Dim engine As New ScanEngine()
            _currentResult = engine.ScanFile(selectedFilePath)
            DisplayResult(_currentResult)
        Catch ex As Exception
            MessageBox.Show(Me, ex.Message, "Scan failed", MessageBoxButtons.OK, MessageBoxIcon.Error)
        Finally
            btnScan.Enabled = True
            UseWaitCursor = False
        End Try
    End Sub

    Private Sub DisplayResult(result As SecurityScanResult)
        dgvFindings.Rows.Clear()
        For Each indicatorItem As BehaviourIndicator In result.Indicators
            Dim rvaText As String = If(indicatorItem.Rva.HasValue, "0x" & indicatorItem.Rva.Value.ToString("X"), "")
            Dim offsetText As String = If(indicatorItem.FileOffset.HasValue, "0x" & indicatorItem.FileOffset.Value.ToString("X"), "")
            dgvFindings.Rows.Add(indicatorItem.Level.ToString(), indicatorItem.Category.ToString(), indicatorItem.Title, indicatorItem.Evidence, rvaText, offsetText)
        Next

        lblAssessment.Text = result.AssessmentLabel & " | Score: " & result.TotalScore.ToString() & " | Findings: " & result.Indicators.Count.ToString()
        rtbReport.Text = ReportWriter.BuildTextReport(result)
    End Sub
End Class
