<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()>
Partial Class Form1
    Inherits System.Windows.Forms.Form

    <System.Diagnostics.DebuggerNonUserCode()>
    Protected Overrides Sub Dispose(disposing As Boolean)
        Try
            If disposing AndAlso components IsNot Nothing Then
                components.Dispose()
            End If
        Finally
            MyBase.Dispose(disposing)
        End Try
    End Sub

    Private components As System.ComponentModel.IContainer

    <System.Diagnostics.DebuggerStepThrough()>
    Private Sub InitializeComponent()
        Dim resources As System.ComponentModel.ComponentResourceManager = New System.ComponentModel.ComponentResourceManager(GetType(Form1))
        Me.lblTitle = New System.Windows.Forms.Label()
        Me.txtFilePath = New System.Windows.Forms.TextBox()
        Me.btnBrowse = New System.Windows.Forms.Button()
        Me.btnScan = New System.Windows.Forms.Button()
        Me.lblAssessment = New System.Windows.Forms.Label()
        Me.dgvFindings = New System.Windows.Forms.DataGridView()
        Me.colLevel = New System.Windows.Forms.DataGridViewTextBoxColumn()
        Me.colCategory = New System.Windows.Forms.DataGridViewTextBoxColumn()
        Me.colTitle = New System.Windows.Forms.DataGridViewTextBoxColumn()
        Me.colEvidence = New System.Windows.Forms.DataGridViewTextBoxColumn()
        Me.colRva = New System.Windows.Forms.DataGridViewTextBoxColumn()
        Me.colOffset = New System.Windows.Forms.DataGridViewTextBoxColumn()
        Me.rtbReport = New System.Windows.Forms.RichTextBox()
        Me.btnCopyReport = New System.Windows.Forms.Button()
        Me.btnSaveText = New System.Windows.Forms.Button()
        Me.btnSaveJson = New System.Windows.Forms.Button()
        CType(Me.dgvFindings, System.ComponentModel.ISupportInitialize).BeginInit()
        Me.SuspendLayout()
        '
        'lblTitle
        '
        Me.lblTitle.AllowDrop = True
        Me.lblTitle.AutoSize = True
        Me.lblTitle.Font = New System.Drawing.Font("Segoe UI", 14.0!, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, CType(0, Byte))
        Me.lblTitle.Location = New System.Drawing.Point(12, 9)
        Me.lblTitle.Name = "lblTitle"
        Me.lblTitle.Size = New System.Drawing.Size(263, 25)
        Me.lblTitle.TabIndex = 0
        Me.lblTitle.Text = "VMA File Behaviour Scanner"
        '
        'txtFilePath
        '
        Me.txtFilePath.AllowDrop = True
        Me.txtFilePath.Anchor = CType(((System.Windows.Forms.AnchorStyles.Top Or System.Windows.Forms.AnchorStyles.Left) _
            Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.txtFilePath.Location = New System.Drawing.Point(17, 46)
        Me.txtFilePath.Name = "txtFilePath"
        Me.txtFilePath.Size = New System.Drawing.Size(794, 23)
        Me.txtFilePath.TabIndex = 1
        '
        'btnBrowse
        '
        Me.btnBrowse.Anchor = CType((System.Windows.Forms.AnchorStyles.Top Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.btnBrowse.Location = New System.Drawing.Point(817, 45)
        Me.btnBrowse.Name = "btnBrowse"
        Me.btnBrowse.Size = New System.Drawing.Size(89, 25)
        Me.btnBrowse.TabIndex = 2
        Me.btnBrowse.Text = "Browse..."
        Me.btnBrowse.UseVisualStyleBackColor = True
        '
        'btnScan
        '
        Me.btnScan.Anchor = CType((System.Windows.Forms.AnchorStyles.Top Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.btnScan.Location = New System.Drawing.Point(912, 45)
        Me.btnScan.Name = "btnScan"
        Me.btnScan.Size = New System.Drawing.Size(89, 25)
        Me.btnScan.TabIndex = 3
        Me.btnScan.Text = "Scan file"
        Me.btnScan.UseVisualStyleBackColor = True
        '
        'lblAssessment
        '
        Me.lblAssessment.AllowDrop = True
        Me.lblAssessment.Anchor = CType(((System.Windows.Forms.AnchorStyles.Top Or System.Windows.Forms.AnchorStyles.Left) _
            Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.lblAssessment.Font = New System.Drawing.Font("Segoe UI", 10.0!, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, CType(0, Byte))
        Me.lblAssessment.Location = New System.Drawing.Point(17, 82)
        Me.lblAssessment.Name = "lblAssessment"
        Me.lblAssessment.Size = New System.Drawing.Size(984, 23)
        Me.lblAssessment.TabIndex = 4
        Me.lblAssessment.Text = "Select one EXE/DLL file or drag and drop one file here."
        '
        'dgvFindings
        '
        Me.dgvFindings.AllowDrop = True
        Me.dgvFindings.AllowUserToAddRows = False
        Me.dgvFindings.AllowUserToDeleteRows = False
        Me.dgvFindings.Anchor = CType((((System.Windows.Forms.AnchorStyles.Top Or System.Windows.Forms.AnchorStyles.Bottom) _
            Or System.Windows.Forms.AnchorStyles.Left) _
            Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.dgvFindings.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize
        Me.dgvFindings.Columns.AddRange(New System.Windows.Forms.DataGridViewColumn() {Me.colLevel, Me.colCategory, Me.colTitle, Me.colEvidence, Me.colRva, Me.colOffset})
        Me.dgvFindings.Location = New System.Drawing.Point(17, 108)
        Me.dgvFindings.MultiSelect = False
        Me.dgvFindings.Name = "dgvFindings"
        Me.dgvFindings.ReadOnly = True
        Me.dgvFindings.RowHeadersVisible = False
        Me.dgvFindings.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect
        Me.dgvFindings.Size = New System.Drawing.Size(984, 265)
        Me.dgvFindings.TabIndex = 5
        '
        'colLevel
        '
        Me.colLevel.HeaderText = "Severity"
        Me.colLevel.Name = "colLevel"
        Me.colLevel.ReadOnly = True
        Me.colLevel.Width = 80
        '
        'colCategory
        '
        Me.colCategory.HeaderText = "Category"
        Me.colCategory.Name = "colCategory"
        Me.colCategory.ReadOnly = True
        Me.colCategory.Width = 120
        '
        'colTitle
        '
        Me.colTitle.HeaderText = "Finding"
        Me.colTitle.Name = "colTitle"
        Me.colTitle.ReadOnly = True
        Me.colTitle.Width = 220
        '
        'colEvidence
        '
        Me.colEvidence.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.Fill
        Me.colEvidence.HeaderText = "Evidence"
        Me.colEvidence.Name = "colEvidence"
        Me.colEvidence.ReadOnly = True
        '
        'colRva
        '
        Me.colRva.HeaderText = "RVA"
        Me.colRva.Name = "colRva"
        Me.colRva.ReadOnly = True
        Me.colRva.Width = 90
        '
        'colOffset
        '
        Me.colOffset.HeaderText = "File offset"
        Me.colOffset.Name = "colOffset"
        Me.colOffset.ReadOnly = True
        Me.colOffset.Width = 90
        '
        'rtbReport
        '
        Me.rtbReport.AllowDrop = True
        Me.rtbReport.Anchor = CType(((System.Windows.Forms.AnchorStyles.Bottom Or System.Windows.Forms.AnchorStyles.Left) _
            Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.rtbReport.DetectUrls = True
        Me.rtbReport.Font = New System.Drawing.Font("Consolas", 9.0!, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, CType(0, Byte))
        Me.rtbReport.Location = New System.Drawing.Point(17, 379)
        Me.rtbReport.Name = "rtbReport"
        Me.rtbReport.ReadOnly = True
        Me.rtbReport.Size = New System.Drawing.Size(984, 216)
        Me.rtbReport.TabIndex = 6
        Me.rtbReport.Text = ""
        '
        'btnCopyReport
        '
        Me.btnCopyReport.Anchor = CType((System.Windows.Forms.AnchorStyles.Bottom Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.btnCopyReport.Location = New System.Drawing.Point(664, 604)
        Me.btnCopyReport.Name = "btnCopyReport"
        Me.btnCopyReport.Size = New System.Drawing.Size(107, 28)
        Me.btnCopyReport.TabIndex = 7
        Me.btnCopyReport.Text = "Copy report"
        Me.btnCopyReport.UseVisualStyleBackColor = True
        '
        'btnSaveText
        '
        Me.btnSaveText.Anchor = CType((System.Windows.Forms.AnchorStyles.Bottom Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.btnSaveText.Location = New System.Drawing.Point(777, 604)
        Me.btnSaveText.Name = "btnSaveText"
        Me.btnSaveText.Size = New System.Drawing.Size(107, 28)
        Me.btnSaveText.TabIndex = 8
        Me.btnSaveText.Text = "Save TXT"
        Me.btnSaveText.UseVisualStyleBackColor = True
        '
        'btnSaveJson
        '
        Me.btnSaveJson.Anchor = CType((System.Windows.Forms.AnchorStyles.Bottom Or System.Windows.Forms.AnchorStyles.Right), System.Windows.Forms.AnchorStyles)
        Me.btnSaveJson.Location = New System.Drawing.Point(890, 604)
        Me.btnSaveJson.Name = "btnSaveJson"
        Me.btnSaveJson.Size = New System.Drawing.Size(111, 28)
        Me.btnSaveJson.TabIndex = 9
        Me.btnSaveJson.Text = "Save XREF JSON"
        Me.btnSaveJson.UseVisualStyleBackColor = True
        '
        'Form1
        '
        Me.AllowDrop = True
        Me.AutoScaleDimensions = New System.Drawing.SizeF(7.0!, 15.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.ClientSize = New System.Drawing.Size(1018, 644)
        Me.Controls.Add(Me.btnSaveJson)
        Me.Controls.Add(Me.btnSaveText)
        Me.Controls.Add(Me.btnCopyReport)
        Me.Controls.Add(Me.rtbReport)
        Me.Controls.Add(Me.dgvFindings)
        Me.Controls.Add(Me.lblAssessment)
        Me.Controls.Add(Me.btnScan)
        Me.Controls.Add(Me.btnBrowse)
        Me.Controls.Add(Me.txtFilePath)
        Me.Controls.Add(Me.lblTitle)
        Me.Font = New System.Drawing.Font("Segoe UI", 9.0!, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, CType(0, Byte))
        Me.Icon = CType(resources.GetObject("$this.Icon"), System.Drawing.Icon)
        Me.MinimumSize = New System.Drawing.Size(900, 600)
        Me.Name = "Form1"
        Me.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen
        Me.Text = "VMA File Behaviour Scanner"
        CType(Me.dgvFindings, System.ComponentModel.ISupportInitialize).EndInit()
        Me.ResumeLayout(False)
        Me.PerformLayout()

    End Sub

    Friend WithEvents lblTitle As System.Windows.Forms.Label
    Friend WithEvents txtFilePath As System.Windows.Forms.TextBox
    Friend WithEvents btnBrowse As System.Windows.Forms.Button
    Friend WithEvents btnScan As System.Windows.Forms.Button
    Friend WithEvents lblAssessment As System.Windows.Forms.Label
    Friend WithEvents dgvFindings As System.Windows.Forms.DataGridView
    Friend WithEvents colLevel As System.Windows.Forms.DataGridViewTextBoxColumn
    Friend WithEvents colCategory As System.Windows.Forms.DataGridViewTextBoxColumn
    Friend WithEvents colTitle As System.Windows.Forms.DataGridViewTextBoxColumn
    Friend WithEvents colEvidence As System.Windows.Forms.DataGridViewTextBoxColumn
    Friend WithEvents colRva As System.Windows.Forms.DataGridViewTextBoxColumn
    Friend WithEvents colOffset As System.Windows.Forms.DataGridViewTextBoxColumn
    Friend WithEvents rtbReport As System.Windows.Forms.RichTextBox
    Friend WithEvents btnCopyReport As System.Windows.Forms.Button
    Friend WithEvents btnSaveText As System.Windows.Forms.Button
    Friend WithEvents btnSaveJson As System.Windows.Forms.Button
End Class
