
' ══════════════════════════════════════════════════════════════════════════
' SAMICIOUS MICROFINANCE V9 — VBA AUTOMATION
' NEW IN V9:
'   - Customer Account Database: formula-driven auto-populate (NO save trigger)
'   - Search: Account Number ONLY
'   - GenerateAccount: writes to DB_Customers, triggers formula refresh
' HOW TO USE:
'   1. Alt+F11 → Insert → Module → paste ALL code below
'   2. Paste ThisWorkbook code into ThisWorkbook object
' ══════════════════════════════════════════════════════════════════════════

Option Explicit

' ─── ACCOUNT NUMBER GENERATION ────────────────────────────────────────────
Function GenAcctNo() As String
    Dim fn As String, yr As String, ph As String
    Dim ws As Worksheet: Set ws = ThisWorkbook.Sheets("Account_Opening")
    fn = UCase(Left(Trim(ws.Range("C5").Value), 3))
    If IsDate(ws.Range("C7").Value) Then
        yr = Format(Year(CDate(ws.Range("C7").Value)), "0000")
    ElseIf Len(Trim(ws.Range("C7").Value)) >= 4 Then
        yr = Left(Trim(ws.Range("C7").Value), 4)
    Else
        yr = Format(Year(Date), "0000")
    End If
    ph = Right(Trim(ws.Range("C8").Value), 4)
    GenAcctNo = fn & yr & ph
End Function

' ─── GENERATE ACCOUNT (writes to DB_Customers + Audit_Log) ──────────────
Sub GenerateAccount()
    Dim wsForm As Worksheet, wsDB As Worksheet, wsAudit As Worksheet
    Dim nextRow As Long, accNum As String

    On Error GoTo ErrHandler
    Set wsForm  = ThisWorkbook.Sheets("Account_Opening")
    Set wsDB    = ThisWorkbook.Sheets("DB_Customers")
    Set wsAudit = ThisWorkbook.Sheets("Audit_Log")

    ' Validate required fields
    If Trim(wsForm.Range("C5").Value) = "" Then MsgBox "First Name required.", vbExclamation: Exit Sub
    If Trim(wsForm.Range("C6").Value) = "" Then MsgBox "Last Name required.", vbExclamation: Exit Sub
    If Trim(wsForm.Range("C7").Value) = "" Then MsgBox "Date of Birth required.", vbExclamation: Exit Sub
    If Trim(wsForm.Range("C8").Value) = "" Then MsgBox "Phone Number required.", vbExclamation: Exit Sub
    If Trim(wsForm.Range("C9").Value) = "" Then MsgBox "Location required.", vbExclamation: Exit Sub
    If Trim(wsForm.Range("C10").Value) = "" Then MsgBox "Occupation required.", vbExclamation: Exit Sub
    If Trim(wsForm.Range("C11").Value) = "" Then MsgBox "Agent required.", vbExclamation: Exit Sub
    If Not IsNumeric(wsForm.Range("C12").Value) Or CDbl(wsForm.Range("C12").Value) < 10 Then
        MsgBox "Opening balance must be at least GHC 10.00.", vbExclamation: Exit Sub
    End If

    accNum = Trim(wsForm.Range("C16").Value)
    If accNum = "" Then accNum = GenAcctNo()

    ' Duplicate check
    If Application.CountIf(wsDB.Columns(1), accNum) > 0 Then
        MsgBox "DUPLICATE: " & accNum & " already exists.", vbCritical: Exit Sub
    End If

    ' Find next empty DB row (headers row 3, data from row 4)
    nextRow = wsDB.Cells(wsDB.Rows.Count, 1).End(xlUp).Row + 1
    If nextRow < 4 Then nextRow = 4

    ' Write to DB_Customers
    With wsDB
        .Cells(nextRow, 1)  = accNum                              ' Account_No
        .Cells(nextRow, 2)  = Trim(wsForm.Range("C5").Value)     ' First_Name
        .Cells(nextRow, 3)  = Trim(wsForm.Range("C6").Value)     ' Last_Name
        .Cells(nextRow, 4)  = Trim(wsForm.Range("C5")) & " " & Trim(wsForm.Range("C6")) ' Full_Name
        .Cells(nextRow, 5)  = Trim(wsForm.Range("C14").Value)    ' ID_Card_Type
        .Cells(nextRow, 6)  = Trim(wsForm.Range("C15").Value)    ' ID_Number
        .Cells(nextRow, 7)  = Trim(wsForm.Range("C10").Value)    ' Occupation
        .Cells(nextRow, 8)  = Trim(wsForm.Range("C11").Value)    ' Agent_Assigned
        .Cells(nextRow, 9)  = CDbl(wsForm.Range("C12").Value)    ' Opening_Balance
        .Cells(nextRow, 10) = Date                                ' Account_Date
        .Cells(nextRow, 11) = "Active"                            ' Status
        ' Cols 12-16 (L-P): formula-driven (SUMIF etc) — leave blank for formula rows
        .Cells(nextRow, 17) = wsForm.Range("C7").Value           ' Date_of_Birth (Q)
        .Cells(nextRow, 18) = Trim(wsForm.Range("C8").Value)     ' Phone (R)
        .Cells(nextRow, 19) = Trim(wsForm.Range("C9").Value)     ' Location (S)
        .Cells(nextRow, 20) = Trim(wsForm.Range("C13").Value)    ' Next_of_Kin (T)
        ' Format dates
        .Cells(nextRow, 10).NumberFormat = "DD/MM/YYYY"
        .Cells(nextRow, 17).NumberFormat = "DD/MM/YYYY"
        .Cells(nextRow, 9).NumberFormat  = "#,##0.00"
        ' Extend formulas for financial columns L-P
        If nextRow > 4 Then
            .Cells(nextRow, 12).Formula = "=SUMIF(DB_Savings!$C:$C,A" & nextRow & ",DB_Savings!$F:$F)"
            .Cells(nextRow, 13).Formula = "=SUMIF(DB_Withdrawals!$C:$C,A" & nextRow & ",DB_Withdrawals!$G:$G)"
            .Cells(nextRow, 14).Formula = "=I" & nextRow & "+L" & nextRow & "-M" & nextRow
            .Cells(nextRow, 15).Formula = "=TRUE()"
            .Cells(nextRow, 16).Formula = "=MAX(0,N" & nextRow & "-System_Config!$B$9)"
        End If
    End With

    ' Audit Log entry
    Dim auditRow As Long
    auditRow = wsAudit.Cells(wsAudit.Rows.Count, 1).End(xlUp).Row + 1
    If auditRow < 2 Then auditRow = 2
    wsAudit.Cells(auditRow, 1) = Now()
    wsAudit.Cells(auditRow, 2) = "ACCOUNT CREATED"
    wsAudit.Cells(auditRow, 3) = accNum
    wsAudit.Cells(auditRow, 4) = Trim(wsForm.Range("C5")) & " " & Trim(wsForm.Range("C6"))
    wsAudit.Cells(auditRow, 5) = Trim(wsForm.Range("C11").Value)
    wsAudit.Cells(auditRow, 6) = "Account opened with balance GHC " & wsForm.Range("C12").Value
    wsAudit.Cells(auditRow, 1).NumberFormat = "DD/MM/YYYY HH:MM:SS"

    ' Clear form
    Dim clearList As Variant
    clearList = Array("C5","C6","C7","C8","C9","C10","C11","C12","C13","C14","C15","C38","C43")
    Dim f As Variant
    For Each f In clearList
        wsForm.Range(CStr(f)).ClearContents
    Next f

    ' Force recalculate so CAD formulas refresh
    Application.Calculate

    MsgBox "✅ Account " & accNum & " committed to database." & Chr(13) & _
           "Form cleared. Customer Database updated instantly.", vbInformation, "Account Created"
    Exit Sub
ErrHandler:
    MsgBox "Error " & Err.Number & ": " & Err.Description, vbCritical, "Error"
End Sub

' ─── THISWORKBOOK CODE (paste into ThisWorkbook object) ─────────────────
' Private Sub Workbook_Open()
'     Application.ScreenUpdating = False
'     ThisWorkbook.Sheets("Manager_Dashboard").Activate
'     Application.ScreenUpdating = True
' End Sub

' ─── SEARCH HELPER: called from Search button if added ──────────────────
Sub ClearSearch()
    ThisWorkbook.Sheets("Customer Account Database").Range("C5").ClearContents
    Application.Calculate
End Sub

' ─── MIN BALANCE GUARD (called from withdrawal sheets) ──────────────────
Sub CheckMinBalance(sheetName As String, transRow As Long)
    Dim ws As Worksheet: Set ws = ThisWorkbook.Sheets(sheetName)
    If Not IsNumeric(ws.Cells(transRow, 6).Value) Then Exit Sub
    If CDbl(ws.Cells(transRow, 6).Value) < 10 Then
        MsgBox "WITHDRAWAL BLOCKED" & Chr(13) & _
               "Balance after: GHC " & Format(ws.Cells(transRow,6).Value,"#,##0.00") & Chr(13) & _
               "Minimum balance is GHC 10.00", vbCritical, "Min Balance Violation"
        ws.Cells(transRow, 5).ClearContents
    End If
End Sub
