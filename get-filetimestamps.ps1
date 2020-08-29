# Modify the directory that you are looking at and the timestamps

# You must be in the directory you are evaluating...
$currentDirectory = "c:\windows"
$files = Get-ChildItem $currentDirectory
# Change the below line to look like the below if you want to recursively look at the files in a directory
#$files = Get-ChildItem $currentDirectory -Recurse
$startDate = Get-Date 2020-07-01
$endDate = Get-Date 2020-07-30

# Only outputs results where a creation time, last access time, and last write time are within the timeframe listed above
# Added the function to look at the MFT File Record for the file being examined.  If that time is within the timeframe it 
# is also captured...
#
# Looking at the MFT File Record will indicate time stomping...

Function Color-Text {
    param ( $inDate)
    If (($inDate -ge $startDate) -and ($inDate -le $endDate)) {
        Write-Host "$($inDate) " -ForegroundColor Yellow -NoNewline
    }
    Else {
        Write-Host "$($inDate) " -NoNewline
    }
}

Function Get-ChangeTime {
    # This function is from https://gallery.technet.microsoft.com/scriptcenter/Get-MFT-Timestamp-of-a-file-9227f399
    # Modified to work in this context.

    param ( $inFile )
    $FileStream = [System.IO.File]::Open($inFile, 'Open', 'Read', 'ReadWrite')
    #$FileStream

    #[void][ntdll]
    #region Module Builder
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TimeStampModule', $False)
    #endregion Module Builder

    #region ENUMs
    $EnumBuilder = $ModuleBuilder.DefineEnum('FileInformationClass', 'Public', [UInt32])
    # Define values of the enum
    [void]$EnumBuilder.DefineLiteral('FileDirectoryInformation', [UInt32] 1)
    [void]$EnumBuilder.DefineLiteral('FileBasicInformation', [UInt32] 4)
    [void]$EnumBuilder.DefineLiteral('FileModeInformation', [UInt32] 16)
    [void]$EnumBuilder.DefineLiteral('FileHardLinkInformation', [UInt32] 46)

    #Create ENUM Type
    [void]$EnumBuilder.CreateType()
    #endregion ENUMs

   
    #region FileBasicInformation
    #Define STRUCT
    $Attributes = 'AutoLayout, AnsiClass, Class, ExplicitLayout, Sealed, BeforeFieldInit,public'
    $TypeBuilder = $ModuleBuilder.DefineType('FileBasicInformation', $Attributes, [System.ValueType], 8, 0x28)
    $CreateTimeField = $TypeBuilder.DefineField('CreationTime', [UInt64], 'Public')
    $CreateTimeField.SetOffset(0)
    $LastAccessTimeField = $TypeBuilder.DefineField('LastAccessTime', [UInt64], 'Public')
    $LastAccessTimeField.SetOffset(8)
    $LastWriteTimeField = $TypeBuilder.DefineField('LastWriteTime', [UInt64], 'Public')
    $LastWriteTimeField.SetOffset(16)
    $ChangeTimeField = $TypeBuilder.DefineField('ChangeTime', [UInt64], 'Public')
    $ChangeTimeField.SetOffset(24)
    $FileAttributesField = $TypeBuilder.DefineField('FileAttributes', [UInt64], 'Public')
    $FileAttributesField.SetOffset(32)
    #Create STRUCT Type
    [void]$TypeBuilder.CreateType()
    #endregion FileBasicInformation

    #region IOStatusBlock
    #Define STRUCT
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('IOStatusBlock', $Attributes, [System.ValueType], 1, 0x10)
    [void]$TypeBuilder.DefineField('status', [UInt64], 'Public')
    [void]$TypeBuilder.DefineField('information', [UInt64], 'Public')
    #Create STRUCT Type
    [void]$TypeBuilder.CreateType()
    #endregion IOStatusBlock

    #region DllImport    $TypeBuilder = $ModuleBuilder.DefineType('ntdll', 'Public, Class')    #region NtQueryInformationFile Method    $PInvokeMethod = $TypeBuilder.DefineMethod(        'NtQueryInformationFile', #Method Name        [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes        [IntPtr], #Method Return Type        [Type[]] @([Microsoft.Win32.SafeHandles.SafeFileHandle], [IOStatusBlock], [IntPtr] ,[UInt16], [FileInformationClass]) #Method Parameters    )
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))    $FieldArray = [Reflection.FieldInfo[]] @(        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')    )
    $FieldValueArray = [Object[]] @(        'NtQueryInformationFile', #CASE SENSITIVE!!        $True    )
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(        $DllImportConstructor,        @('ntdll.dll'),        $FieldArray,        $FieldValueArray    )
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)    #endregion NtQueryInformationFile Method
    [void]$TypeBuilder.CreateType()    #endregion DllImport


    $fbi = New-Object "FileBasicInformation"
    $iosb = New-Object "IOStatusBlock"
    $p_fbi = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($fbi))
    
    # Pull file timestamps from file
    #[DllImport("ntdll.dll", SetLastError=$true)] 
    $iprc = [ntdll]::NtQueryInformationFile($FileStream.SafeFileHandle, $iosb, $p_fbi, 
        [System.Runtime.InteropServices.Marshal]::SizeOf($fbi), [FileInformationClass]::FileBasicInformation
    )

    

    # Check to make sure no issues occurred
    $IsOK = (($iprc -eq [intptr]::Zero) -AND ($iosb.status -eq 0))

    If ($IsOK) {
        # Pull data from unmanaged memory block into a usable object
        # The below line in the original document does notwork.  Add [System.Type] in the front and it works...
        # https://poshsecurity.com/blog/2014/2/3/powershell-error-the-specified-structure-must-be-blittable-o.html
        $fbi = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p_fbi, [System.Type][FileBasicInformation])
        #$Object = [pscustomobject]@{
        #    FullName = $FileStream.Name
        #    CreationTime = [datetime]::FromFileTime($fbi.CreationTime)
        #    LastAccessTime = [datetime]::FromFileTime($fbi.LastAccessTime)
        #    LastWriteTime = [datetime]::FromFileTime($fbi.LastWriteTime)
        #    ChangeTime = [datetime]::FromFileTime($fbi.ChangeTime)
        #}
        #$Object.PSTypeNames.Insert(0,'System.Io.FileTimeStamp')
        return [datetime]::FromFileTime($fbi.ChangeTime)
    } Else {
        return "$($Item): $(New-Object ComponentModel.Win32Exception)"
    }
    #region Perform Cleanup
    $FileStream.Close()
    # Deallocate memory
    If ($p_fbi -ne [intptr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($p_fbi)
    }

}


ForEach ($file in $files) {
    $creationTime = $file.CreationTime
    $lastAccessTime = $file.LastAccessTime
    $lastWriteTime = $file.LastWriteTime
    Try {
        If ($file.Attributes -notmatch 'Directory') {
            $changeTime = Get-ChangeTime -inFile $file.FullName
        }
        Else {
            # Arbitrary change time if one is not found by the function...
            $changeTime = (Get-Date).AddYears(-20)
        }
    }
    Catch {
        # Arbitrary change time if one is not found by the function...
        $changeTime = (Get-Date).AddYears(-20)
    }


    # Only output what matches the criteria above
    # If the MFT time of creation matches the timeframe it is output
    If ((($creationTime -ge $startDate) -and ($creationTime -le $endDate)) -or (($lastAccessTime -ge $startDate) -and ($lastAccessTime -le $endDate)) -or (($lastWriteTime -ge $startDate) -and ($lastWriteTime -le $endDate)) -or (($changeTime -ge $startDate) -and ($changeTime -le $endDate))) {
        Write-Host "-- File Information --"
        Write-Host "Name: " -NoNewLine  -ForegroundColor Green
        Write-Host "$($file.FullName)"
        Write-Host "Attributes: " -NoNewline -ForegroundColor Green
        Write-Host "$($file.Attributes)" 
        Write-Host "Length: " -NoNewline -ForegroundColor Green
        Write-Host "$($file.Length)"
        If ($file.Attributes -notmatch 'Directory') {
            $changeTime = Get-ChangeTime -inFile $file.FullName
            Write-Host "MFT Change Time: " -NoNewline -ForegroundColor Green
            Write-Host (Color-Text -inDate $changeTime)
        }
        Write-Host "Create: " -NoNewline -ForegroundColor Green
        Write-Host (Color-Text -inDate $creationTime) -NoNewline
        Write-Host "Last Access Time: " -NoNewline -ForegroundColor Green
        Write-Host (Color-Text -inDate $lastAccessTime) -NoNewline
        Write-Host "Last Write Time: " -NoNewline -ForegroundColor Green
        Write-Host (Color-Text -inDate $lastWriteTime)
        If ($file.Attributes -notmatch 'Directory') {
            $md5 = (Get-FileHash -LiteralPath $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            $sha1 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
            $sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            Write-Host "`r`n-- Hashes --"
            Write-Host "MD5: " -NoNewline -ForegroundColor Green
            Write-Host $md5 
            Write-Host "SHA1: " -NoNewline -ForegroundColor Green
            Write-Host $sha1
            Write-Host "SHA256: " -NoNewline -ForegroundColor Green
            Write-Host $sha256
            # Rewrite this section to silence the errors
            # If signature is not valid do not output to screen
            Write-Host "`r`n--Signature Information --"
            Write-Host "Issuer: " -NoNewline -ForegroundColor Green
            Write-Host ((Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction SilentlyContinue).SignerCertificate).Issuer
            Write-Host "Signature: " -NoNewline -ForegroundColor Green
            If ((Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction SilentlyContinue).Status -eq "Valid") {
                Write-Host "Valid" 
            }
            Else {
                Write-Host "Not Valid" -ForegroundColor Yellow
            }
            # Do Alternate Data Streams Exist
            $ads = Get-Item -Path $file -Stream *
            $adsCount = 0
            # Rewrite this to output in 1 line for a csv file...
            ForEach ($stream in $ads) {
                if ($stream.PSChildName -notmatch 'DATA') {
                    if ($adsCount -eq 0) {
                        Write-Host "`r`n-- Aternate Data Stream(s) Found --"
                    }
                    #How to quickly create an alternate data stream...
                    #Set-Content -Path d:\ -Value "Hello, World" -Stream Test
                    #Get-Content -Path d:\ -Stream Test
                    Write-Host "Alternate Data Stream: " -NoNewline -ForegroundColor Green
                    Write-Host $stream.PSChildName 
                    $adsCount += 1
                }
            }
        }
        Write-Host "`r`n`r`n"
    }
    
}