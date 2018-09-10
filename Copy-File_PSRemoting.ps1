## Powershell For Penetration Testers Exam Task 6 - Transfer files over PowerShell Remoting
function CopyFilePSRemoting
{ 
<#
.SYNOPSIS
A cmdlet to transfer a file from local to the Remote machine

.DESCRIPTION
this script will allow to transfer a file from local to the Remote machine via PowerShell Remoting

.PARAMETER LocalFile
The localfile you want to transfer to the remote machine using PowerShell Remoting.

.PARAMETER Destination
The remote Destination Path using PowerShell Remoting.

.PARAMETER Computer
The remote computer name you want to send the file to via PowerShell Remoting.

.PARAMETER User
The user to auth to the remote machine as via PowerShell Remoting. 

.PARAMETER password
The credentials of the remote machine.

.EXAMPLE
PS C:\> . .\Transfer-file-remoting
PS C:\> Transfer-file-remoting -LocalFile C:\Users\User\Desktop\file.txt -Destination C:\Users\remoteuser\Desktop\ -Computer "computername" -User r"emoteuser" -password "remotepassword" 

.LINK
https://stackoverflow.com/questions/48519757/moving-files-via-powershell-to-remote-computers

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification EXAMPLE
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225

#>           
	[CmdletBinding()] 
	Param( 
		
		[Parameter(Mandatory = $false)]
		[String]
		$UserName,
		
		[Parameter(Mandatory = $true)]
		[String]
		$Password,
		
		[Parameter(Mandatory = $true)]
		[String]
		$FileName,
		
		[Parameter(Mandatory = $true)]
		[String]
		$RemoteFileName,
		
		[Parameter(Mandatory = $true)]
		[String]
		$RemoteComputer


	)

	
	#set Sessions parameter to creates a session to the remote server and uses that session to send the file.
	$SecurePassword = convertto-securestring -AsPlainText -Force -String $password
	$PSRemotingCreds = new-object -typename System.Management.Automation.PSCredential -argumentlist $UserName,$SecurePassword
	
	try {
		$PSSession = New-PSSession -ComputerName $RemoteComputer -Credential $PSRemotingCreds -ErrorAction Stop
		
		Write-Host "[+] Copying file $FileName to remote machine ..." -ForeGroundColor Green
		#start copying file
		Copy-Item -ToSession $PSSession -Path $FileName -Destination $RemoteFileName
		Write-Host "[+] File succesfully copied to remote machine !" -ForeGroundColor Green
		
		$PSSession | Remove-PSSession
		
		
		
	}
	catch {
	
		write-host "[-] Could not connect to the remote host $RemoteComputer ..." -ForeGroundColor Red
		write-host '[-] Make sure you entered a valid credentials .' -ForeGroundColor Red
	
	}
 }
