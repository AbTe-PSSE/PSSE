## Powershell For Penetration Testers Exam Task 2 - Enumerate all open shares on a network, noteing read and write access
function CheckFileShares
{

<#

.SYNOPSIS
Powershell cmdlet to enumerate open shares in a network for read and write permissions

.DESCRIPTION
This script is used to scan a network hosts for file shares, and then determine which shares the user has read and write access on

.PARAMETER Target
This switch is used to scan a single host for readable and writeable file shares

.PARAMETER hosts
Use this switch to suply a list of hosts to scan for readable and writeable file shares

.Example
PS C:\> . .\CheckSharesPermissions.ps1
PS C:\> CheckFileShares -Target testMachine

.Example
PS C:\> . .\CheckSharesPermissions.ps1
PS C:\> CheckFileShares -hosts .\list.txt

.LINK
https://winception.wordpress.com/2011/02/14/windows-share-permissions-and-using-powershell-to-manipulate-them/
https://itknowledgeexchange.techtarget.com/powershell/shares-understanding-the-access-mask/
https://4sysops.com/archives/find-shares-with-powershell-where-everyone-has-full-control-permissions/
https://github.com/ahhh/PSSE/blob/master/Scan-Share-Permissions.ps1

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225

#>

	[CmdletBinding()] Param(		
		
		[String]
		$Target,
		
		# A List of IPs to scan against, you can use other powershell cmdlets to easily generate IP lists
		[Parameter(Mandatory = $false)]
		[String]
		$hosts = $null
		
	)
	
	function scanShares($hostt)	
	{
		# List of what we will print if a match occures
		$acmsk = DATA {
        ConvertFrom-StringData -StringData @'
        1 = Read permission
        2 = Write permission
        
'@
        }
		# List of flags to compate it with shares GetAccessMask returned value
		$flags = @(1,2)

		try
		{
			# Get list of shares on remote computer
			$shares = Get-WmiObject -Class win32_share -ComputerName $hostt -ErrorAction Stop
            
		}
		# If we could not obtain the shares list, then catch the exception and print to user
		catch
		{
			Write-Host "Could not connect to the host: \\$hostt\"  -ForegroundColor Red  
			$shares = $null
		}
		
	
		foreach ($share in $shares) 
		{  
			# Print discovered shares to the user
			
            $shareName = $share | select -ExpandProperty Name
			Write-Host "Working on \\$hostt\$shareName" -ForegroundColor Green    
			
			try 
			{  
                # Get security setting using GetAccessMask, if we could not then through an exception
				$mask = Invoke-WmiMethod -InputObject $share -Name GetAccessMask -ErrorAction Stop
				
				# loop through the flags array list
                foreach ($flag in $flags){
					
					#if a match found then print to the user the permissions
                    if ($mask.ReturnValue -band $flag) {
						
                        Write-Host "[+]" $acmsk["$($flag)"] -ForegroundColor Cyan
                    }

                }
         
			}  
			catch  
			{ 
				Write-Host "[-]"  "Could not get permissions for  \\$hostt\$shareName" -ForegroundColor Red
			}
           
		} # Loop foreach closing brackets
	}				

	# Check if a list was supplied by the user
	if ($hosts)
	{
		# Read the list of IP's and store it in ipList
		$ipList = Get-Content $hosts
		# Looping through the list of ip's
		foreach ($ip in $ipList)
		{
			Write-Host "[+] Scanning \\$ip for shared folders" -ForegroundColor Green
			# Checking each host for file shares permissions
			scanShares($ip)
		}
	}
	else
	{
		Write-Host "[+] Scanning \\$Target for shared folders" -ForegroundColor Green
		# Checking the target host for shares permissions
		scanShares($Target)
	}
}
