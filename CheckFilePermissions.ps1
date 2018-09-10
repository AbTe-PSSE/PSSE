## Powershell For Penetration Testers Exam Task 3 - Enumerate directories inside "C:\Windows\System32" which are writable by non-admin users

function EnumerateSysPermissions
{ 
<#
.SYNOPSIS
PowerShell cmdlet to enumerate files permissions within system32 directory.

.DESCRIPTION
This script is used to check what permissions a user has on C:\Windows\System32\ directory

.PARAMETER baseDir
directory to check, the default directory is "C:\Windows\System32".

.PARAMETER currentUser
User you want to enumerate file permissions on.

.EXAMPLE
PS C:\> . .\CheckFilePermissions.ps1
PS C:\> EnumerateSysPermissions -currentUser test

.LINK
https://community.spiceworks.com/topic/1982988-powershell-command-to-check-if-user-has-permissions-to-a-folder
http://lockboxx.blogspot.com/2016/01/scan-dir-permissions-powershell-for.html
https://exchangepedia.com/2017/11/get-file-or-folder-permissions-using-powershell.html

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225

#>  


    [CmdletBinding()] Param( 

            [Parameter()]
		    [String]
		    $baseDir = 'C:\Windows\System32\',
        
		    [Parameter()]
		    [String]
			$currentUser
    )
	    # getting the host name
		$hostName = hostname.exe
		
		# append the supllied user to the host name
		$currentUser = $hostName + "\" + $currentUser
		
		# Get directories recursively starting from C:\windows\system32
	    $dirlist = Get-ChildItem -path $baseDir -Directory -Recurse -ErrorAction SilentlyContinue
	    
		write-host "[+] Printing Permisions for user $currentUser" -ForeGroundColor Cyan
		
		# looping through the list of directories.
	    foreach ($folder in $dirlist){
            try{
                   
				# Using the Get-Acl cmdlet we were able to get list of directories that the current user has access on.
	            if (( $folder.fullname| Get-Acl -ErrorAction SilentlyContinue -ErrorVariable Erroracl).access  | ?{!$Erroracl} |?{$_.IdentityReference -contains $currentUser} ) {
                        # Filtering out the needed output 
			            $perm = ( $folder.fullname| Get-Acl ).access | ?{$_.IdentityReference -contains $currentUser} | select IdentityReference,FileSystemRights
						# Printing results to the user
			            Write-Host "[+] User '$($perm.IdentityReference)' has '$($perm.FileSystemRights)' rights on folder '$($folder.fullname)' " -ForeGroundColor Green
	            }
	

	        }
			# If any exception triggered, it means that we dont have access on that folder, so we print it
            catch{
                Write-Host "[-] No access to '$($folder.fullname)'" -ForeGroundColor Red
            
            }
}
}
