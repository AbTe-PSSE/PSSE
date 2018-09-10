function SimpleServer
{ 
<#
.SYNOPSIS
Powershell cmdlet to launch a simple web server

.DESCRIPTION
This cmdlet can be used to launch a simple PowerShell web server that can list,download,upload and delete files

.PARAMETER WebRoot
The web root of the simple web server (default is '.')

.PARAMETER url
The url of the web server 

.EXAMPLE
PS C:\> . .\WebServer.ps1
PS C:\> SimpleServer -WebRoot <Webroot Path> -url <http://localhost:8088>

.LINK
https://gallery.technet.microsoft.com/scriptcenter/Powershell-Webserver-74dcf466
https://github.com/ahhh/PSSE/blob/master/Run-Simple-WebServer.ps1
https://gist.github.com/Tiberriver256/868226421866ccebd2310f1073dd1a1e
http://obscuresecurity.blogspot.mx/2014/05/dirty-powershell-webserver.html

.NOTES
Big thanks to "ahhh" for the idea (https://github.com/ahhh).

This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3225

#>           
    [CmdletBinding()] Param( 

       [Parameter(Mandatory = $false)]
       [String]
       $WebRoot = ".",
       
       [Parameter(Mandatory = $false)]
       [String]
       $url = 'http://localhost:8088/'

    )

    # List of responses to different user requests 
    $switches = @{
      # Simply notifying the user that the web server is working
      "GET /" = { return '<html><body>It Works!</body></html>' } 

      # Listing files in web root
      "GET /list" = { return dir $WebRoot }

      # Download file supllied from query string
      "GET /download" = { return (Get-Content (Join-Path $WebRoot ($context.Request.QueryString[0]))) }

      # Deletes file supllied from query string
      "GET /delete" = { (rm (Join-Path $WebRoot ($context.Request.QueryString[0])))
                     return "Succesfully deleted" }

      # Return an html for file upload		
      "GET /upload" = { return $upload = @"
			<html><body>
				<form method="POST" enctype="multipart/form-data" action="/upload">
				<p><b>File to upload:</b><input type="file" name="filedata"></p>
				<input type="submit" name="button" value="Upload">
				</form>
			</body></html>
"@ }

					 
      # Killing the server
      "GET /kill" = { exit }
	  
	  # Upload the file supllied by the HTML form to the web server root
	  # Adopted from https://gallery.technet.microsoft.com/scriptcenter/Powershell-Webserver-74dcf466
	  "POST /upload" = {
		if ($httpReq.HasEntityBody){
					# set default message to error message (since we just stop processing on error)
					$bufffer = "Received corrupt or incomplete form data"
					$a = "heyehyehyehye"
					$a
					# check content type

					if ($httpReq.ContentType)
					{
						# retrieve boundary marker for header separation
						$BOUNDARY = $NULL
						if ($httpReq.ContentType -match "boundary=(.*);")
						{	$BOUNDARY = "--" + $MATCHES[1] }
						else
						{ # marker might be at the end of the line
							if ($httpReq.ContentType -match "boundary=(.*)$")
							{ $BOUNDARY = "--" + $MATCHES[1] }
						}
						if ($BOUNDARY)
						{ # only if header separator was found
							# read complete header (inkl. file data) into string 
							$READER = New-Object System.IO.StreamReader($httpReq.InputStream, $httpReq.ContentEncoding)
							$DATA = $READER.ReadToEnd()
							$READER.Close()
							$httpReq.InputStream.Close()
							$b = "clodes input stream"
							$b
							# variables for filenames
							$FILENAME = ""
							$SOURCENAME = ""
							# separate headers by boundary string
							$DATA -replace "$BOUNDARY--\r\n", "$BOUNDARY`r`n--" -split "$BOUNDARY\r\n" | % {

								# omit leading empty header and end marker header
								if (($_ -ne "") -and ($_ -ne "--"))
								{
									# only if well defined header (seperation between meta data and data)
									if ($_.IndexOf("`r`n`r`n") -gt 0)
									{
										# header data before two CRs is meta data
										# first look for the file in header "filedata"
										if ($_.Substring(0, $_.IndexOf("`r`n`r`n")) -match "Content-Disposition: form-data; name=(.*);")
										{
											$HEADERNAME = $MATCHES[1] -replace '\"'
											# headername "filedata"?
											if ($HEADERNAME -eq "filedata")
											{ # yes, look for source filename
												if ($_.Substring(0, $_.IndexOf("`r`n`r`n")) -match "filename=(.*)")
												{ # source filename found
													$SOURCENAME = $MATCHES[1] -replace "`r`n$" -replace "`r$" -replace '\"'
													# store content of file in variable
													$FILEDATA = $_.Substring($_.IndexOf("`r`n`r`n") + 4) -replace "`r`n$"
												}
											}
										}
										else
										{ # look for other headers (we need "filepath" to know where to store the file)

											if ($_.Substring(0, $_.IndexOf("`r`n`r`n")) -match "Content-Disposition: form-data; name=(.*)")
											{ # header found
												$HEADERNAME = $MATCHES[1] -replace '\"'
												# headername "filepath"?
												if ($HEADERNAME -eq "filepath")
												{ # yes, look for target filename
													$FILENAME = $_.Substring($_.IndexOf("`r`n`r`n") + 4) -replace "`r`n$" -replace "`r$" -replace '\"'
												}
											}
										}
									}
								}
							}
								if ($SOURCENAME -ne "")
								{ # only upload if source file exists
									# check or construct a valid filename to store
									$c = "trying to upload"
								
									$TARGETNAME = ""
									$c
				   
									try {
										# ... save file with the same encoding as received
					  
									   
										
										$TARGETNAME = pwd 
										$TARGETNAME = "$TARGETNAME\" + $SOURCENAME
										$TARGETNAME
										$FILEDATA
										$httpReq.ContentEncoding
										[IO.File]::WriteAllText($TARGETNAME, $FILEDATA, $httpReq.ContentEncoding) 
									}
									catch	{}
									if ($Error.Count -gt 0)
									{ # retrieve error message on error
										$bufffer += "`nError saving '$TARGETNAME'`n`n"
										$bufffer += $Error[0]
										$Error.Clear()
										return $bufffer
										
										
									}
									else
									{ # success
										$bufffer = "File $SOURCENAME successfully uploaded as $TARGETNAME"
										return $bufffer
									
									}
								}
								else
								{
									$bufffer = "No file data received"
									return $bufffer
									
								}
						}
					}
		}
		else
		{
			$bufffer = "No client data received"
			return $bufffer
			
		}
	  
	  
	  }
    }
     

    # Initiating the web server listener and start it
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($url)
    $listener.Start()
    
    Write-Host "Listening on $url..."  -ForeGroundColor Green
      
    try{
	  # Always listen	
      while ($listener.IsListening)
      {
        
		$context = $listener.GetContext()
        # Getting the requested URL
		$requestUrl = $context.Request.Url
		
        $response = $context.Response
       
        Write-Host ''
        Write-Host "URL: $requestUrl"
       
        # Absolute file name
		$localPath = $requestUrl.LocalPath
		$httpReq = $context.Request
		# The http method used
		$httpMethod = $httpReq.httpMethod
		# User entered switch 
		$finalSwitch = $httpMethod + " " + $localPath
		# Compare the entered switch with the switches list
        $selectedSwitch = $switches.Get_Item($finalSwitch)
		
		write-host "$selectedSwitch"
       
	    # If a switch does not exist we responed with 404 error
        if ($selectedSwitch -eq $null) 
        {
          $response.StatusCode = 404
        }
        else 
        {
          $content = & $selectedSwitch
          $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
          $response.ContentLength64 = $buffer.Length
          $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        $response.Close()
        $responseStatus = $response.StatusCode
        Write-Host "$responseStatus"
      }
    }catch{ }
  }
