function Invoke-ShareHunter {
    <#
        .Synopsis
        A 'multithreaded' script that enumerates the permissions of SMB shares

        .Description
        A 'multithreaded' script that enumerates the permissions of SMB shares on the NTFS level via a list of hosts seperated by newlines in a text file

        .Parameter HostList
        The path to the text file that contains all SMB hosts separated by a newline

        .Parameter Domain
        The domain name used in the current network

        .Parameter Delay
        The time to delay in-between enumerating shares on a remote target (double value accepted 7.5)

        .Parameter Username
        The username to use for enumerating shares and their permssions

        .Parameter Password
        The password to use with the username for enumerating shares and their permissions

        .Parameter ExcludeShareNames
        An array of strings that specifies the names of shares to ignore (Default: IPC$ and Print$)

        .Parameter ShowProgress
        Shows the progress bar

        .Parameter Threads
        Specifiy how many threads to use. The larger the number the faster the process may complete. Please keep in mind that a higher number will also use a greater number of resources! (Default: 50)

        .Example
        1. powershell -exec bypass
        2. cd to/dir/
        3. Import-Modules .\ShareHunter.ps1

        (Invoke-ShareHunter -HostList \.listofhosts.txt -Delay 3 -ShowProgress -ExcludeShareNames @("NETLOGON", "SYSVOL", "print$", "ipc$") | Where-Object {$_.IdentityReference -eq "Everyone"})
        Invoke-ShareHunter -HostList \.listofhosts.txt -Username bob -Password bobpassword -Domain domain.net
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$HostList,
        [string]$Domain = $null,
        [double]$Delay = $null,
        [string]$Username = $null,
        [string]$Password = $null,
        [string[]]$ExcludeShareNames = @("IPC$", "Print$"),
        [switch]$ShowProgress,
        [int]$Threads = 50
    )

    $JobBlock = {
        [CmdletBinding()]
        param (
            [string]$RemoteHost,
            [string]$Domain,
            [double]$Delay,
            [string]$Username,
            [string]$Password,
            [System.Management.Automation.PSCredential]$Cred,
            [string[]]$ExcludeShareNames
        )

        function Get-ShareAce {
            [CmdletBinding()]
            param (
                [string]$Target,
                [string]$Share,
                [System.Management.Automation.PSCredential]$Credential
            )
    
            $AceArray = New-Object System.Collections.ArrayList;
    
            If ($Credential) {
                #Job - run get-acl cmdlet under the context of another user via start-job
                $Job = (Start-Job -Credential $Credential -ArgumentList @($Target, ($Share.Split(',')[0]), $VerbosePreference) -ScriptBlock { 
                        param(
                            $THost, 
                            $TShare, 
                            $VPref
                        ) 
    
                        try {
                            (Get-Acl -Path ("\\{0}\{1}" -f $THost, $TShare.Split(',')[0]) -ErrorAction Stop).Access
                        }
                        catch [System.UnauthorizedAccessException] {
                            if ($VPref) {
                                try {
                                    Write-Verbose "Not enough permissions to show rights for share: \\$([System.Net.Dns]::GetHostEntry($THost).HostName)\$($TShare.Split(',')[0])`n";
                                }
                                catch [System.Net.Sockets.SocketException] {
                                    Write-Verbose "Not enough permissions to show rights for share: \\$($THost)\$($TShare.Split(',')[0])`n";
                                }
                            }
                        }
                        catch [System.Management.Automation.ItemNotFoundException] {
                            if ($VPref) {
                                Write-Verbose "The share \\$([System.Net.Dns]::GetHostEntry($THost).HostName)\$($TShare.Split(',')[0]) could not be found!`n";
                            }
                        } 
                    });
    
                [void](Wait-Job -Job $Job);
                $AccessObject = Receive-Job -Job $Job; 
    
                foreach ($Ace in $AccessObject) {
                    $Result = "" | Select-Object SharePath, AccessControlType, IdentityReference, FileSystemRights; #assign these properties to the Result pscustomobject
                    $Result.SharePath = "\\$([System.Net.Dns]::GetHostEntry($Target).HostName)\$($Share.Split(',')[0])";
                    $Result.AccessControlType = $Ace.AccessControlType;
                    $Result.IdentityReference = $Ace.IdentityReference;
                    $Result.FileSystemRights = $Ace.FileSystemRights;
                    [void]$AceArray.Add($Result); #Array of pscustomobjects
                    
                    # $AccessObject | Add-Member -Type NoteProperty -Name SharePath -Value "\\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])";
                    # [void]$AceArray.Add($AccessObject)
                }
            }
            else {
                try {
                    foreach ($AccessObject in (Get-Acl -Path ("\\{0}\{1}" -f $Target, $Share.Split(',')[0]) -ErrorAction Stop).Access) {
                        $Result = "" | Select-Object SharePath, AccessControlType, IdentityReference, FileSystemRights; #assign these properties to the Result pscustomobject
                        $Result.SharePath = "\\$([System.Net.Dns]::GetHostEntry($Target).HostName)\$($Share.Split(',')[0])";
                        $Result.AccessControlType = $AccessObject.AccessControlType;
                        $Result.IdentityReference = $AccessObject.IdentityReference;
                        $Result.FileSystemRights = $AccessObject.FileSystemRights;
                        [void]$AceArray.Add($Result); #Array of pscustomobjects
                        
                        # $AccessObject | Add-Member -Type NoteProperty -Name SharePath -Value "\\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])";
                        # [void]$AceArray.Add($AccessObject)
                    }
                }
                catch [System.UnauthorizedAccessException] {
                    if ($VerbosePreference) {
                        try {
                            Write-Verbose "Not enough permissions to show rights for share: \\$([System.Net.Dns]::GetHostEntry($Target).HostName)\$($Share.Split(',')[0])`n";
                        }
                        catch [System.Net.Sockets.SocketException] {
                            Write-Verbose "Not enough permissions to show rights for share: \\$($Target)\$($Share.Split(',')[0])`n";
                        }
                    }
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    if ($VerbosePreference) {
                        Write-Verbose "The share \\$([System.Net.Dns]::GetHostEntry($Target).HostName)\$($Share.Split(',')[0]) could not be found!`n";
                    }
                }    
            }
            return $AceArray;
        }



        # Main execution in scriptblock here
        try {
            foreach ($Share in ((net view \\$RemoteHost /all /Domain:$Domain 2> $null) | Select-Object -Skip 7).Replace("The command completed successfully.", "").TrimEnd(" ") -replace "\s{2,}", ",") {
                if ($Share -and ![string]::IsNullOrWhiteSpace($Share)) {
                    if ($ExcludeShareNames -notcontains $Share.Split(",")[0]) {
                        if ($Username -and $Password) {
                            Get-ShareAce -Target $RemoteHost -Share $Share -Credential $Cred;
                        }
                        else {
                            Get-ShareAce -Target $RemoteHost -Share $Share;
                        }
                    }
                }
            }
        }
        catch [System.Exception] {
            if ($VerbosePreference) {
                Write-Verbose "Error: $_";
            }
        }
        Start-Sleep -Seconds $Delay
    }



    # Main Execution Starts Here  
    $Targets = (Get-Content -Path $HostList);
    $ShareInfoResults = new-object System.Collections.ArrayList
    $Count = 0;
    $Cred = $null;

    # Preliminary setup 
    if ($Password) {
        $SecPassword = (ConvertTo-SecureString $Password -AsPlainText -Force); 
        $Cred = New-Object System.Management.Automation.PSCredential ("$($env:USERDNSDOMAIN)\$($Username)", $SecPassword);
    }
    
    if (!$ShowProgress) {
        $ProgressPreference = "SilentlyContinue";
    }
    elseif ($ShowProgress) {
        $ProgressPreference = "Continue"
    }

    # Setup jobs for share enumeration (per host NOT per share for every host)
    foreach ($RemoteHost in $Targets) {
        $Count++;

        while ((Get-Job -State Running | Measure-Object).Count -ge $Threads) {
            Write-Verbose "Thread count reached, waiting 5 seconds";
            Start-Sleep -Seconds 5;
        }

        Write-Progress -Activity "Starting Share Enumeration Jobs" -Status "$Count of $($Targets.Length) - $([Math]::Ceiling(($Count / $Targets.Length) * 100))%" -PercentComplete $([Math]::Ceiling(($Count / $Targets.Length) * 100));
        [void](Start-Job -ScriptBlock $JobBlock -ArgumentList @($RemoteHost, $Domain, $Delay, $Username, $Password, $Cred, $ExcludeShareNames));
    }

    # Keep checking for jobs in running state
    while (Get-Job -State Running) {
        Write-Progress -Activity "Enumerating Share Permissions" -Status "$([Math]::Ceiling($(($((Get-Job -State Completed | Measure-Object).Count)/$($Targets.Length)) * 100)))% Complete:" -PercentComplete $([Math]::Ceiling($(($((Get-Job -State Completed | Measure-Object).Count)/$($Targets.Length)) * 100)));
        Start-Sleep -Milliseconds 100;
    }

    # Retrieve results for all completed jobs and store information into a pscustomobject and then store 
    foreach ($Property in (Get-Job | Receive-Job)) {
        $Result = "" | Select-Object SharePath, AccessControlType, IdentityReference, FileSystemRights; #assign these properties to the Result pscustomobject
        $Result.SharePath = [string]$Property.SharePath;
        $Result.AccessControlType = [string]$Property.AccessControlType;
        $Result.IdentityReference = [string]$Property.IdentityReference;
        $Result.FileSystemRights = [string]$Property.FileSystemRights;
        [void]$ShareInfoResults.Add($Result); #Array of pscustomobjects
    }

    # Clean up 
    Remove-Job *; 

    return $ShareInfoResults;
}
