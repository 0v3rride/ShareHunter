function Invoke-ShareHunter {
    <#
        .Synopsis
        Enumerates the permissions of SMB shares

        .Description
        Enumerates the permissions of SMB shares on the NTFS level via a list of hosts seperated by newlines in a text file
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$HostList,
        [string]$Domain = $null,
        [double]$Delay = $null,
        [string]$Username = $null,
        [string[]]$Exclude = @("IPC$", "Print$"),
        [string]$Password = $null,
        [switch]$ShowProgress
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
        $AceArray;
    }


    #Main Execution Starts Here
    $Count = 0;
    $Targets = (Get-Content -Path $HostList);
    $Cred = $null;

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

    foreach ($RemoteHost in $Targets) {
        $Count++;
        Write-Progress -Activity "Enumerating SMB Shares" -Status "Enumeration Progress: $([Math]::Ceiling(($Count/$Targets.Length) * 100))%" -PercentComplete $([Math]::Ceiling(($Count / $Targets.Length) * 100));

        try {
            foreach ($Share in ((net view \\$RemoteHost /all /Domain:$Domain 2> $null) | Select-Object -Skip 7).Replace("The command completed successfully.", "").TrimEnd(" ") -replace "\s{2,}", ",") {
                if ($Share -and ![string]::IsNullOrWhiteSpace($Share)) {
                    if($Exclude -notcontains $Share.Split(",")[0])
                    {
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
        Start-Sleep -Seconds $Delay;
    }
}
