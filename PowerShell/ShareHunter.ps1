function Invoke-ShareHunter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$HostList,
        [string]$Domain = $env:USERDNSDOMAIN,
        [double]$Delay = $null,
        [string]$Username = $null,
        [securestring]$Password = $null,
        [switch]$ShowProgress
    )

    function Enum-Shares {
        [CmdletBinding()]
        param (
            [string]$RemoteHost,
            [String]$Share
        )

        try {
            $AceArray = New-Object System.Collections.ArrayList;

            foreach ($AccessObject in (Get-Acl -Path ("\\{0}\{1}" -f $RemoteHost, $Share.Split(',')[0]) -ErrorAction Stop).Access) {
                $Result = "" | Select-Object SharePath, AccessControlType, IdentityReference, FileSystemRights; #assign these properties to the Result pscustomobject
                $Result.SharePath = "\\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])";
                $Result.AccessControlType = $AccessObject.AccessControlType;
                $Result.IdentityReference = $AccessObject.IdentityReference;
                $Result.FileSystemRights = $AccessObject.FileSystemRights;
                [void]$AceArray.Add($Result); #Array of pscustomobjects
            
                # $AccessObject | Add-Member -Type NoteProperty -Name SharePath -Value "\\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])";
                # [void]$AceArray.Add($AccessObject)
            }

            $AceArray;
        }
        catch [System.UnauthorizedAccessException] {
            if ($VerbosePreference) {
                try {
                    Write-Verbose "Not enough permissions to show rights for share: \\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])`n";
                }
                catch [System.Net.Sockets.SocketException] {
                    Write-Verbose "Not enough permissions to show rights for share: \\$($RemoteHost)\$($Share.Split(',')[0])`n";
                }
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            if ($VerbosePreference) {
                Write-Verbose "The share \\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0]) could not be found!`n";
            }
        }
    }


    #Main Execution Starts Here
    $Count = 0;
    $Targets = (Get-Content -Path $HostList)
    
    if (!$ShowProgress) {
        $ProgressPreference = "SilentlyContinue";
    }
    elseif ($ShowProgress) {
        $ProgressPreference = "Continue"
    }

    foreach ($RemoteHost in $Targets) {
        $Count++;
        Write-Progress -Activity "Enumerating SMB Shares" -Status "Enumeration Progress: $([Math]::Ceiling(($Count/$Targets.Length) * 100))%" -PercentComplete $([Math]::Ceiling(($Count/$Targets.Length) * 100));

        try {
            foreach ($Share in ((net view \\$RemoteHost /all /Domain:$Domain 2> $null) | Select-Object -Skip 7).Replace("The command completed successfully.", "").TrimEnd(" ") -replace "\s{2,}", ",") {
                if ($Share -and ![string]::IsNullOrWhiteSpace($Share) -and $Share -notlike "*IPC$*") {
                    Enum-Shares -RemoteHost $RemoteHost -Share $Share;
                }
            }
        }
        catch [System.Exception] {
            if ($VerbosePreference) {
                Write-Verbose "System Error";
            }
        }
        Start-Sleep -Seconds $Delay;
    }
}
