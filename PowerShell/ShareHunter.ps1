function Invoke-ShareHunter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$HostList,
        [string]$Domain = $env:USERDNSDOMAIN,
        [string]$Username = $null,
        [securestring]$Password = $null
    )

    foreach ($RemoteHost in (Get-Content -Path $HostList)) {
        foreach ($Share in ((net view \\$RemoteHost /all /Domain:$Domain) | Select-Object -Skip 7).Replace("The command completed successfully.", "").TrimEnd(" ") -replace "\s{2,}", ",") {
            if ($Share -and ![string]::IsNullOrWhiteSpace($Share)) {
                Enum-Shares -RemoteHost $RemoteHost -Share $Share;
            }
        }
    }
}

function Enum-Shares {
    [CmdletBinding()]
    param (
        [string]$RemoteHost,
        [String]$Share
    )

    try {
        $AceArray = New-Object System.Collections.ArrayList;

        foreach ($AccessObject in (Get-Acl -Path ("\\{0}\{1}" -f $RemoteHost, $Share.Split(',')[0]) -ErrorAction Stop).Access) {
            $Result = "" | Select-Object SharePath, AccessControlType, IdentityReference, FileSystemRights; #assign these properties to the Result custom object
            $Result.SharePath = "\\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])";
            $Result.AccessControlType = $AccessObject.AccessControlType;
            $Result.IdentityReference = $AccessObject.IdentityReference;
            $Result.FileSystemRights = $AccessObject.FileSystemRights;
            [void]$AceArray.Add($Result);
            
            # $AccessObject | Add-Member -Type NoteProperty -Name SharePath -Value "\\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])";
            # [void]$AceArray.Add($AccessObject)
        }

        $AceArray
    }
    catch [System.UnauthorizedAccessException] {
        if ($VerbosePreference) {
            Write-Verbose "Not enough permissions to show rights for share: \\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0])`n";
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        if ($VerbosePreference) {
            Write-Verbose "The share \\$([System.Net.Dns]::GetHostEntry($RemoteHost).HostName)\$($Share.Split(',')[0]) could not be found!`n";
        }
    }
}
