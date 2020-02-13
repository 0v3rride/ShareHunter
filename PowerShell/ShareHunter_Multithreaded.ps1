function Invoke-ShareHunter {
    <#
        .Synopsis
        A 'multithreaded' script that enumerates the permissions of SMB shares and files within those shares pending permissions.

        .Description
        A 'multithreaded' script that enumerates the permissions of SMB shares on the NTFS level via a list of hosts separated by newlines in a text file. 
        Files within these shares, pending permissions under the current context the script is running with, can also be enumerated by optionally targeting the file name itself or content values within the file.
        
        .Parameter Enumerate
        String representing what details you want to enumerate in accordance to a share (ValidateSet {Permissions | Files}).
        Use Permissions to enumerate NTFS permissions for shares.
        Use Files to enumerate files in a share that match a certain file name or the contents of a file.

        .Parameter HostList
        The path to the text file that contains all SMB hosts separated by a newline.

        .Parameter Domain
        The domain name used in the current network.

        .Parameter Username
        The username to use for enumerating shares and their permssions.

        .Parameter Password
        The password to use with the username for enumerating shares and their permissions.

        .Parameter ExcludeShareNames
        An array of strings that specifies the names of shares to ignore (Default: IPC$ and Print$).

        .Parameter ShowProgress
        Shows the progression bar and status.

        .Parameter Threads
        Specifiy how many threads to use. The larger the number the faster the process may complete. Please keep in mind that a higher number will also use a greater number of resources! (Default: 50).

        .Parameter FileNames
        An array of strings that represents file names to look for. Regular expressions CAN be used (Default: *Pass*).

        .Parameter FileValues
        An array of strings that represents the contents in a file to look for. Regular expressions CAN be used.

        .Notes
        It may look like the script isn't doing anything, but running it is running via background jobs. Each host in the target list file your provide will represent a separate job. Keep in mind that the output may also not be displayed immeditaley at the 100% mark if you're using the showprogress flag.

        .Example
        1. powershell -exec bypass
        2. cd to/dir/with/ShareHunter.ps1
        3. Import-Modules .\ShareHunter.ps1

        (Invoke-ShareHunter -HostList .\listofhosts.txt -Verbose -ShowProgress -Enumerate Permissions -ExcludeShareNames @("NETLOGON", "SYSVOL", "print$", "ipc$") | Where-Object {$_.Principal -eq "Everyone"})
        Invoke-ShareHunter -Hostlist .\targetlist.txt -Enumerate Files -ShowProgress -FileNames "web.config", "machine.config" -FileValues "machinekey" -Threads 20
    #>

    [CmdletBinding(DefaultParameterSetName = "SubnetList")]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = "HostList", HelpMessage = "The fully qualified path to the text file containing the SMB hosts delimited by a new line")]
        [string]$HostList,

        [Parameter(Mandatory = $false, ParameterSetName = "SubnetList", HelpMessage = "Provide a subnet or a list of subnets to build a list of IPs from by using the builtin IP enumerator")]
        [string[]]$SubnetList,

        [Parameter(Mandatory = $true, HelpMessage = "Enumerate the permissions on the top-level of the share itself or enumerate the files within each share")]
        [ValidateSet("Permissions", "Files")]
        [string]$Enumerate,

        [string]$Domain = $null,

        [string]$Username = $null,

        [string]$Password = $null,

        [string[]]$ExcludeShareNames = @("IPC$", "Print$"),

        [string[]]$FileNames = @("*pass*"),

        [string[]]$FileValues = $null,

        [switch]$ShowProgress,

        [ValidateRange(1, 300)]
        [int]$Threads = 50
    )

    #https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Subnet-db45ec74
    function Get-IPs { 
 
        Param( 
            [Parameter(Mandatory = $true)] 
            [array] $Subnets 
        ) 
 
        foreach ($subnet in $subnets) { 
         
            #Split IP and subnet 
            $IP = ($Subnet -split "\/")[0] 
            $SubnetBits = ($Subnet -split "\/")[1] 
         
            #Convert IP into binary 
            #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total 
            $Octets = $IP -split "\." 
            $IPInBinary = @() 
            foreach ($Octet in $Octets) { 
                #convert to binary 
                $OctetInBinary = [convert]::ToString($Octet, 2) 
                 
                #get length of binary string add leading zeros to make octet 
                $OctetInBinary = ("0" * (8 - ($OctetInBinary).Length) + $OctetInBinary) 
 
                $IPInBinary = $IPInBinary + $OctetInBinary 
            } 
            $IPInBinary = $IPInBinary -join "" 
 
            #Get network ID by subtracting subnet mask 
            $HostBits = 32 - $SubnetBits 
            $NetworkIDInBinary = $IPInBinary.Substring(0, $SubnetBits) 
         
            #Get host ID and get the first host ID by converting all 1s into 0s 
            $HostIDInBinary = $IPInBinary.Substring($SubnetBits, $HostBits)         
            $HostIDInBinary = $HostIDInBinary -replace "1", "0" 
 
            #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits) 
            #Work out max $HostIDInBinary 
            $imax = [convert]::ToInt32(("1" * $HostBits), 2) - 1 
 
            $IPs = @() 
 
            #Next ID is first network ID converted to decimal plus $i then converted to binary 
            For ($i = 1 ; $i -le $imax ; $i++) { 
                #Convert to decimal and add $i 
                $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary, 2) + $i) 
                #Convert back to binary 
                $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal, 2) 
                #Add leading zeros 
                #Number of zeros to add  
                $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length 
                $NextHostIDInBinary = ("0" * $NoOfZerosToAdd) + $NextHostIDInBinary 
 
                #Work out next IP 
                #Add networkID to hostID 
                $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary 
                #Split into octets and separate by . then join 
                $IP = @() 
                For ($x = 1 ; $x -le 4 ; $x++) { 
                    #Work out start character position 
                    $StartCharNumber = ($x - 1) * 8 
                    #Get octet in binary 
                    $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber, 8) 
                    #Convert octet into decimal 
                    $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary, 2) 
                    #Add octet to IP  
                    $IP += $IPOctetInDecimal 
                } 
 
                #Separate by . 
                $IP = $IP -join "." 
                $IPs += $IP 
 
                 
            } 
            
            return $IPs 
        } 
    }

    $JobBlock = {
        [CmdletBinding()]
        param (
            [string]$Enumerate,
            [string]$RemoteHost,
            [string]$Domain,
            [string]$Username,
            [string]$Password,
            [System.Management.Automation.PSCredential]$Credential,
            [string[]]$ExcludeShareNames,
            [string[]]$FileNames,
            [string[]]$FileValues
        )
        
        function Get-Files {
            [CmdletBinding()]
            param (
                [string]$TargetHost,
                [string]$TargetShare,
                [string[]]$TargetFileNames,
                [string[]]$TargetValues,
                [System.Management.Automation.PSCredential]$Credential
            )
            
            $Matches = New-Object System.Collections.ArrayList;

            if ($Credential) {
                $Job = (Start-Job -Credential $Credential -ArgumentList @($TargetHost, ($TargetShare.Split(',')[0]), $VerbosePreference, $TargetFileNames, $TargetFileValues) -ScriptBlock {
                        param(
                            $TargetHost, 
                            $TargetShare, 
                            $VPref,
                            $TargetFileNames,
                            $TargetValues
                        ) 

                        try {
                            $CredMatches = New-Object System.Collections.ArrayList;
            
                            foreach ($JobResults in (Get-ChildItem -Path "\\$($TargetHost)\$($TargetShare)" -Recurse -Include $TargetFileNames -ErrorAction Stop)) {
                                $Result = "" | Select-Object -Property Path, Name, Content;
                                $Result.Path = $JobResults.FullName
                                $Result.Name = $JobResults.Name
                                
                                if ($TargetValues.Count -gt 0) {
                                    $Result.Content = ( Get-Content -Path $JobResults.FullName | Select-String -Pattern $TargetValues -ErrorAction Stop)
                                }
            
                                if ($TargetValues.Count -le 0) {
                                    $Result.PsObject.Members.Remove("Matches");
                                    [void]$CredMatches.Add($Result);
                                }
                                elseif ($TargetValues.Count -gt 0 -and ![string]::IsNullOrEmpty($Result.Content) -and ![string]::IsNullOrWhiteSpace($Result.Content)) {
                                    [void]$CredMatches.Add($Result);
                                }
                            }
            
                            return $CredMatches;
                        }
                        catch [System.UnauthorizedAccessException] {
                            Write-Verbose "The current contex does not have enough permissions to access \\$($TargetHost)\$($TargetShare)\$($JobResults.Name)!"
                        }
                        catch [System.Management.Automation.ItemNotFoundException] {
                            Write-Verbose "The path \\$($TargetHost)\$($TargetShare)\$($JobResults.Name) could not be found!"
                        }
                        catch [System.IO.DirectoryNotFoundException] {
                            Write-Verbose "A portion of the path \\$($TargetHost)\$($TargetShare)\$($JobResults.Name) could not be located!"
                        }
                    });

                [void](Wait-Job -Job $Job);
                $Matches = Receive-Job -Job $Job; 
            }
            else {
                try {
                    foreach ($FileObject in (Get-ChildItem -Path "\\$($TargetHost)\$($TargetShare)" -Recurse -Include $TargetFileNames -ErrorAction Stop)) {
                        $Result = "" | Select-Object -Property Path, Name, Content;
                        $Result.Path = $FileObject.FullName
                        $Result.Name = $FileObject.Name
                        
                        if ($TargetValues.Count -gt 0) {
                            $Result.Content = ( Get-Content -Path $FileObject.FullName | Select-String -Pattern $TargetValues -ErrorAction Stop)
                        }
    
                        if ($TargetValues.Count -le 0) {
                            $Result.PsObject.Members.Remove("Matches");
                            [void]$Matches.Add($Result);
                        }
                        elseif ($TargetValues.Count -gt 0 -and ![string]::IsNullOrEmpty($Result.Content) -and ![string]::IsNullOrWhiteSpace($Result.Content)) {
                            [void]$Matches.Add($Result);
                        }
                    }
                }
                catch [System.UnauthorizedAccessException] {
                    Write-Verbose "The current contex does not have enough permissions to access \\$($TargetHost)\$($TargetShare)\$($FileObject.Name)!"
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    Write-Verbose "The path \\$($TargetHost)\$($TargetShare)\$($FileObject.Name) could not be found!"
                }
                catch [System.IO.DirectoryNotFoundException] {
                    Write-Verbose "A portion of the path \\$($TargetHost)\$($TargetShare)\$($FileObject.Name) could not be located!"
                }
            }

            return $Matches;
        }
            

        function Get-NTFSPermissions {
            [CmdletBinding()]
            param (
                [string]$TargetHost,
                [string]$TargetShare,
                [System.Management.Automation.PSCredential]$Credential
            )

            $Aces = New-Object System.Collections.ArrayList;
                        
            if ($Credential) {
                $Job = (Start-Job -Credential $Credential -ArgumentList @($TargetHost, ($TargetShare.Split(',')[0]), $VerbosePreference, $TargetFileNames, $TargetFileValues) -ScriptBlock {
                        param(
                            $TargetHost, 
                            $TargetShare, 
                            $VPref,
                            $TargetFileNames,
                            $TargetValues
                        ) 
                            
                        try {
                            $CredAces = New-Object System.Collections.ArrayList;
                                
                            foreach ($AccessObject in (Get-Acl -Path "\\$($TargetHost)\$($TargetShare)" -ErrorAction Stop).Access) { 
                                $Result = "" | Select-Object -Property UNCPath, Principal, Verb, NTFSPermissions;
                                $Result.UNCPath = ("\\{0}\{1}" -f [System.Net.Dns]::GetHostEntry($TargetHost).HostName, $TargetShare);
                                $Result.Principal = $AccessObject.IdentityReference;
                                $Result.Verb = $AccessObject.AccessControlType;
                                $Result.NTFSPermissions = $AccessObject.FileSystemRights;
                
                                [void]$CredAces.Add($Result);
                            }
                
                            return $CredAces
                        }
                        catch [System.UnauthorizedAccessException] {
                            Write-Verbose "The current contex does not have enough permissions to access \\$($TargetHost)\$($TargetShare)!"
                        }
                        catch [System.Management.Automation.ItemNotFoundException] {
                            Write-Verbose "The UNC path \\$($TargetHost)\$($TargetShare) could not be found!"
                        }
                    });
    
                [void](Wait-Job -Job $Job);
                $Aces = Receive-Job -Job $Job; 
            }
            else {
                try {
                    foreach ($AccessObject in (Get-Acl -Path "\\$($TargetHost)\$($TargetShare)" -ErrorAction Stop).Access) {
                        $Result = "" | Select-Object -Property UNCPath, Principal, Verb, NTFSPermissions;
                        $Result.UNCPath = ("\\{0}\{1}" -f [System.Net.Dns]::GetHostEntry($TargetHost).HostName, $TargetShare);
                        $Result.Principal = $AccessObject.IdentityReference;
                        $Result.Verb = $AccessObject.AccessControlType;
                        $Result.NTFSPermissions = $AccessObject.FileSystemRights;
        
                        [void]$Aces.Add($Result);
                    }
        
                    return $Aces;
                }
                catch [System.UnauthorizedAccessException] {
                    Write-Verbose "The current contex does not have enough permissions to access \\$($TargetHost)\$($TargetShare)!"
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    Write-Verbose "The UNC path \\$($TargetHost)\$($TargetShare) could not be found!"
                }
            }
        }



        # Main execution in scriptblock here
        try {
            foreach ($Share in ((net view \\$RemoteHost /all /Domain:$Domain 2> $null) | Select-Object -Skip 7).Replace("The command completed successfully.", "").TrimEnd(" ") -replace "\s{2,}", ",") {
                if ($Share -and ![string]::IsNullOrWhiteSpace($Share)) {
                    if ($ExcludeShareNames -notcontains $Share.Split(",")[0]) {
                        if ($Enumerate -eq "Permissions") {
                            if ($Username -and $Password) {
                                Get-NTFSPermissions -TargetHost $RemoteHost -TargetShare $Share.Split(",")[0] -Credential $Credential;
                            }
                            else {
                                Get-NTFSPermissions -TargetHost $RemoteHost -TargetShare $Share.Split(",")[0]; 
                            }
                        }
                        elseif ($Enumerate -eq "Files") {
                            if ($Username -and $Password) {
                                Get-Files -TargetHost $RemoteHost -TargetShare $Share.Split(",")[0] -TargetFileNames $FileNames -TargetValues $FileValues -Credential $Credential; 
                            }
                            else {
                                Get-Files -TargetHost $RemoteHost -TargetShare $Share.Split(",")[0] -TargetFileNames $FileNames -TargetValues $FileValues; 
                            }
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
    }


    # Preliminary setup 
    $Targets = $null;
    $Count = 0;
    $Credential = $null;

    if ($HostList -and !($SubnetList)) {
        $Targets = (Get-Content -Path $HostList);
    }
    elseif ($SubnetList -and !($HostList)){
        $Targets = Get-IPs -Subnets $SubnetList
    }

    if ($Password) {
        $SecPassword = (ConvertTo-SecureString $Password -AsPlainText -Force); 
        $Credential = New-Object System.Management.Automation.PSCredential ("$($env:USERDNSDOMAIN)\$($Username)", $SecPassword);
    }
    
    if (!$ShowProgress) {
        $ProgressPreference = "SilentlyContinue";
    }
    elseif ($ShowProgress) {
        $ProgressPreference = "Continue"
    }

    # 1. Setup jobs for share enumeration (per host NOT per share for every host)
    foreach ($RemoteHost in $Targets) {
        $Count++;

        while ((Get-Job -State Running | Measure-Object).Count -ge $Threads) {
            Write-Verbose "Maximum thread count reached, waiting 10 seconds";
            Start-Sleep -Seconds 10;
        }
           
        Write-Progress -Activity "Starting Share Enumeration Jobs" -Status "$Count of $($Targets.Length) - $([Math]::Ceiling(($Count / $Targets.Length) * 100))%" -PercentComplete $([Math]::Ceiling(($Count / $Targets.Length) * 100)) -ErrorAction SilentlyContinue;
        [void](Start-Job -ScriptBlock $JobBlock -ArgumentList @($Enumerate, $RemoteHost, $Domain, $Username, $Password, $Credential, $ExcludeShareNames, $FileNames, $FileValues));
        Start-Sleep -Milliseconds 100;
    }

    # 2. Keep checking for jobs in running state
    while (Get-Job -State Running) {
        $ActivityDescription = $null;

        if ($Enumerate -eq "Permissions") {
            $ActivityDescription = "Enumerating Share Permissions"
        }
        elseif ($Enumerate -eq "Files") {
            $ActivityDescription = "Enumerating File Information"
        }

        Write-Progress -Activity $ActivityDescription -Status "$([Math]::Ceiling($(($((Get-Job -State Completed | Measure-Object).Count)/$($Targets.Length)) * 100)))% Complete:" -PercentComplete $([Math]::Ceiling($(($((Get-Job -State Completed | Measure-Object).Count) / $($Targets.Length)) * 100))) -ErrorAction SilentlyContinue;
        Start-Sleep -Milliseconds 100;
    }

    # 3. Retrieve results for all completed jobs and store information into a pscustomobject and then store 
    $EnumerationResults = New-Object System.Collections.ArrayList;
    
    if ($Enumerate -eq "Permissions") {
        foreach ($JobResults in (Get-Job | Receive-Job)) {
            $Result = "" | Select-Object -Property UNCPath, Principal, Verb, NTFSPermissions;
            $Result.UNCPath = [string]$JobResults.UNCPath;
            $Result.Principal = [string]$JobResults.Principal;
            $Result.Verb = [string]$JobResults.Verb;
            $Result.NTFSPermissions = [string]$JobResults.NTFSPermissions

            [void]$EnumerationResults.Add($Result);
        }
    }
    elseif ($Enumerate -eq "Files") {
        if ($FileValues.Count -le 0) {
            foreach ($JobResults in (Get-Job | Receive-Job)) {
                $Result = "" | Select-Object -Property Path, Name;
                $Result.Path = [string]$JobResults.Path;
                $Result.Name = [string]$JobResults.Name;

                [void]$EnumerationResults.Add($Result);
            }
        }
        elseif ($FileValues.Count -gt 0) {
            foreach ($JobResults in (Get-Job | Receive-Job)) {
                $Result = "" | Select-Object -Property Path, Name, Content;
                $Result.Path = [string]$JobResults.Path;
                $Result.Name = [string]$JobResults.Name;
                $Result.Content = [string]$JobResults.Content;

                [void]$EnumerationResults.Add($Result);
            }
        }
    }
    
    # 4. Clean up all jobs
    Remove-Job *; 

    return $EnumerationResults;
}
