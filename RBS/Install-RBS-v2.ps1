<#
.SYNOPSIS
    Install Rubrik Backup Service from a specific cluster to a list of Windows Computers

.DESCRIPTION
    Install Rubrik Backup Service from a specific cluster to a list of Windows Computers. 
    - Downloads RBS from specified cluster and extracts file. 
    - Copies to each server and remotely installs RBS (in order of input, one at a time) 
    - Deletes RBS files on remote computers
    - Sets service to run as specified user account and restarts service. 
    NOTE: REQUIRES PS6 or greater due to Remote PSSessions
    OPTIONAL: Run with ChangeRBSPasswordOnly switch at CLI to change user/pw on existing RBS installs only (no install)

.PARAMETER RubrikCluster
    Name or IP of Rubrik Cluster to download the RBS from

.PARAMETER ComputerName
    List of comma separated host FQDN to install RBS on

.PARAMETER RBSCredential
    PSCredential of service account username/password to use on remote computer for RBS Service

.PARAMETER RBSUserName
    Username of service account to use on remote computer for RBS Service

.PARAMETER RBSPassword
    Password of service account to use on remote computer for RBS Service (WARNING: Cleartext on commandline and in PS History--use carefully)

.PARAMETER ChangeRBSPasswordOnly
    CLI switch to signal to only change user/pw on server. Does not download/copy/install RBS. 

.PARAMETER Path
    Location to download and extract RBS to. Default C:\Temp

.NOTES
    Updated 2023.08.26 by David Oslager for community usage
    GitHub: doslagerRubrik
    Originally based on Install-RubrikBackupService.ps1 by Chris Lumnah
    https://github.com/rubrikinc/rubrik-scripts-for-powershell/blob/master/RBS/Install-RubrikBackupService.ps1

.EXAMPLE
    Install-RBS-v2.ps1 

    Install RBS remotely and prompt for all of the variables.

.EXAMPLE
    Install-RBS-v2.ps1 -ComputerName "server1.domain.com,server2,domain.com,server3.domain.com"

    Install RBS on computerName one at a time - Must be comma separated, and the entire string in quotes
    Prompt for Rubrik Cluster and credential info

.EXAMPLE
    Install-RBS-v2.ps1 -RubrikCluster rubrik01.domain.com -RBSUserName DOMAIN\svc-RubrikRBS -RBSPassword P@ssw0rd123

    Install RBS from Cluster "rubrik01.domain.com" using specified Username and Password (WARNING! Cleartext on commandline)

.EXAMPLE
    Install-RBS-v2.ps1 -RubrikCluster rubrik01.domain.com -RBSCredential $RBSCredential

    Install RBS from Cluster "rubrik01.domain.com" using specified PSCredential Variable (must be defined, or will prompt for user/pw)

#>
#Requires -version 6.0
[CmdletBinding()]                                # <-- Verbose and Debug enabled with the [CmdletBinding()] directive
param(
    # Rubrik Cluster name or ip address
    [string]$RubrikCluster,
    
    # Computer(s) that should have the Rubrik Backup Service installed onto and then added into Rubrik
    [String]$ComputerName,

    # Credential to run the Rubrik Backup Service on the Computer
    [pscredential]$RBSCredential,

    #Username to connect with. If RBSPassword not included on command line, will prompt for password (Secure!)
    [string]$RBSUserName,

    #Optionally, can use username and password (clear text!) via command line. NOT RECOMMENDED
    [string]$RBSPassword,

    #Skip RBS install, change RBS user/pw only
    [switch]$ChangeRBSPasswordOnly,

    #Local Location to store download of RBS
    [string]$Path = "c:\temp"
)
$dateformat    = 'yyyy-MM-ddTHH:mm:ss'     #ISO8601 time standard
$LineSepDashes = "-" * 150

write-host $LineSepDashes
Write-Host "Starting Install-RBS-v2.ps1 - $(Get-Date -format $dateformat)" -ForegroundColor GREEN
write-host $LineSepDashes

#Region RubrikCluster
if (-not $ChangeRBSPasswordOnly) {
    If ($RubrikCluster) {
        Write-Host "Rubrik Cluster specified: $RubrikCluster" -ForegroundColor GREEN
    } else {
        Write-Host "ERROR! Rubrik cluster not specified on command line for RBS Download" -ForegroundColor RED
        $RubrikCluster = Read-Host -Prompt "Please enter Rubrik Cluster Name"
        write-host
    }
}
#EndRegion RubrikCluster


#Region ComputerName(s)
if ($ComputerName) {
    Write-Host "Target computers: $($computername -join ',')" -ForegroundColor GREEN
} else {
    if ($ChangeRBSPasswordOnly) {
        Write-Host "ERROR! List of target computers to change RBS user/pw not provided on command line" -ForegroundColor RED
    } else {
        Write-Host "ERROR! List of target computers to install RBS not provided on command line" -ForegroundColor RED
    }
    $ComputerName = Read-HOst -Prompt "Please enter list of computers, comma separated" 
    write-host
}
#EndRegion ComputerName(s)


#Region User/Pw/Creds
if ( $RBSCredential -and ($RBSCredential.GetType().Name -eq "PSCredential") ){
    #Credential supplied via command line and var type is a PSCredential
    Write-Host "Credential specified." -ForegroundColor CYAN
    $RubrikServiceAccount = $RBSCredential
} elseif ( $RBSCredential ) {
    #Variable is defined, but not a proper PScredential - Ignore and re-prompt
    Write-Host "Credential entered on CLI, but not a proper PScredential. Prompting for credential" -ForegroundColor CYAN
    Write-Host "Enter user name and password for the service account that will run the Rubrik Backup Service" -ForegroundColor Cyan
    $RubrikServiceAccount = Get-Credential
} elseif ( $RBSUserName -and $RBSPassword ){
    Write-Host "Username and password specified via CLI, creating Credential" -ForegroundColor Cyan
    # Convert Cleartext from CLI to SecureString
    [securestring]$secStringPassword = ConvertTo-SecureString $RBSPassword -AsPlainText -Force
    [pscredential]$RubrikServiceAccount = New-Object System.Management.Automation.PSCredential ($RBSUserName, $secStringPassword)
} elseif ( $RBSUserName ) {
    #UserName only supplied on CLI, prompt for password
    Write-Host "Enter password for the service account ($RBSUserName) that will run the Rubrik Backup Service" -ForegroundColor Cyan
    $RubrikServiceAccount = Get-Credential -UserName $RBSUserName 
    #$RubrikServiceAccount = Get-Credential -UserName $RBSUserName -Title "Enter user name and password for the service account that will run the Rubrik Backup Service"
} else {
    #Nothing supplied - prompt for user/pw
    Write-Host "Nothing specified on CLI...prompting for credential" -ForegroundColor Cyan
    Write-Host "Enter user name and password for the service account that will run the Rubrik Backup Service" -ForegroundColor Cyan
    $RubrikServiceAccount = Get-Credential
}
Write-Verbose "RBS Username:  $($RubrikServiceAccount.UserName)"
Write-Verbose "RBS Password:  $($RubrikServiceAccount.GetNetworkCredential().Password)"
#EndRegion User/Pw/Creds
write-host $LineSepDashes


#region Download the Rubrik Connector 
#forcing PS6+ with the Requires at the top of the script. 
#Do not want to use PS 5.x and dealing with SSL self signed certs
#additional steps to invoke-command better run on PS7
if (-not $ChangeRBSPasswordOnly) {
    if (-not (test-path  $Path) ) {
        $null = New-Item -Path $Path -ItemType Directory 
    }
    $url =  "https://$($RubrikCluster)/connector/RubrikBackupService.zip"
    $OutFile = "$Path\RubrikBackupService.zip"

    Write-Host "Downloading RBS zip file from $url" -ForegroundColor CYAN
    write-Host "Saving as $OutFile" -ForegroundColor CYAN

    #Set progress to none - Invoke-Webrequest is annoying and lingers over the CLI after it is complete
    $oldProgressPreference = $progressPreference; 
    $progressPreference = 'SilentlyContinue'
    try {
        $null = Invoke-WebRequest -Uri $url -OutFile $OutFile -SkipCertificateCheck
    } catch {
        Write-Host "ERROR! Could not download RBS zip file from $RubrikCluster. Please verify connectivity" -ForegroundColor Red
        exit 1
    }
    #Set ProgressPref back to what it was before we did IWR
    $progressPreference = $oldProgressPreference 
    Write-Host "Expanding RBS locally to c:\Temp\RubrikBackupService\" -ForegroundColor CYAN
    Expand-Archive -LiteralPath "c:\Temp\RubrikBackupService.zip" -DestinationPath "C:\Temp\RubrikBackupService" -Force
    write-host $LineSepDashes
}
#endregion

#Region Validate the Servername(s) and if it is online
write-Host "Testing connectivity to each target server. Please wait." -ForegroundColor CYAN
$ValidComputerList=@()
foreach( $Computer in $($ComputerName -split ',') ) {
    if ((Test-Connection -ComputerName $Computer -Count 3 -quiet -ErrorAction SilentlyContinue)) {
        Write-Host "$Computer is reachable - will attempt to install RBS" -ForegroundColor GREEN
        $ValidComputerList +=$Computer
    } else {
        Write-Host "  > $Computer is not reachable, the RBS will not be installed on this server!" -ForegroundColor RED
    }  
}
write-host $LineSepDashes
#EndRegion Validate the Servername(s) and if it is online


#Region Loop Through Computer List
foreach($Computer in $ValidComputerList){
    if ($ChangeRBSPasswordOnly){
        Write-Host "Changing RBS Password on " -ForegroundColor CYAN -NoNewline 
    } else {
        Write-Host "Starting Install of RBS on " -ForegroundColor CYAN -NoNewline 
    }
    Write-Host "$Computer" -ForegroundColor GREEN -NoNewline
    Write-Host ". Please wait" -ForegroundColor CYAN

    #region Copy RBS files, Install RBS, Delete RBS Files
    if (-not $ChangeRBSPasswordOnly) {
        #region Copy the RubrikBackupService files to the remote computer
        Write-Host "Copying RBS files to $Computer. Please wait" -ForegroundColor CYAN
        try {
            Invoke-Command -ComputerName $Computer -ScriptBlock { 
                New-Item -Path "C:\Temp\RubrikBackupService" -type directory -Force | out-null
            }
            $Session = New-PSSession -ComputerName $Computer 
            foreach ($file in Get-ChildItem C:\Temp\RubrikBackupService) {
                write-host "  > Copying $file to $computer" -ForegroundColor CYAN
                Copy-Item -ToSession $Session $file -Destination C:\Temp\RubrikBackupService | out-Null
            }
            Remove-PSSession -Session $Session
        } catch {
            Write-Host "ERROR! There was an error copying the RBS to $Computer. Skipping install on this computer. Please try manually" -ForegroundColor RED
            #Write-Host "$($error[0].exception.message)" -ForegroundColor RED
            write-host $LineSepDashes
            continue
        }
        #endregion



        #region Install the RBS on the Remote Computer
        Write-Host "Installing RBS on $Computer. Please wait" -ForegroundColor CYAN
        $Session = New-PSSession -ComputerName $Computer 
        try {
            Invoke-Command -Session $Session -ScriptBlock {
                Start-Process -FilePath "C:\Temp\RubrikBackupService\RubrikBackupService.msi" -ArgumentList "/quiet" -Wait
            }        
        } catch {
            Write-Host "ERROR! There was an error installing RBS to $Computer. Please try manually" -ForegroundColor RED
            #Write-Host "$($error[0].exception.message)" -ForegroundColor RED
            write-host $LineSepDashes
            continue    
        }
        Remove-PSSession -Session $Session
        #endregion



        #Region remove RBS files
        Write-Host "Deleting RBS files on $Computer. Please wait" -ForegroundColor CYAN
        try {
            Invoke-Command -ComputerName $Computer -ScriptBlock { 
                Remove-Item -Path "C:\Temp\RubrikBackupService" -recurse -Force | out-null
            }
        } catch {
            Write-Host "ERROR! There was an error removing RBS installer files. Please try manually" -ForegroundColor RED
            #Write-Host "$($error[0].exception.message)" -ForegroundColor RED
            write-host $LineSepDashes
            continue
        }
        #EndRegion Remove RBS Files
    }
    #ENDregion Copy RBS files, Install RBS, Delete RBS Files


    #Region Setting Service Username/Password
    Write-Host "Setting service run as $RBSusername on $Computer" -ForegroundColor CYAN
    try {
        Get-CimInstance Win32_Service -computer $Computer -Filter "Name='Rubrik Backup Service'" | Invoke-CimMethod -MethodName Change -Arguments @{ StartName = $RBSUsername; StartPassword = $RBSPassword } | out-null
    } catch {
        Write-Host "ERROR! Did not set the username properly on $Computer. Please check manually"
    }
    #EndRegion Setting Service Username/Password



    #Region Restarting Service on remote computer
    Start-Sleep 5
    Write-Host "Restarting RBS service on $computer" -ForegroundColor Cyan
    try {
        Invoke-Command -ComputerName $Computer -ScriptBlock { 
            get-service "rubrik backup service" | Stop-Service 
            Start-Sleep 2
            get-service "rubrik backup service" | Start-Service
        }
    } catch {
        Write-Host "ERROR! Could not restart service properly on $Computer. Please check manually"
    }
    #EndRegion Restarting Service on remote computer


    write-host $LineSepDashes

} 
#EndRegion Loop Through Computer List

Write-Host "Script complete - $(Get-Date -format $dateformat)" -ForegroundColor Green
