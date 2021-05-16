<#
.SYNOPSIS
MAB Integration From CM

.Description
Query for valid MAC-adresses from an SCCM/MEMCM abd updates AD Users (used for MAB) in an AD.
Recommendations: Run only on Microsoft Windows OS (Windows Data Protection API). Encryption will not work on other OS! Use with Powershell Version 5.1 (ink. Active Directory Module) or higher.

.NOTES
Author : Johnny Gordon
Version : 1
Date: 2020-05-11

.EXAMPLE
Default usage : PowerShell.exe -ExecutionPolicy Bypass -File .\Update-MAB-V1.ps1 -ScriptAction Run

.EXAMPLE
Test usage (Will not update to AD) : PowerShell.exe -ExecutionPolicy Bypass -File .\Update-MAB-V1.ps1 -ScriptAction Test

.EXAMPLE
Debug usage (Extensive logging) : PowerShell.exe -ExecutionPolicy Bypass -File .\Update-MAB-V1.ps1 -ScriptAction Debug

#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Run','Test','Debug')]
    [string]$ScriptAction
)

#List of requirements
#Requires -Version 5.1
#Requires -Modules ActiveDirectory

Function Compare-ADCM{
<#
.DESCRIPTION
    The function "Compare-ADCM" will compare the MAB users from the AD and the MAB objects from the CM(Query) and define an AD action (Eg. Create, Remove, Update, ...)
#>
    [CmdletBinding()]
    param(
    [parameter(Mandatory=$true)]
        [AllowNull()]
        [Object[]]$CMData,
    [parameter(Mandatory=$true)]
        [AllowNull()]
        [Object[]]$ADData
    )

    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Converting data from AD" -PercentComplete 0
    Write-Log "" -CopyToHost
    Write-Log "COMPARING AD TO CM" -CopyToHost

    #Convert both arrays to same objectstructure for the use of "Compare-Object".
    $Compareable_ADData = New-Object -TypeName "System.Collections.ArrayList"

    #Only unique Names (IDs) in the list!
    $ADData | Group-Object -Property Name | Where-Object Count -EQ 1 | ForEach-Object {
        $tempObj = [pscustomobject]@{ID=$_.Group.Name; DESCRIPTION=$_.Group.Description}
        $null = $Compareable_ADData.Add($tempObj)
    }
    Write-Log "Checking for duplicates in the list from AD"
    #For duplicate Names (IDs), use only the first!
    $ADData | Group-Object -Property Name | Where-Object Count -GT 1 | ForEach-Object {
        Write-Log "The AD list contained duplicates! Skipped the duplicate of $($_.Group[0].Name), $($_.Group[0].Description)" -LogLevel 2 -CopyToHost

        $tempObj = [pscustomobject]@{ID=$_.Group[0].Name; DESCRIPTION=$_.Group[0].Description}
        $null = $Compareable_ADData.Add($tempObj)
    }
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Converting data from CM" -PercentComplete 25 
    $Compareable_CMData = New-Object -TypeName "System.Collections.ArrayList"
    #Only unique MACs (IDs) in the list!
    $CMData | Group-Object -Property MAC | Where-Object Count -EQ 1 | ForEach-Object {
        $tempObj = [pscustomobject]@{ID=$_.Group.MAC; DESCRIPTION=$_.Group.Description}
        $null = $Compareable_CMData.Add($tempObj)
    }
    Write-Log "Checking for duplicates in the list from CM"
    #For duplicate MAC (IDs), use only the first!
    $CMData | Group-Object -Property MAC | Where-Object Count -GT 1 | ForEach-Object {
        Write-Log "The CM list contained duplicates! Skipped the duplicate of $($_.Group[0].MAC), $($_.Group[0].Description)" -CopyToHost
        
        $tempObj = [pscustomobject]@{ID=$_.Group[0].MAC; DESCRIPTION=$_.Group[0].Description}
        $null = $Compareable_CMData.Add($tempObj)
    }
    
    #Compare the lists
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Default comparing method" -PercentComplete 50 
    Write-Log "Starting the default comparing method"
    $Analyze = Compare-Object -ReferenceObject $Compareable_CMData -DifferenceObject $Compareable_ADData -Property ID,DESCRIPTION -IncludeEqual -ErrorAction Stop

    #Create a new arraylist for the result
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Enhanced/Detailed comparing method" -PercentComplete 75 
    $AnalyzedList = New-Object -TypeName "System.Collections.ArrayList"

    #Find unique objects only present in CM.
    Write-Log "Looking for unique objects only present in CM"
    ($Analyze | Group-Object -Property ID | Where-Object Count -EQ 1).Group | Where-Object SideIndicator -EQ '<=' | ForEach-Object {
            Write-Log "$($_.ID),$($_.DESCRIPTION) was set to CREATE"
            
            $tempObj = [pscustomobject]@{ID=$_.ID; DESCRIPTION=$_.DESCRIPTION; ACTION='CREATE'}
            $null = $AnalyzedList.Add($tempObj)
    }
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Enhanced comparing method " -PercentComplete 80 

    #Find objects present in AD & CM. And CM has a another description for the object.
    Write-Log "Looking for objects present in CM & AD. And CM has a another description for the object."
    ($Analyze | Group-Object -Property ID | Where-Object Count -GT 1).Group | Where-Object SideIndicator -EQ '<=' | ForEach-Object {
            Write-Log "$($_.ID),$($_.DESCRIPTION) was set to UPDATE"
            
            $tempObj = [pscustomobject]@{ID=$_.ID; DESCRIPTION=$_.DESCRIPTION; ACTION='UPDATE'}
            $null = $AnalyzedList.Add($tempObj)
    }
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Enhanced comparing method " -PercentComplete 85 

    #Find unique objects only present in AD.
    Write-Log "Looking for unique objects only present in AD."
    ($Analyze | Group-Object -Property ID | Where-Object Count -EQ 1).Group | Where-Object SideIndicator -EQ '=>' | ForEach-Object {
            Write-Log "$($_.ID),$($_.DESCRIPTION) was set to REMOVE"
            
            $tempObj = [pscustomobject]@{ID=$_.ID; DESCRIPTION=$_.DESCRIPTION; ACTION='REMOVE'}
            $null = $AnalyzedList.Add($tempObj)
    }
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Enhanced comparing method " -PercentComplete 90 

    #Find objects present in AD & CM. Where AD has a another description for the object.
    Write-Log "Looking for objects present in CM & AD. And AD has a another description for the object."
    ($Analyze | Group-Object -Property ID | Where-Object Count -GT 1).Group | Where-Object SideIndicator -EQ '=>' | ForEach-Object {
            Write-Log "$($_.ID),$($_.DESCRIPTION) was SKIPPED!"
    }
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Enhanced comparing method " -PercentComplete 95 

    #Find unique objects present in AD & CM with the same description.
    Write-Log "Looking for unique objects present in AD & CM with the same description."
    ($Analyze | Group-Object -Property ID | Where-Object Count -EQ 1).Group | Where-Object SideIndicator -EQ '==' | ForEach-Object {
            Write-Log "$($_.ID),$($_.DESCRIPTION) was set to NONE"

            $tempObj = [pscustomobject]@{ID=$_.ID; DESCRIPTION=$_.DESCRIPTION; ACTION='NONE'}
            $null = $AnalyzedList.Add($tempObj)
    }
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Status "Enhanced comparing method " -PercentComplete 100 
    Write-Progress -Id 1 -ParentId 0 -Activity "Analyzing" -Completed

    Write-Log "An update would do the following to AD-users(MAB)" -CopyToHost
    Write-Log "Create $(($AnalyzedList | Where-Object ACTION -EQ 'CREATE' | Measure-Object).Count) users" -CopyToHost
    Write-Log "Update $(($AnalyzedList | Where-Object ACTION -EQ 'UPDATE' | Measure-Object).Count) users" -CopyToHost
    Write-Log "Remove $(($AnalyzedList | Where-Object ACTION -EQ 'REMOVE' | Measure-Object).Count) users" -CopyToHost
    Write-Log "Keep $(($AnalyzedList | Where-Object ACTION -EQ 'NONE' | Measure-Object).Count) users" -CopyToHost
    
    return($AnalyzedList)
}

Function Convert-CMMABQuery{
<#
.DESCRIPTION
    The function "Convert-CMMABQuery" will convert (and validate) the CM query 
    to objects that can be used when comparing with the AD query. 
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory,
                    ValueFromPipeline)]
        [Object[]]$CMObject,
        [parameter(Mandatory=$true)]
        [int]$Count,
        [parameter(Mandatory=$true)]
        $QueryTranslation
    )

    BEGIN {
        Write-Log 'Converting the results from the CMQuery to Objects'
        $MABObjects = New-Object -TypeName "System.Collections.ArrayList"

        #Replace the placeholders (<Variable>) from Config to PS-variables ($Variable).
        $TranslateMAC = ($QueryTranslation.MAC -replace '<(?=(.+>))', '$($CMObject.') -replace '>', ')'
        $TranslateDescription = ($QueryTranslation.Description -replace '<(?=(.+>))', '$($CMObject.') -replace '>', ')'

        #Progress Counter
        $i = 0
    }
    PROCESS {
        Write-Progress -Id 1 -ParentId 0 -Activity "Converting" -Status "Processing item $i out of $Count" -PercentComplete ((($i++)/$Count)*100)
        $MABObject = New-Object -TypeName psobject

        try{
            #Create the MAC
            $MAC = $ExecutionContext.InvokeCommand.ExpandString($TranslateMAC) | Convert-MACMAB -ErrorAction Stop
            #Create a description with information about the Computer.
            $DESCRIPTION = $ExecutionContext.InvokeCommand.ExpandString($TranslateDescription)

            Write-Log "$i MAC: '$MAC', Description: '$DESCRIPTION'"

            $MABObject | Add-Member -MemberType NoteProperty -Name 'MAC' -Value $MAC
            $MABObject | Add-Member -MemberType NoteProperty -Name 'DESCRIPTION' -Value $DESCRIPTION
            $MABObjects.add($MABObject) | Out-Null
        }catch{
            Write-Log "An error occured when converting the cm query to objects. The object was skipped. $_" -LogLevel 3
            Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
            Write-Warning "An error occured when converting the cm query to objects. The object was skipped. $_"
        }
    }
    END {
        Write-Log 'Conversion is done'
        Write-Log "CM responded with; $(($MABObjects | Measure-Object).count) valid objects" -CopyToHost
        Write-Progress -Id 1 -ParentId 0 -Activity "Converting" -Status "Done" -Completed
        return($MABObjects)
    }
}

Function Convert-MACMAB{
<#
.DESCRIPTION
    The function "Convert-MACMAB" will convert the MAC-adress in a Hexadecimal 
    representation to the standard IEEE "human-friendly" format. Eg."FF-FF-FF-FF-FF-FF".
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,
                    ValueFromPipeline)]
        [string]$MAC
    )

    if($DebugMode){Write-Log "Will try to convert '$MAC'"}
    #Trimming and replace other known octet seperators.
    $FormatedMAC = $MAC.Trim().replace(' ','').toUpper().replace(':','-').replace('.','-')

    #Insert the octet seperator "-" if its missing.
    if($FormatedMAC.Length -eq 12){
        $FormatedMAC = ($FormatedMAC -split '(\w{2})' | ? {$_}) -join '-'
    }

    if($FormatedMAC -match "^[A-F0-9]{2}([-][A-F0-9]{2}){5}$"){
        if($DebugMode){Write-Log "Convertion of '$MAC' to '$FormatedMAC' was successful."}
    }else{
        Write-Log "Convertion of '$MAC' to a valid MAC-adress for MAB failed!" -LogLevel 2
        Write-Error "Convertion of '$MAC' to a valid MAC-adress for MAB failed!"
    }

    #Return the formated MAC.
    return ($FormatedMAC)
}

Function Get-CMMABQuery{
<#
.DESCRIPTION
    The function "Get-CMMABQuery" will invoke and validate the response for a predefined Query in CM.
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$CredUser,
        [parameter(Mandatory=$true)]
        [string]$ProviderMachineName,
        [parameter(Mandatory=$true)]
        [string]$SiteCode,
        [parameter(Mandatory=$true)]
        [string]$QueryID,
        [parameter(Mandatory=$true)]
        [string]$QueryCollection,
        [parameter(Mandatory=$true)]
        $ExpectedProps
    )
    Write-Log 'Creating the query to CM'

    # Customizations
    $initParams = @{}
    $initParams.Add("ErrorAction", "Stop") #Stop the script on any errors

    # Import the ConfigurationManager.psd1 module 
    if((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams | Out-Null
    }

    # Connect to the site's drive if it is not already present
    if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams -Credential $CredUser | Out-Null
    }

    # Set the current location to be the site code.
    Set-Location "$($SiteCode):\" @initParams

    Write-Log "Invoking CM Query '$QueryID'"
    $CMQuery = Invoke-CMQuery -Id $QueryID -LimitToCollectionId $QueryCollection

    Write-Log 'Validating CM response!'
    #Verify that the response is an array of objects with a set of expected properties.
    if(($CMQuery -ne $null) -and ($CMQuery.GetType().Name -eq "Object[]")){
            
        #Get the properties of the objects.
        $ResultProp = $CMQuery[0] | Get-Member -MemberType Property

        #Expected count of object properties
        $ExpectedPropsCount = ($ExpectedProps | Measure-Object).count

        #Result count of expected object properties
        $ResultPropsCount = (($ResultProp | Where-Object {$ExpectedProps -contains $_.Name}) | Measure-Object).count

        #Verify that all the expected properties are present in the result.
        if($ResultPropsCount -eq $ExpectedPropsCount){
            Write-HostMasked "CM Query was successful."
            Write-Log "Recevied $(($CMQuery | Measure-Object).count) objects from the CM Query."
            return($CMQuery)
        }else{
            Write-Log "Expected properties was not found in the CM response!" -LogLevel 3
            Write-Error "Expected properties was not found in the CM response!" -ErrorAction Stop
        }
    }else{
        Write-Log "Not found or possible changes in the CM Query!" -LogLevel 3
        Write-Error "Not found or possible changes in the CM Query!" -ErrorAction Stop
    } 
}

Function Get-ADMABUsers{
<#
.DESCRIPTION
    The function "Get-ADMABUsers"will retrieve accounts from the AD to be compared to the updated information in CM(Query).
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$CredUser,
        [parameter(Mandatory=$true)]
        [string]$Server,
        [parameter(Mandatory=$true)]
        [string]$SearchBase

    )

    #Collect the MAB users
    try{
        #Collect all the users
        $Users = Get-ADUser -Filter "Name -like '*'" -Server $Server -SearchBase $SearchBase -Properties Description, distinguishedName -Credential $CredUser -ErrorAction Stop | Select-Object Name,Description
        Write-Log "AD responded with: $(($Users | Measure-Object).Count) objects (Total)"

        #Select only the users with a valid mac-adress as Name
        $Users = $Users | Where-Object {$_.Name -match "^[A-F0-9]{2}([-][A-F0-9]{2}){5}$"}
        Write-Log "AD responded with: $(($Users | Measure-Object).Count) objects (Filtered on valid MAC-adress)" -CopyToHost
        return($Users)
    }
    catch{
        Write-Log "Error when trying to retrieve the users from AD: $_" -LogLevel 2 -CopyToHost
        Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
        Write-Error "Error when trying to retrieve the users from AD: $_" -ErrorAction Stop
        return($null)
    }
}

Function Import-Credential{
<#
.DESCRIPTION
    The function "Import-Credential" will load the credentials encrypted to a file or ask for new credentials if the file is missing and save it.
#>
    [CmdletBinding()]
    param(
    [parameter(Mandatory=$true)]
        [string]$FilePath,
    [parameter(Mandatory=$true)]
        [string]$Info
    )

    if(Test-Path -Path $FilePath){
        Write-Log "Loading credentials from file: $FilePath"
        $Credential = Import-CliXml -Path $FilePath -ErrorAction Stop
    }else{
        Write-Log "No saved credentials was found at: $FilePath" -LogLevel 2
        Write-Log "Prompting for credentials" -CopyToHost
        $Credential = Get-Credential -Message $Info -ErrorAction Stop
        if($Credential -ne $null){
            Write-Log "Saving credentials to file: $FilePath"
            $Credential | Export-CliXml -Path $FilePath -Force:$true -ErrorAction SilentlyContinue
        }
    }

    if($Credential -eq $null){
        Write-Log "Credentials could not be Imported!" -CopyToHost -LogLevel 3
        Write-Error "Credentials could not be Imported!" -ErrorAction Stop
    }

    return($Credential)
}

Function Remove-Log{
<#
.DESCRIPTION
    The function "Remove-Log" will remove old logs (incl. Debug).
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$Title
    )

    try {
        #Remove all logs older than 1 month.
        $OldLog = Get-ChildItem -Path $PSScriptRoot -Include *.log -Force -Recurse | Where-Object -FilterScript {
                ($_.Name -ilike "*$($Title)*") -and (((Get-Date)-($_.CreationTime)).Months -ge 1)
            }
        $OldLog | ForEach-Object {Write-Log "Removing old log: $_"}
        $OldLog | Remove-Item -Force -ErrorAction Stop

        #Remove all debug-logs if not in debug.
        if(!($DebugMode)){
            $DebugLog = Get-ChildItem -Path $PSScriptRoot -Include *.log -Force -Recurse | Where-Object -FilterScript {
                ($_.Name -ilike "*$($Title)*Debug*")
            }
            $DebugLog | ForEach-Object {Write-Log "Removing debug log: $_"}
            $DebugLog | Remove-Item -Force -ErrorAction Stop
        }
    } catch {
        Write-Log "An error ocurred when removing old logs. $_" -LogLevel 2
        Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
        Write-Error "An error ocurred when removing old logs. $_"
    }
}

Function Send-ReportByMail{
<#
.DESCRIPTION
    The function "Send-ReportByMail" will run all the functions needed to updated MAB-users.
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory,
                    ValueFromPipeline)]
        [pscustomobject]$Stats,
        [parameter(Mandatory=$true)]
        [string]$Recipient,
        [parameter(Mandatory=$true)]
        [string]$Sender,
        [parameter(Mandatory=$true)]
        [string]$SMTPServer,
        [parameter(Mandatory=$true)]
        [string]$CM_SMSProvider,
        [parameter(Mandatory=$true)]
        [string]$CM_QueryID,
        [parameter(Mandatory=$true)]
        [string]$AD_Domain
    )
    #ToDo: Replace with "mailkit".

    $MailSubject = "Updated Staging - Report"
    $MailBody = 
@"
    A total of $($Stats.Created+$Stats.Updated+$Stats.Kept) MAC addresses where approved for staging by '$CM_SMSProvider' (Query: '$CM_QueryID').
    The approval was updated to '$AD_Domain' @ $(Get-Date -Format "yyyy-MM-dd HH:mm")

    Statistics from the update
    Created(New): $($Stats.Created)
    Updated descriptions: $($Stats.Updated)
    Removed: $($Stats.Removed)
    Kept: $($Stats.Kept)

    This message was generated on $($env:computername)
"@
    Write-Log "" -CopyToHost
    Write-Log "SENDING REPORT" -CopyToHost
    Write-Log "Recipient: $Recipient"
    Write-Log "Subject: $MailSubject"
    Write-Log "Body: $MailBody" -Masked:$false

    try{
        Send-MailMessage -From $Sender -To $Recipient -Subject $MailSubject -Body $MailBody -SmtpServer $SMTPServer -ErrorAction Stop
        Write-Log "Wait for the postman. ;)" -CopyToHost
    }catch{
        Write-Log "An error ocurred when trying to send the report by email." -CopyToHost -LogLevel 3
        Write-Log "$_" -LogLevel 3
        Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
    }
}

Function Start-MainScript{
<#
.DESCRIPTION
    The function "Start-MainScript" will run all the functions needed to update AD-users for MAB.
#>
    [CmdletBinding()]
        param(
            [parameter(Mandatory=$false)]
            [Switch]$NoUpdate
        )

    #Load the config settings.
    $ConfigPath = Join-Path $PSScriptRoot 'config.psd1'
    $Config = Import-PowerShellDataFile $ConfigPath -ErrorAction Stop
    $ConfigFileInfo = "Configurationfile Info: Version: $($Config.Version), Owner: $((Get-Acl -Path $ConfigPath).Owner), CreationTime: $((Get-ItemProperty -Path $ConfigPath).CreationTime), LastWriteTime: $((Get-ItemProperty -Path $ConfigPath).LastWriteTime)"
    Write-Log $ConfigFileInfo -Masked:$false

    #Path to the stored credential to AD and CM
    $Cred_FileAD = Join-Path $PSScriptRoot "AD-Credential-${env:USERNAME}-${env:COMPUTERNAME}.xml"
    $Cred_FileCM = Join-Path $PSScriptRoot "CM-Credential-${env:USERNAME}-${env:COMPUTERNAME}.xml"

    #Define and clear variables
    $AnalyzedResults = $null
    $ADObjects = $null
    $CMResponse = $null
    $CMObjects = $null
    $CMCredential = $null
    $ADCredential = $null
    $cm = $null
    $styx = $null
    
    #Show Settings
    $BaseSettings = 
@"

ACTIVE DIRECTORY SETTINGS
Domain: $($Config.ADSettings.Domain)
ChangeBase: $($Config.ADSettings.ChangeBase)
PasswordPolicy(AD GROUP) : $($Config.ADSettings.GroupPasswordPolicy)
VLAN(AD GROUP) : $($Config.ADSettings.GroupVLAN)

CONFIGURATION MANAGER SETTINGS
SideCode: $($Config.CMSettings.SiteCode)
SMSProvider: $($Config.CMSettings.SMSProvider)
QueryID: $($Config.CMSettings.QueryID)
QueryCollectionID: $($Config.CMSettings.QueryCollection)
Expected objects from CM: $($Config.CMSettings.ExpectedMin) - $($Config.CMSettings.ExpectedMax)

OTHER SETTINGS
MailRecipient: $($Config.OtherSettings.Mail.Recipient)
MailSender: $($Config.OtherSettings.Mail.Sender)
MailSMTPServer: $($Config.OtherSettings.Mail.SMTPServer)
CredentialFile AD: $Cred_FileAD
CredentialFile CM: $Cred_FileCM
"@

    Write-Log $BaseSettings -CopyToHost
    Write-Progress -Id 0 -Activity "Main" -Status 'Load/Create credentials' -PercentComplete 0

    #Import the credentials for CM.
    $CMCredential = Import-Credential -FilePath $Cred_FileCM -Info "Input credentials for CM ($(($Config.CMSettings.SMSProvider))). Credentials will be encrypted for use by ${env:USERNAME} on ${env:COMPUTERNAME}" -ErrorAction Stop
    #Import the credentials for AD.
    $ADCredential = Import-Credential -FilePath $Cred_FileAD -Info "Input credentials for AD ($(($Config.ADSettings.Domain))). Credentials will be encrypted for use by ${env:USERNAME} on ${env:COMPUTERNAME}" -ErrorAction Stop
    #Verify the Account 
    Test-ADCredential -Server $Config.ADSettings.Domain -Username $ADCredential.UserName -Password $ADCredential.GetNetworkCredential().Password -ErrorAction Stop

    Write-Progress -Id 0 -Activity "Main" -Status 'Selecting a fixed DC' -PercentComplete 1

    #Choose one domain controller to work with. 
    $DomainControllers = Get-ADDomainController -Filter * -Server $Config.ADSettings.Domain -Credential $ADCredential  -ErrorAction Stop | Select-Object Hostname

    #Select the first one.
    if(($DomainControllers | Measure-Object).Count -gt 0){
        $AD_SelectedDC = $DomainControllers[0].Hostname
        Write-Log "Selected DC: $AD_SelectedDC" -CopyToHost
    }else{
        Write-Log "Could not select a DC!" -LogLevel 2 -CopyToHost
        Write-Error "Could not select a DC!"
    }

    Write-Progress -Id 0 -Activity "Main" -Status "Importing from CM $($Config.CMSettings.SMSProvider)" -PercentComplete 10

    $CMResponse = Get-CMMABQuery -CredUser $CMCredential -ProviderMachineName $Config.CMSettings.SMSProvider -SiteCode $Config.CMSettings.SiteCode -QueryID $Config.CMSettings.QueryID -QueryCollection $Config.CMSettings.QueryCollection -ExpectedProps $Config.CMSettings.QueryValidation.ExpectedProps -ErrorAction Stop
    Write-Progress -Id 0 -Activity "Running" -Status "Converting CM ($($Config.CMSettings.SMSProvider)) data" -PercentComplete 10
    $CMObjects = $CMResponse | Convert-CMMABQuery -Count ($CMResponse | Measure-Object).Count -QueryTranslation $Config.CMSettings.QueryTranslation -ErrorAction Stop

    Write-Progress -Id 0 -Activity "Main" -Status "Importing from AD" -PercentComplete 20
    $ADQueryResults = Get-ADMABUsers -Server $AD_SelectedDC -SearchBase $Config.ADSettings.ChangeBase -CredUser $ADCredential -ErrorAction Stop

    if((($CMObjects | Measure-Object).Count -ge $Config.CMSettings.ExpectedMin) -and (($CMObjects | Measure-Object).Count -le $Config.CMSettings.ExpectedMax)){
        Write-Progress -Id 0 -Activity "Main" -Status 'Analyzing data' -PercentComplete 30
        $AnalyzedResults = Compare-ADCM -CMData $CMObjects -ADData $ADQueryResults -ErrorAction Stop

        if(!$NoUpdate){
            Write-Progress -Id 0 -Activity "Main" -Status "Updating" -PercentComplete 40

            $UpdateSettings = @{
                AD = $Config.ADSettings.Domain
                Server = $AD_SelectedDC
                ChangeBase = $Config.ADSettings.ChangeBase
                GroupPP = $Config.ADSettings.GroupPasswordPolicy
                GroupVLAN = $Config.ADSettings.GroupVLAN
                Count = ($AnalyzedResults | Measure-Object).Count
            }

            $ReportSettings =@{
                Recipient = $Config.OtherSettings.Mail.Recipient
                Sender = $Config.OtherSettings.Mail.Sender
                SMTPServer = $Config.OtherSettings.Mail.SMTPServer
                CM_SMSProvider = $Config.CMSettings.SMSProvider
                CM_QueryID = $Config.CMSettings.QueryID
                AD_Domain = $Config.ADSettings.Domain
            }

            $AnalyzedResults | Update-ADMABUser @UpdateSettings -Verify -CredUser $ADCredential -ErrorAction Stop | Send-ReportByMail @ReportSettings -ErrorAction Continue
        }
        Write-Progress -Id 0 -Activity "Main" -Completed
    }else{
        Write-Log "" -CopyToHost   
        Write-Log "The number of objects received from CM $($Config.CMSettings.SMSProvider) was out of the specified range $($Config.CMSettings.ExpectedMin) - $($Config.CMSettings.ExpectedMax). No changes was made!" -LogLevel 2 -CopyToHost    
        Write-Log "Check the CM or CM Query for changes or problems." -LogLevel 2 -CopyToHost
    }
}

Function Start-Log{
<#
.DESCRIPTION
    The function "Start-Log" will initiate the logging of this script.
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$Title
    )
    try {
        $DirPath = Join-Path $PSScriptRoot "Logs"

        if($DebugMode){
            $FilePath = Join-Path $DirPath "$($Title)-Debug-$(Get-Date -Format FileDateTimeUniversal).log"
        }else{
            $FilePath = Join-Path $DirPath "$($Title)-Log-$(Get-Date -Format FileDateTimeUniversal).log"
        }

        New-Item -ItemType Directory -Path $DirPath -Force:$true -ErrorAction Stop | Out-Null
        New-Item -ItemType File -Path $FilePath -ErrorAction Stop | Out-Null

        # Set the global variable to be used as the FilePath for all subsequent Write-Log calls in this session
        $global:ScriptLogFilePath = $FilePath
    } catch {
        Write-Error "Error ocurred when starting the log $_" -ErrorAction Stop
    }
}

Function Test-ADCredential{
<#
.DESCRIPTION
    The function "Test-ADCredential" will test if a AD user credentials for MAB is correct.
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [String]$Server,
        [parameter(Mandatory=$true)]
        [String]$Username,
        [parameter(Mandatory=$true)]
        [String]$Password
    )

    $LDAPDC = "LDAP://"+$Server
      
    Try{
        # Get Domain
        $DirEntry = New-Object System.DirectoryServices.DirectoryEntry($LDAPDC,$Username,$Password) -ErrorAction Stop
        if($DirEntry.name -ne $null){
            Write-Log "Successfully authenticated: $Username"
        }else{
            Write-Log "The tested credential was wrong or the server did not respond." -LogLevel 3
            Write-Error "The tested credential was wrong or the server did not respond."
        }
    }Catch{
        Write-Log "Error when testing the credential to AD. $_" -LogLevel 3
        Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
        Write-Error "Error when testing the credential to AD. $_e"
    }
}

Function Update-ADMABUser{
<#
.DESCRIPTION
    The function "Update-ADMABUser will update(Create, Remove or Update) the AD accounts.
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$CredUser,
        [parameter(Mandatory=$true)]
        [string]$AD,
        [parameter(Mandatory=$true)]
        [string]$Server,
        [parameter(Mandatory=$true)]
        [string]$ChangeBase,
        [parameter(Mandatory=$false)]
        [string]$GroupPP,
        [parameter(Mandatory=$false)]
        [string]$GroupVLAN,
        [parameter(Mandatory,
                    ValueFromPipeline)]
        [pscustomobject]$User,
        [parameter(Mandatory=$true)]
        [int]$Count,
        [parameter(Mandatory=$false)]
        [Switch]$Verify
    )

    BEGIN{
        Write-Log "" -CopyToHost
        Write-Log "UPDATING USERS IN AD" -CopyToHost

        if($PSBoundParameters.ContainsKey('GroupPP')){
            Write-Log "Assigning users to AD-group '$GroupPP' to lower the Fine-grained passwordpolicy for MAB users."
            $PasswordPolicyGroup = Get-ADGroup -Server $Server -Filter "name -eq '$GroupPP'" -Credential $CredUser -ErrorAction Stop
        }
        if($PSBoundParameters.ContainsKey('GroupVLAN')){
            Write-Log "Assigning users to AD-group '$GroupVLAN'"
            $VLANGroup = Get-ADGroup -Server $Server -Filter "name -eq '$GroupVLAN'" -Credential $CredUser -ErrorAction Stop
        }
        $EmailBase = "@$AD"
        #Progress counter
        $i = 0
        #Statistics
        $Created = 0
        $Updated = 0 
        $Removed = 0
        $Kept = 0
    }

    PROCESS{
        Write-Progress -Id 2 -ParentId 0 -Activity "Processing item $i out of $Count" -PercentComplete ((($i++)/$Count)*100)

        #Check the MAC-address! 
        if($DebugMode){Write-Log "Checking if the MAC-adress $($User.ID) has the correct format."}
        if($User.ID -match "^[A-F0-9]{2}([-][A-F0-9]{2}){5}$"){
            if($DebugMode){Write-Log 'MAC format was correct!'}

            if($User.Action -eq 'REMOVE'){
                Try{
                    Write-Log "Remove: $($User.ID), $($User.DESCRIPTION)" -CopyToHost
                    Remove-ADUser -Identity $User.ID -Server $Server -Confirm:$false -Credential $CredUser -ErrorAction Stop
                    $Removed++
                }Catch{
                    Write-Log "Error when removing the user: $_" -LogLevel 3 -CopyToHost
                    Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
                }

            }elseif($User.Action -eq 'UPDATE'){
                Try{
                    Write-Log "Update: $($User.ID), $($User.DESCRIPTION)" -CopyToHost
                    Set-ADUser -Identity $User.ID -Description $User.DESCRIPTION -Server $Server -Credential $CredUser -ErrorAction Stop
                    $Updated++
                }Catch{
                    Write-Log "Error when updating the user: $_" -LogLevel 3 -CopyToHost
                    Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
                }

            }elseif($User.Action -eq 'CREATE'){
                Try
                {
                    #Test if the user exists.
                    $NewUser = Get-ADUser -Server $Server -Filter "Name -eq '$($User.ID)'" -Credential $CredUser -ErrorAction Stop
                    
                    if($NewUser -eq $null){
                        Write-Log "Create: $($User.ID), $($User.DESCRIPTION)" -CopyToHost
                        
                        if($PasswordPolicyGroup -ne $null){
                            #Create the user with Fine-grained passwordpolicy in AD.

                            #Create a complex password for temporary use.
                            Add-Type -AssemblyName System.Web
                            $TempPassword = [System.Web.Security.Membership]::GeneratePassword(50,10)

                            #Create the user
                            $UserSettings = @{
                                Name = $User.ID
                                SamAccountName = $User.ID 
                                UserPrincipalName = $User.ID + $EmailBase
                                AccountPassword = ConvertTo-SecureString -String $TempPassword -AsPlainText -Force
                                Description = $User.DESCRIPTION 
                                Enabled = $True 
                                PasswordNeverExpires = $True 
                                CannotChangePassword = $True 
                                Path = $ChangeBase 
                            }

                            $NewUser = New-ADUser @UserSettings -Server $Server -Credential $CredUser -Confirm:$False -PassThru -ErrorAction Stop
                            $Created++

                            #Add the user to the group for Fine-grained lower password policy.
                            Add-ADGroupMember -Server $Server -Identity $PasswordPolicyGroup -Members $NewUser -Credential $CredUser -ErrorAction Stop

                            #Change password to MAC-adress.
                            Set-ADAccountPassword -Server $Server -Identity $User.ID -Reset -NewPassword (ConvertTo-SecureString -String $User.ID -AsPlainText -Force) -Credential $CredUser -ErrorAction Stop
                        }else{
                            #Create the user
                            $UserSettings = @{
                                Name = $User.ID
                                SamAccountName = $User.ID 
                                UserPrincipalName = $User.ID + $EmailBase
                                AccountPassword = ConvertTo-SecureString -String $User.ID -AsPlainText -Force
                                Description = $User.DESCRIPTION 
                                Enabled = $True 
                                PasswordNeverExpires = $True 
                                CannotChangePassword = $True 
                                Path = $ChangeBase 
                            }
                            $NewUser = New-ADUser @UserSettings -Server $Server -Credential $CredUser -Confirm:$False -PassThru -ErrorAction Stop
                            $Created++
                        }

                        if($VLANGroup -ne $null){
                            #Add the user to the group
                            Add-ADGroupMember -Server $Server -Identity $VLANGroup -Members $NewUser -Credential $CredUser -ErrorAction Stop
                        }

                        #Test if the account is in AD as expected.
                        if($Verify){
                            #If waiting for AD sync is required, remove comment(#) on next line.
                            #Start-Sleep -Milliseconds 500
                            Test-ADCredential -Username $NewUser.SamAccountName -Password $NewUser.SamAccountName -Server $Server -ErrorAction Stop
                        }
                    }else{
                        Write-Log "$($User.ID) already exist in AD." -LogLevel 2
                    }
                }Catch {
                    Write-Log "Error when creating the user: $_" -LogLevel 3 -CopyToHost -ErrorAction Continue
                    Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
                }
            }elseif($User.Action -eq 'NONE'){
                Write-Log "No action will be made against the AD for '$($User.ID)'"
                $Kept++
            }else{
                Write-Log "$($User.Action) is an unknown action and has no defined action against the AD!" -LogLevel 3
                Write-Error -Message "$($User.Action) is an unknown action and has no defined action against the AD!" -LogLevel 3 -ErrorAction Stop
            }
        }else{
            Write-Log 'MAC-adress format was wrong! Item was skipped!' -LogLevel 2
        }
    }

    END{
        Write-Progress -Id 2 -ParentId 0 -Activity "Updating Active Directory" -Completed
        Write-Log "Created $Created users" -CopyToHost
        Write-Log "Updated $Updated users" -CopyToHost
        Write-Log "Removed $Removed users" -CopyToHost
        Write-Log "Kept $Kept users" -CopyToHost

        $UpdateStats = New-Object PSObject -Property @{
            Created = $Created
            Updated = $Updated
            Removed = $Removed
            Kept = $Kept
        }

        return($UpdateStats)
    }
}

Function Write-HostMasked{
<#
.DESCRIPTION
    The function "Write-HostMasked" will write to the host (Masked or unmasked).
#>
    [CmdletBinding()]
    param (
        [Parameter(Position=0)]
        [AllowNull()]
        $Message
    )
    
    if(!$DebugMode){
        #Mask the main part of MAC-adresses (format) if not in debug.
        $Message = $Message -replace "([a-fA-F0-9]{2})([-.:]{0,1})([a-fA-F0-9]{2})([-.:]{0,1})([a-fA-F0-9]{2})([-.:]{0,1})([a-fA-F0-9]{2})([-.:]{0,1})([a-fA-F0-9]{2})([-.:]{0,1})([a-fA-F0-9]{2})", '**$2**$4**$6**$8$9$10$11'
    }

    Write-Host $Message
}

Function Write-Log{
<#
.DESCRIPTION
    The function "Write-Log" will write (masked or unmasked) to the log.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Message,
        [Parameter(Mandatory = $false)]
        [Switch]$CopyToHost,
        [Parameter(Mandatory = $false)]
        [Switch]$Masked = $true,
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )

    if(!$DebugMode -and $Masked){
        #Mask the main part of MAC-adresses (format) if not in debug.
        $Message = $Message -replace "([a-fA-F0-9]{2})([\W]{0,1})([a-fA-F0-9]{2})([\W]{0,1})([a-fA-F0-9]{2})([\W]{0,1})([a-fA-F0-9]{2})([\W]{0,1})([a-fA-F0-9]{2})([\W]{0,1})([a-fA-F0-9]{2})", '**$2**$4**$6**$8$9$10$11'
    }

    if($CopyToHost){
        Write-HostMasked -Message $Message
    }

    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat

    Add-Content -Value $Line -Path $global:ScriptLogFilePath -ErrorAction Continue
}

#Debug settings
$global:DebugMode = $false
#Only used with Write-Verbose
$VerbosePreference = 'SilentlyContinue'
#Set to 'Continue' if debugging or 'SilentlyContinue' in production.
$DebugPreference = 'SilentlyContinue'

#Name and version of the script
$Script_Name = "MAB_Integration_From_CM"
$Script_Version = "V1" 
$Script_Title = "$Script_Name-$Script_Version"

Write-Host "$Script_Title"

try{
    #Set the global DEBUG variable
    if($ScriptAction.ToUpper().Equals("DEBUG")){
        Write-Log "Running script in DEBUG mode!" -CopyToHost -LogLevel 2
        $global:DebugMode = $true
    }

    #Start logging
    Start-Log -Title $Script_Title

    #Start the MainScript!
    if ($ScriptAction.ToUpper().Equals("RUN") -or $ScriptAction.ToLower().Equals("debug")){
        Start-MainScript -ErrorAction Stop
    }
    elseif($ScriptAction.ToUpper().Equals("TEST")){
        Write-Log "Running script in TEST mode!" -CopyToHost -LogLevel 2
        Start-MainScript -NoUpdate -ErrorAction Stop
    }
    else{
        Write-Log "$ScriptName - No params? Use -ScriptAction run or -ScriptAction test" -CopyToHost -LogLevel 2
        $ExecutionFail = $true
    }

    #Remove old logs
    Remove-Log -Title $Script_Title

}catch{
    Write-Log "An error occurred when running the script!" -CopyToHost -LogLevel 3
    Write-Log "Errordetails! `n  MyCommand: $($Error[0].InvocationInfo.MyCommand) `n ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber) `n  PositionMessage: $($Error[0].InvocationInfo.PositionMessage)" -LogLevel 3
    $ExecutionFail = $true
}
  
Write-Log "Done!" -CopyToHost

#Return the exitcode. (Default = $false)
exit([int]$ExecutionFail)
