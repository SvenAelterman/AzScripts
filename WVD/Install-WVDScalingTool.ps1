function New-LogAnalyticsWorkspace {
	param(
		[string]$azRegion,
		[string]$azAAResourceGroupName,
		[string]$azLAName
	)

	try {
		Get-AzOperationalInsightsWorkspace -Name $azLAName -ResourceGroupName $azAAResourceGroupName -ErrorAction Stop
	}
	catch {
		Write-Warning "Creating Log Analytics Workspace $azLAName"
		New-AzOperationalInsightsWorkspace -Location $azRegion -Name $azLAName -Sku Standard `
		  -ResourceGroupName $azAAResourceGroupName	
	}
}

function New-AzureAutomationAccount {
	param(
		[string]$azRegion,
		[string]$aadTenantId,
		[string]$azSubscriptionId,
		[string]$azAAResourceGroupName,
		[string]$azAAName,
		[string]$azLAName
	)
	
	# Download the script that will create the Azure Automation Account
	$Uri = "https://raw.githubusercontent.com/Azure/RDS-Templates/master/wvd-templates/wvd-scaling-script/CreateOrUpdateAzAutoAccount.ps1"
	# Download the script
	Invoke-WebRequest -Uri $Uri -OutFile ".\CreateOrUpdateAzAutoAccount.ps1"

	# Define script parameters - assuming Spring 2020 (ARM) release only
	$Params = @{
		"Location"				= $azRegion
		"UseARMAPI"				= $true
		"AADTenantId"		 	= $aadTenantId				# Optional. If not specified, it will use the current Azure context
		"SubscriptionId"		= $azSubscriptionId			# Optional. If not specified, it will use the current Azure context
		"ResourceGroupName"		= $azAAResourceGroupName	# Optional. Default: "WVDAutoScaleResourceGroup"
		"AutomationAccountName" = $azAAName			 		# Optional. Default: "WVDAutoScaleAutomationAccount"
		"WorkspaceName"			= $azLAName			 		# Optional. If specified, Log Analytics will be used to configure the custom log table that the runbook PowerShell script can send logs to
	}

	Write-Output "Checking Log Analytics Workspace"

	New-LogAnalyticsWorkspace -azAAResourceGroupName $azAAResourceGroupName -azRegion $azRegion `
		-azLAName $azLAName

	Write-Output "Creating Azure Automation Account $azAAName"

	# Create the Azure Automation Account
	# This will take several minutes
	# Be sure to capture any output
	.\CreateOrUpdateAzAutoAccount.ps1 @Params
}

function New-AzureAutomationRunAsAccount {
	param(
		[string]$automationAccountName,
		[string]$resourceGroupName,
		[string]$subscriptionId,
		[string]$keyVaultName,
		[string]$location,
		[string]$tempFolder,
		[string]$aadTenantId
	)
	
	$GetKeyVault = Get-AzKeyVault -VaultName $keyVaultName
	[int]$Retries = 0

	while (!$GetKeyVault -And $Retries -le 6) {
		$Retries = $Retries++
		Write-Warning -"Key Vault not found. Creating the Key Vault $keyVaultName."
	
		$NewKeyVault = New-AzKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -Location $location
	
		if (!$NewKeyVault) {
			Write-Error "Key Vault $keyVaultName creation failed."
			return
		}

		Start-Sleep -s 15
		$GetKeyVault = Get-AzKeyVault -VaultName $keyVaultName
	}
	
	[string]$ApplicationDisplayName = $automationAccountName
	# TODO: Improve randomness
	[string]$SelfSignedCertPlainPassword = [Guid]::NewGuid().ToString().Substring(0, 8) + "!"
	[int]$NoOfMonthsUntilExpired = 36
	
	$CertifcateAssetName = "AzureRunAsCertificate"
	$CertificateName = $automationAccountName + $CertifcateAssetName
	$PfxCertPathForRunAsAccount = Join-Path $tempFolder ($CertificateName + ".pfx")
	$PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
	$CerCertPathForRunAsAccount = Join-Path $tempFolder ($CertificateName + ".cer")
	$CertSubjectName = "cn=" + $CertificateName
	
	Write-Output "Generating the cert using Key Vault..."
	
	$Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" `
		-SubjectName $CertSubjectName -IssuerName "Self" `
		-ValidityInMonths $NoOfMonthsUntilExpired -ReuseKeyOnRenewal

	$AddAzureKeyVaultCertificateStatus = Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $certificateName -CertificatePolicy $Policy
	
	While ($AddAzureKeyVaultCertificateStatus.Status -eq "inProgress") {
		Write-Output "Key Vault certificate creation: $($AddAzureKeyVaultCertificateStatus.Status)"
		Start-Sleep -s 10
		$AddAzureKeyVaultCertificateStatus = Get-AzKeyVaultCertificateOperation -VaultName $keyVaultName -Name $CertificateName
	}
	
	if ($AddAzureKeyVaultCertificateStatus.Status -ne "completed") {
		Write-Error -Message "Key Vault certifcate creation is not sucessfull and its status is: $($AddAzureKeyVaultCertificateStatus.Status)"
		return
	}
	
	$SecretRetrieved = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $CertificateName
	$PfxBytes = [System.Convert]::FromBase64String($SecretRetrieved.SecretValueText)
	$CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
	$CertCollection.Import($PfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
	
	# Export the .pfx file
	$ProtectedCertificateBytes = $CertCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
	[System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $ProtectedCertificateBytes)
	
	# Export the .cer file
	$Cert = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $CertificateName
	$CertBytes = $Cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
	[System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $CertBytes)
	
	Write-Output "Creating service principal..."

	# Create Service Principal
	$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 `
		-ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
	
	$keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
	$KeyId = [Guid]::NewGuid()
	
	$startDate = Get-Date
	$endDate = (Get-Date $PfxCert.GetExpirationDateString()).AddDays(-1)
	
	# Use Key credentials and create AAD Application
	$Application = New-AzADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $applicationDisplayName) -IdentifierUris ("http://" + $KeyId)
	New-AzADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $startDate -EndDate $endDate
	New-AzADServicePrincipal -ApplicationId $Application.ApplicationId
	
	# Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
	Start-Sleep -s 15
	
	$NewRole = $null
	$Retries = 0;
	While ($null -eq $NewRole -And $Retries -le 6) {
		New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -scope ("/subscriptions/" + $subscriptionId) -ErrorAction SilentlyContinue
		Start-Sleep -s 10
		$NewRole = Get-AzRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
		$Retries++;
	}
	
	Write-Output "Creating Automation account"
	New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $Location
	
	Write-Output "Creating Certificate in the Asset..."
	# Create the automation certificate asset
	$CertPassword = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force
	Remove-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -automationAccountName $AutomationAccountName -Name $certifcateAssetName -ErrorAction SilentlyContinue
	New-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -automationAccountName $AutomationAccountName -Path $PfxCertPathForRunAsAccount -Name $certifcateAssetName -Password $CertPassword -Exportable | write-verbose
	
	# Populate the ConnectionFieldValues
	$ConnectionTypeName = "AzureServicePrincipal"
	$ConnectionAssetName = "AzureRunAsConnection"
	$ApplicationId = $Application.ApplicationId
	$Thumbprint = $PfxCert.Thumbprint
	$ConnectionFieldValues = @{"ApplicationId" = $ApplicationID; "TenantId" = $aadTenantId; "CertificateThumbprint" = $Thumbprint; "SubscriptionId" = $subscriptionId}
	
	# Create a Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
	Write-Output "Creating Connection in the Asset..."
	Remove-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName -Name $ConnectionAssetName `
		-Force -ErrorAction SilentlyContinue
	New-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $automationAccountName -Name $ConnectionAssetName `
		-ConnectionTypeName $ConnectionTypeName -ConnectionFieldValues $ConnectionFieldValues
	
	Write-Output "RunAsAccount Creation Completed..."	
}

function New-LogicApp {
	param (
		[string]$wvdHostPoolName, <# TODO: Make this is an array #>
		[string]$azAAName,
		[string]$aadTenantId,
		[string]$azSubscriptionId,
		[string]$resourceGroupName,
		[string]$azRegion,
		[int]$recurrenceInterval,
		[string]$beginPeakTime,
		[string]$endPeakTime,
		[string]$timeDifference,
		[string]$sessionThresholdPerCPU,
		[string]$minimumNumberOfRDSH,
		[string]$maintenanceTagName,
		[int]$limitSecondsToForceLogOffUser,
		[string]$logOffMessageTitle,
		[string]$logOffMessageBody,
		[string]$logAnalyticsPrimaryKey,
		[string]$logAnalyticsWorkspaceId
	)

	# Replace the Logic App definition with the custom EDU version
	$Uri = "https://raw.githubusercontent.com/Azure/RDS-Templates/master/wvd-templates/wvd-scaling-script/CreateOrUpdateAzLogicApp.ps1"
	# Download the script
	Invoke-WebRequest -Uri $Uri -OutFile ".\CreateOrUpdateAzLogicApp.ps1"

	$WVDHostPool = Get-AzResource -ResourceType "Microsoft.DesktopVirtualization/hostpools" -Name $wvdHostPoolName

	$AutoAccount = Get-AzAutomationAccount -Name $azAAName -ResourceGroupName $resourceGroupName
	# TODO: There should only be 1?
	$AutoAccountConnection = (Get-AzAutomationConnection -ResourceGroupName $AutoAccount.ResourceGroupName `
		-AutomationAccountName $AutoAccount.AutomationAccountName)[0]
		#Out-GridView -OutputMode:Single -Title "Select the Azure RunAs connection asset"

	$WebhookUri = Get-WebHookUri -azAAName $azAAName -resourceGroupName $resourceGroupName

	$Params = @{
		"AADTenantId"					= $aADTenantId						# Optional. If not specified, it will use the current Azure context
		"SubscriptionID"				= $azSubscriptionId					# Optional. If not specified, it will use the current Azure context
		"ResourceGroupName"				= $azAAResourceGroupName				# Optional. Default: "WVDAutoScaleResourceGroup"
		"Location"				  		= $azRegion						  # Optional. Default: "West US2"
		"UseARMAPI"				 		= $true
		"HostPoolName"					= $WVDHostPool.Name
		"HostPoolResourceGroupName"		= $WVDHostPool.ResourceGroupName		 # Optional. Default: same as ResourceGroupName param value
		"LogAnalyticsWorkspaceId"		= $logAnalyticsWorkspaceId			  # Optional. If not specified, script will not log to the Log Analytics
		"LogAnalyticsPrimaryKey"		= $logAnalyticsPrimaryKey				# Optional. If not specified, script will not log to the Log Analytics
		"ConnectionAssetName"			= $AutoAccountConnection.Name			# Optional. Default: "AzureRunAsConnection"
		"RecurrenceInterval"			= $recurrenceInterval				  # Optional. Default: 15
		"BeginPeakTime"					= $beginPeakTime					  # Optional. Default: "09:00"
		"EndPeakTime"					= $endPeakTime						# Optional. Default: "17:00"
		"TimeDifference"			 	= $timeDifference					 # Optional. Default: "-7:00"
		"SessionThresholdPerCPU"		= $sessionThresholdPerCPU				# Optional. Default: 1
		"MinimumNumberOfRDSH"			= $minimumNumberOfRDSH				 # Optional. Default: 1
		"MaintenanceTagName"			= $maintenanceTagName				  # Optional.
		"LimitSecondsToForceLogOffUser" = $limitSecondsToForceLogOffUser		 # Optional. Default: 1
		"LogOffMessageTitle"			= $logOffMessageTitle				  # Optional. Default: "Machine is about to shutdown."
		"LogOffMessageBody"				= $logOffMessageBody					# Optional. Default: "Your session will be logged off. Please save and close everything."
		"WebhookURI"					= $WebhookUri
	}

	$out = .\CreateOrUpdateAzLogicApp.ps1 @Params
	
	Write-Host $out

	# This is the replacement that's done to create the Logic App's name in the script called above
	return "$($WVDHostPool.Name)_Autoscale_Scheduler".Replace(" ", "-")
}

function Get-WebHookUri {
	param (
		[string]$azAAName,
		[string]$resourceGroupName
	)

	return (Get-AzAutomationVariable -Name 'WebhookURIARMBased' -ResourceGroupName $resourceGroupName `
		-AutomationAccountName $azAAName).Value
}

<#
 # VARIABLES SECTION
 # REVIEW AND CUSTOMIZE
 #>

# MUST SET VARIABLES

# Folder where script files will be downloaded to, and working directory of the script
# TODO: This folder will contain a PFX certificate file and other secrets and should be cleaned after

#$TempFolder = $env:TEMP
$TempFolder = "C:\Temp"

# TODO: Get from params

# Common Prefix (can be left blank if not desired)
$CommonResourceNamePrefix = "WVD-ScaleAuto-Test-"
# Name of the WVD Host Pool to apply scaling solution
$WVDHostPoolName = "wvd-pool-ai-gpu"
# Resource Group Name for the Azure Automation Account
$AzAAResourceGroupName = "$($CommonResourceNamePrefix)RG"
# Subscription name or ID
$SubscriptionName = "Visual Studio Enterprise (MS)"
# Set to $true if the Logic App definition should be the one created by the US EDU CSAs
$UseUsEduLogicApp = $true
# This variable is currently not used
$TimeZoneNameForPeakTime = "Central Standard Time"

# END MUST SET VARIABLES

# In minutes, how often the Logic App will run and call the Runbook to scale
$RecurrenceInterval = 15
# The start time for peak hours in local time, e.g. 9:00
$BeginPeakTime = "8:00"
# The end time for peak hours in local time, e.g. 18:00
$EndPeakTime = "17:00"
# The time difference between local time and UTC in hours, e.g. +5:30
# Note: This is not Daylight Saving Time ("Summertime") aware
$TimeDifference = "-5:00"
# Enter the maximum number of sessions per CPU that will be used as a threshold to determine when new session host VMs need to be started during peak hours
# This need not be the same number set in the host pool configuration
$SessionThresholdPerCPU = 2
# The minimum number of session host VMs to keep running during off-peak hours
$MinimumNumberOfRDSH = 1
# The minimum number of session host VMs to run during peak hours
# Note: this value is only relevant when using the US EDU customized logic app
$MinimumNumberOfRDSHPeak = 2
# The name of the Tag associated with VMs you don't want to be managed by this scaling tool
$MaintenanceTagName = "$($CommonResourceNamePrefix)scaling-dont-touch"
# Enter the number of seconds to wait before automatically signing out users. 
# If set to 0, any session host VM that has user sessions, will be left untouched
$LimitSecondsToForceLogOffUser = 900
# Enter the title of the message sent to the user before they are forced to sign out
$LogOffMessageTitle = "This session host is about to shut down"
# Enter the body of the message sent to the user before they are forced to sign out
$LogOffMessageBody = "Please save your work and log off. If you need to continue working, you may immediately log on again."

# TODO: Ensure the Az module is up-to-date

Login-AzAccount
Select-AzSubscription -Subscription $SubscriptionName
$AzContext = Get-AzContext

# Assuming the Azure AD Directory of the user is where WVD lives
# Change if necessary
$AadTenantId = $AzContext.Subscription.TenantId
$AzSubscriptionId = $AzContext.Subscription.Id
# Name for the Azure Automation Account
$AzAAName = "$($CommonResourceNamePrefix)AutomationAccount"
# Azure Region for the Automation Account, Log Analytics workspace, etc.
$AzAARegion = "eastus"
# Log Analytics workspace name
# It will be created if it doesn't exist
$AzLAName = "$($CommonResourceNamePrefix)Workspace"
# Name of the Key Vault to store the certificate for the Azure Automation Run As account
# It will be created if it doesn't exist
$KeyVaultName = "$($CommonResourceNamePrefix)KV"

# END VARIABLES SECTION

# Get a resource group object
try {
	Get-AzResourceGroup -Name $AzAAResourceGroupName -ErrorAction Stop
	Write-Verbose "Found resource group"
} 
catch {
	Write-Warning "Creating Resource Group"
	New-AzResourceGroup -Name $AzAAResourceGroupName -Location $AzAARegion
}

# Ensure the temp folder exists and switch to it
New-Item -ItemType Directory -Path $tempFolder -Force
Set-Location -Path $tempFolder

<#
 # THIS SECTION NEEDS TO BE EXECUTED ONLY ONCE TO CREATE AN AUTOMATION ACCOUNT
 # MULTIPLE HOST POOLS CAN USE THE SAME AUTOMATION ACCOUNT
 #>

New-AzureAutomationAccount -azRegion $AzAARegion -aadTenantId $AadTenantId -azSubscriptionId $AzSubscriptionId `
	-azAAResourceGroupName $AzAAResourceGroupName -azAAName $AzAAName -azLAName $AzLAName

<# Create the Azure Automation Account Run As credential
 # Based on https://abcdazure.azurewebsites.net/create-automation-account-with-powershell/
 #>
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"
New-AzureAutomationRunAsAccount -automationAccountName $AzAAName -resourceGroupName $AzAAResourceGroupName `
	-keyVaultName $KeyVaultName -subscriptionId $AzSubscriptionId -location $AzAARegion `
	-tempFolder $TempFolder -aadTenantId $AadTenantId

<#
 # Create the Azure Logic App, based on US EDU customizations
 #>
# You may repeat the function call to create the Logic App for as many host pools you have

# Retrieve details from the Log Analytics Workspace (that might have been created by the call above)
$WorkSpace = Get-AzOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $AzAAResourceGroupName -Name $AzLAName -WarningAction Ignore
$LogAnalyticsPrimaryKey = $Workspace.PrimarySharedKey
$LogAnalyticsWorkspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $AzAAResourceGroupName -Name $AzLAName).CustomerId.GUID
	
# TODO: Make $WVDHostPoolName an array to create multiple logic apps at one time
[string]$LogicAppName = New-LogicApp -azAAName $AzAAName -azSubscriptionId $AzSubscriptionId -wvdHostPoolName $WVDHostPoolName `
	-resourceGroupName $AzAAResourceGroupName -aadTenantId $AADTenantId -azRegion $AzAARegion `
	-recurrenceInterval $RecurrenceInterval -beginPeakTime $BeginPeakTime -endPeakTime $EndPeakTime `
	-timeDifference $TimeDifference -sessionThresholdPerCPU $SessionThresholdPerCPU `
	-minimumNumberOfRDSH $MinimumNumberOfRDSH -maintenanceTagName $MaintenanceTagName `
	-limitSecondsToForceLogOffUser $LimitSecondsToForceLogOffUser -logOffMessageTitle $LogOffMessageTitle `
	-logOffMessageBody $LogOffMessageBody `
	-logAnalyticsPrimaryKey $LogAnalyticsPrimaryKey -logAnalyticsWorkspaceId $LogAnalyticsWorkspaceId

if ($UseUsEduLogicApp) {
	$UsEduCustomLogicAppDefinitionUri = "https://raw.githubusercontent.com/Microsoft-USEduAzure/Windows-Virtual-Desktop/master/daily-scaling/files/dailyscaling.json"
	$LogicAppDefinitionFileName = "UsEduCustomLogicAppDefinition.json"
	$LogicAppDefinitionContentFileName = "UsEduCustomLogicAppDefinitionContent.json"
	$WvdHostPoolResourceGroupName = (Get-AzResource -ResourceType "Microsoft.DesktopVirtualization/hostpools" -Name $wvdHostPoolName).ResourceGroupName

	# Disable the Logic App while making changes
	Write-Verbose "Disabling the Logic App during updates"
	Set-AzLogicApp -ResourceGroupName $AzAAResourceGroupName -Name $LogicAppName `
		-State Disabled -Force

	# Download the customized Logic App definition from GitHub
	Write-Verbose "Downloading the US EDU custom Logic App definition"
	Invoke-WebRequest -Uri $UsEduCustomLogicAppDefinitionUri -OutFile ".\$($LogicAppDefinitionFileName)"

	Write-Verbose "Processing the custom definition"
	$LogicAppDefinition = Get-Content -Raw -Path $LogicAppDefinitionFileName | ConvertFrom-Json

	# Remove "definition" root node from JSON
	# The Set-AzLogicApp cmdlet doesn't want the actual "definition" property in the JSON
	$LogicAppDefinitionContent = $LogicAppDefinition.definition

	# Modify the Logic App variables and trigger to match what's been set in this script
	$LogicAppDefinitionContent.triggers.Recurrence.recurrence.interval = $RecurrenceInterval

	# Replace placeholders in JSON with values from this script
	# $LogicAppVariables is just a shortcut to the lengthy object model
	$LogicAppVariables = $LogicAppDefinitionContent.actions.Configuration.inputs.variables[0].value
	$LogicAppVariables.AutomationURI = Get-WebHookUri -azAAName $AzAAName -resourceGroupName $AzAAResourceGroupName
	$LogicAppVariables.Timezone = $TimeZoneNameForPeakTime

	# HostpoolParams
	$HostpoolParams = $LogicAppVariables.HostpoolParams[0]
	$HostpoolParams.AADTenantId = $AadTenantId
	$HostpoolParams.HostPoolName = $WVDHostPoolName
	$HostpoolParams.LimitSecondsToForceLogOffUser = $LimitSecondsToForceLogOffUser
	$HostpoolParams.LogAnalyticsPrimaryKey = $LogAnalyticsPrimaryKey
	$HostpoolParams.LogAnalyticsWorkspaceId = $LogAnalyticsWorkspaceId
	$HostpoolParams.LogOffMessageBody = $LogOffMessageBody
	$HostpoolParams.LogOffMessageTitle = $LogOffMessageTitle
	$HostpoolParams.MaintenanceTagName = $MaintenanceTagName
	$HostpoolParams.ResourceGroupName = $WvdHostPoolResourceGroupName
	$HostpoolParams.SessionThresholdPerCPU = $SessionThresholdPerCPU
	$HostpoolParams.SubscriptionId = $AzSubscriptionId
	$HostpoolParams.TimeDifference = $TimeDifference

	# Daily schedule
	foreach ($ScheduleDay in $LogicAppVariables.Schedule) {
		Write-Verbose "Setting schedule for $($ScheduleDay.Day)"
		$ScheduleDay.PeakStart = $BeginPeakTime
		$ScheduleDay.PeakEnd = $EndPeakTime
		$ScheduleDay.MinimumHostsOffHours = $MinimumNumberOfRDSH
		$ScheduleDay.MinimumHostsPeakHours = $MinimumNumberOfRDSHPeak
	}

	# Convert the PowerShell object back to JSON and save as a new file
	$LogicAppDefinitionContent | ConvertTo-Json -Depth 50 | Out-File ".\$($LogicAppDefinitionContentFileName)"

	Write-Verbose "Setting customized Logic App definition"
	Set-AzLogicApp -ResourceGroupName $AzAAResourceGroupName -Name $LogicAppName `
		-DefinitionFilePath ".\$($LogicAppDefinitionContentFileName)" -Force

	# Re-enable the Logic App
	Write-Verbose "Re-enabling logic app"
	Set-AzLogicApp -ResourceGroupName $AzAAResourceGroupName -Name $LogicAppName `
		-State Enabled -Force
}

Write-Host "Completed..."

Write-Verbose "You should clear the contents of the $TempFolder directory because secrets are stored in it."
