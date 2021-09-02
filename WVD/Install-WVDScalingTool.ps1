# TODO: Specify modules as Requires
param (
	# A prefix that will be added to all resources created by this script
	[Parameter()]
	[string]$CommonResourceNamePrefix = "WVD-AutoScale-",
	# Resource Group Name for the Azure Automation Account
	[Parameter(Position = 0)]
	[Alias("ResourceGroup,ResourceGroupName,RG")]
	[string]$AzAAResourceGroupName = "$($CommonResourceNamePrefix)RG",
	# The temporary folder that will hold downloaded scripts and certificates
	[Parameter()]
	[string]$TempFolder = $env:TEMP,
	# Name of the WVD Host Pool to apply scaling solution
	[ValidateNotNullOrEmpty()]
	[Parameter(Mandatory,
		HelpMessage = "Name of the WVD Host Pool to apply the scaling solution to.",
		Position = 1)]
	[string]$WVDHostPoolName,
	# The name (or ID) of the Azure subscription where the WVD host pool lives and where the scaling resources are created
	[ValidateNotNullOrEmpty()]
	[Parameter(Mandatory,
		HelpMessage = "Name (or ID) of the Azure subscription where the WVD host pool lives.")]
	[string]$SubscriptionName,
	# If the Logic App Definition should be the custom version developed by US EDU CSA
	[Parameter()]
	[switch]$UseUsEduLogicApp,
	# If set, does not delete the temp folder after the script finishes
	[Parameter()]
	[switch]$SkipDeletingTempFolder,
	# In minutes, how often the Logic App will run and call the runbook to scale
	[Parameter()]
	[int]$RecurrenceInterval = 15,
	# The start time for peak hours, in local time, in 24-hour format, e.g. "9:00"
	[Parameter()]
	[string]$BeginPeakTime = "9:00",
	# The end time for peak hours, in local time, in 24-hour format, e.g. "17:00"
	[Parameter()]
	[string]$EndPeakTime = "17:00",
	# The time difference between local time and UTC in hours, e.g. +5:30
	[Parameter()]
	[string]$TimeDifference = "-5:00",
	# Enter the maximum number of sessions per CPU that will be used as a threshold to determine when new session host VMs need to be started. This need not be the same number set in the host pool configuration.
	[Parameter()]
	[int]$SessionThresholdPerCPU = 2,
	# The minimum number of session host VMs to keep running during off-peak hours
	[Parameter()]
	[int]$MinimumNumberOfRDSH = 1,
	# The minimum number of session host VMs to start in advance at the start of peak hours
	[Parameter()]
	[int]$MinimumNumberOfRDSHPeak = 2,
	# The name of the Tag associated with session host VMs you don't want to be managed by this scaling tool
	[Parameter()]
	[string]$MaintenanceTagName = "$($CommonResourceNamePrefix)scaling-dont-touch",
	# The number of seconds to wait before automatically signing out users on a session host that will be shut down when scaling in. If set to 0, any session host VM that has user sessions will be left untouched.
	[Parameter()]
	[int]$LimitSecondsToForceLogOffUser = 600,
	# The title of the message sent to the user before they are forced to sign out
	[Parameter()]
	[string]$LogOffMessageTitle = "This session host is about to shut down",
	# The body of the message sent to the user before they are forced to sign out
	[Parameter()]
	[string]$LogOffMessageBody = "Please save your work and log off. If you need to continue working, you may immediately log on again.",
	# The Tenant ID of the Azure AD tenant. If not specified, the tenant ID of the selected subscription will be used
	[Parameter()]
	[string]$AadTenantId,
	# The subscription ID to use. If not specified, the active subscription from the active AzContext will be used. If specified, it must match the subscription specified in $SubscriptionName.
	[Parameter()]
	[string]$AzSubscriptionId,
	# The name for the Azure Automation Account. If it doesn't exist yet, it will be created.
	[Parameter()]
	[string]$AzAAName = "$($CommonResourceNamePrefix)AutomationAccount",
	# The Azure region to use for new resources
	[Parameter()]
	[string]$AzAARegion = "eastus",
	# The name of the Log Analytics Workspace. If it doesn't exist yet, it will be created.
	[Parameter()]
	[string]$AzLAName = "$($CommonResourceNamePrefix)Workspace",
	# The name of the Key Vault to store the certificate for the Azure Automation Run As account. If it doesn't exist yet, it will be created.
	[Parameter()]
	[string]$KeyVaultName = "$($CommonResourceNamePrefix)KV"
)
function New-WvdScaleLogAnalyticsWorkspace {
	param(
		[string]$azRegion,
		[string]$azAAResourceGroupName,
		[string]$azLAName
	)

	try {
		# Attempt to get the workspace by name and resource group
		Get-AzOperationalInsightsWorkspace -Name $azLAName -ResourceGroupName $azAAResourceGroupName -ErrorAction Stop
	}
	catch {
		# TODO: Ensure global uniqueness: try the specified name first, then add randomization
		# Global uniqueness requirement doc: https://docs.microsoft.com/en-us/azure/azure-monitor/learn/quick-create-workspace#create-a-workspace
		Write-Warning "Creating new Log Analytics Workspace $azLAName"
		New-AzOperationalInsightsWorkspace -Location $azRegion -Name $azLAName -Sku Standard `
			-ResourceGroupName $azAAResourceGroupName	
	}
}

function New-WvdScaleAzureAutomationAccount {
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
		"Location"              = $azRegion
		"UseARMAPI"             = $true
		"AADTenantId"           = $aadTenantId				# Optional. If not specified, it will use the current Azure context
		"SubscriptionId"        = $azSubscriptionId			# Optional. If not specified, it will use the current Azure context
		"ResourceGroupName"     = $azAAResourceGroupName	# Optional. Default: "WVDAutoScaleResourceGroup"
		"AutomationAccountName" = $azAAName			 		# Optional. Default: "WVDAutoScaleAutomationAccount"
		"WorkspaceName"         = $azLAName			 		# Optional. If specified, Log Analytics will be used to configure the custom log table that the runbook PowerShell script can send logs to
	}

	Write-Output "Checking Log Analytics Workspace"

	New-WvdScaleLogAnalyticsWorkspace -azAAResourceGroupName $azAAResourceGroupName -azRegion $azRegion `
		-azLAName $azLAName

	Write-Output "Creating Azure Automation Account $azAAName"

	# Create the Azure Automation Account
	# This will take several minutes
	# Be sure to capture any output
	.\CreateOrUpdateAzAutoAccount.ps1 @Params
}

function New-WvdScaleAzureAutomationRunAsAccount {
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
	
	$SecretRetrieved = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $CertificateName -AsPlainText
	#$PfxBytes = [System.Convert]::FromBase64String($SecretRetrieved.SecretValueText)
	$PfxBytes = [System.Convert]::FromBase64String($SecretRetrieved)
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
	$ConnectionFieldValues = @{"ApplicationId" = $ApplicationID; "TenantId" = $aadTenantId; "CertificateThumbprint" = $Thumbprint; "SubscriptionId" = $subscriptionId }
	
	# Create a Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
	Write-Output "Creating Connection in the Asset..."
	Remove-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName -Name $ConnectionAssetName `
		-Force -ErrorAction SilentlyContinue
	New-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $automationAccountName -Name $ConnectionAssetName `
		-ConnectionTypeName $ConnectionTypeName -ConnectionFieldValues $ConnectionFieldValues
	
	Write-Output "RunAsAccount Creation Completed..."	
}

function New-WvdScaleLogicApp {
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
		"AADTenantId"                   = $aADTenantId						# Optional. If not specified, it will use the current Azure context
		"SubscriptionID"                = $azSubscriptionId					# Optional. If not specified, it will use the current Azure context
		"ResourceGroupName"             = $azAAResourceGroupName				# Optional. Default: "WVDAutoScaleResourceGroup"
		"Location"                      = $azRegion						  # Optional. Default: "West US2"
		"UseARMAPI"                     = $true
		"HostPoolName"                  = $WVDHostPool.Name
		"HostPoolResourceGroupName"     = $WVDHostPool.ResourceGroupName		 # Optional. Default: same as ResourceGroupName param value
		"LogAnalyticsWorkspaceId"       = $logAnalyticsWorkspaceId			  # Optional. If not specified, script will not log to the Log Analytics
		"LogAnalyticsPrimaryKey"        = $logAnalyticsPrimaryKey				# Optional. If not specified, script will not log to the Log Analytics
		"ConnectionAssetName"           = $AutoAccountConnection.Name			# Optional. Default: "AzureRunAsConnection"
		"RecurrenceInterval"            = $recurrenceInterval				  # Optional. Default: 15
		"BeginPeakTime"                 = $beginPeakTime					  # Optional. Default: "09:00"
		"EndPeakTime"                   = $endPeakTime						# Optional. Default: "17:00"
		"TimeDifference"                = $timeDifference					 # Optional. Default: "-7:00"
		"SessionThresholdPerCPU"        = $sessionThresholdPerCPU				# Optional. Default: 1
		"MinimumNumberOfRDSH"           = $minimumNumberOfRDSH				 # Optional. Default: 1
		"MaintenanceTagName"            = $maintenanceTagName				  # Optional.
		"LimitSecondsToForceLogOffUser" = $limitSecondsToForceLogOffUser		 # Optional. Default: 1
		"LogOffMessageTitle"            = $logOffMessageTitle				  # Optional. Default: "Machine is about to shutdown."
		"LogOffMessageBody"             = $logOffMessageBody					# Optional. Default: "Your session will be logged off. Please save and close everything."
		"WebhookURI"                    = $WebhookUri
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

$ErrorActionPreference = "Inquire"

<#
 # VARIABLES SECTION
 # REVIEW, AND CUSTOMIZE IF NEEDED
 #>

# This variable is not currently used
[string]$TimeZoneNameForPeakTime = (Get-TimeZone).Id
 
#Check if Az module is on the system  
if (Get-Module -ListAvailable -Name Az) {
	# TODO: Ensure running as admin before updating or installing a module
	Update-Module -Name Az
}
else {
	Install-Module Az
}

$AzContext = Get-AzContext

if (!$AzContext) {
	Login-AzAccount

	$AzContext = Get-AzContext

	if (!$AzContext) {
		throw "Could not retrieve Azure context. Did you authenticate?"
	}
}

Select-AzSubscription -Subscription $SubscriptionName
$AzContext = Get-AzContext

# If no tenant ID was specified as a parameter
if (! $AadTenantId) {
	# Get the tenant from the current context
	$AadTenantId = $AzContext.Subscription.TenantId
	Write-Warning "Automatically using subscription's tenant $AadTenantId"
}

# If no subscription ID was specified as a parameter
if (! $AzSubscriptionId) {
	$AzSubscriptionId = $AzContext.Subscription.Id
	Write-Warning "Automatically using subscription $AzSubscriptionId"
}

# END VARIABLES SECTION

# Get or create a resource group object
try {
	Get-AzResourceGroup -Name $AzAAResourceGroupName -ErrorAction Stop
	Write-Verbose "Found resource group $AzAAResourceGroupName"
} 
catch {
	Write-Warning "Creating Resource Group $AzAAResourceGroupName"
	New-AzResourceGroup -Name $AzAAResourceGroupName -Location $AzAARegion -Verbose -Force
}

# Ensure the temp folder exists and switch to it
# TODO: Error handling
[string]$SubDir = New-Guid
$TempFolder = "$TempFolder\$SubDir"

New-Item -ItemType Directory -Path $TempFolder -Force
# TODO: Capture current path and switch back after script terminates
Set-Location -Path $TempFolder

<#
 # THIS SECTION NEEDS TO BE EXECUTED ONLY ONCE TO CREATE AN AUTOMATION ACCOUNT
 # MULTIPLE HOST POOLS CAN USE THE SAME AUTOMATION ACCOUNT
 #>

# TODO: check if automation account by that name exists, and if so, in that region and RG
New-WvdScaleAzureAutomationAccount -azRegion $AzAARegion -aadTenantId $AadTenantId -azSubscriptionId $AzSubscriptionId `
	-azAAResourceGroupName $AzAAResourceGroupName -azAAName $AzAAName -azLAName $AzLAName

<# Create the Azure Automation Account Run As credential
 # Based on https://abcdazure.azurewebsites.net/create-automation-account-with-powershell/
 #>
# TODO: Only when new automation account was created
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"
New-WvdScaleAzureAutomationRunAsAccount -automationAccountName $AzAAName -resourceGroupName $AzAAResourceGroupName `
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
[string]$LogicAppName = New-WvdScaleLogicApp -azAAName $AzAAName -azSubscriptionId $AzSubscriptionId -wvdHostPoolName $WVDHostPoolName `
	-resourceGroupName $AzAAResourceGroupName -aadTenantId $AADTenantId -azRegion $AzAARegion `
	-recurrenceInterval $RecurrenceInterval -beginPeakTime $BeginPeakTime -endPeakTime $EndPeakTime `
	-timeDifference $TimeDifference -sessionThresholdPerCPU $SessionThresholdPerCPU `
	-minimumNumberOfRDSH $MinimumNumberOfRDSH -maintenanceTagName $MaintenanceTagName `
	-limitSecondsToForceLogOffUser $LimitSecondsToForceLogOffUser -logOffMessageTitle $LogOffMessageTitle `
	-logOffMessageBody $LogOffMessageBody `
	-logAnalyticsPrimaryKey $LogAnalyticsPrimaryKey -logAnalyticsWorkspaceId $LogAnalyticsWorkspaceId

if ($UseUsEduLogicApp) {
	Write-Host "Customizing the Logic App definition with the US Education customizations"
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

if ($SkipDeletingTempFolder) {
	Write-Verbose "You should clear the contents of the $TempFolder directory because secrets are stored in it."
}
else {
	Remove-Item -Path $TempFolder -Force
	Write-Verbose "Deleted the temporary folder $TempFolder"
}

Write-Host "Completed..."
