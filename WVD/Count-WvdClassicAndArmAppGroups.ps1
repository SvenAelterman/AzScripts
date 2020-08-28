$RDModuleName = "Microsoft.RDInfra.RDPowerShell"
$TenantId = "<paste-aad-tenant-id-here>"

$ClassicAppGroupCount = 0
$ARMAppGroupCount = 0

$m = Get-Module -ListAvailable -Name $RDModuleName

if ($m.Length -eq 0) {
    Write-Host "Installing module $RDModuleName"
    Install-Module -Name $RdModuleName -Force
}
else {
    Write-Host "Updating module $RDModuleName"
    Update-Module -Name $RDModuleName
}

# Sign in to classic WVD
Add-RdsAccount -DeploymentUrl "https://rdbroker.wvd.microsoft.com"

# Classic app group counting
$ClassicTenants = Get-RdsTenant

foreach ($ClassicTenant in $ClassicTenants) {
    $ClassicHostPools = Get-RdsHostPool -TenantName $ClassicTenant.TenantName

    foreach ($ClassicHostPool in $ClassicHostPools) {
        #$ClassicHostPool
        $ClassicAppGroupCount = $ClassicAppGroupCount + (Get-RdsAppGroup -TenantName $TenantName -HostPoolName $ClassicHostPool.HostPoolName).Count
    }
}

Write-Host "Classic App Groups: $ClassicAppGroupCount"

# ARM App Group Counting
Login-AzAccount -Tenant $TenantId
$Subscriptions = Get-AzSubscription -TenantId $TenantId

foreach ($sub in $subs) {
    $ARMAppGroupCount = $ARMAppGroupCount + (Get-AzWvdApplicationGroup -subscriptionID $sub.ID).Count
}

Write-Host "ARM App Groups: $ARMAppGroupCount"

# Total
$TotalAppGroupsInTenant = $ClassicAppGroupCount + $ARMAppGroupCount
Write-Host "Total App Groups: $TotalAppGroupsInTenant"

$MaxAppGroups = 50

Write-Host "You have used $($TotalAppGroupsInTenant / $MaxAppGroups * 100)% ($TotalAppGroupsInTenant of $MaxAppGroups) of available WVD app groups"

# Quick Setup of Classic WVD
#$SubscriptionId = "<paste-azure-subscription-id-here>"
#New-RdsTenant -Name $TenantName -AadTenantId $TenantId -AzureSubscriptionId $SubscriptionId
#Get-RdsTenant
#New-RdsHostPool -TenantName $TenantName -Name "TestHostPool" -ValidationEnv $false
#New-RdsAppGroup -TenantName $TenantName -Name "DAG" -ResourceType Desktop -HostPoolName "TestHostPool"