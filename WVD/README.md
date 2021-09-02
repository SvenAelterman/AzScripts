# Install-WVDScalingTool.ps1

A PowerShell script to combine the three separate steps from the Microsoft Docs to deploy the Azure Virtual Desktop (AVD) scaling tool.

## Usage

Minimum:

```PowerShell
.\Install-WVDScalingTool.ps1 -WVDHostPoolName $HostPoolName -SubscriptionName $SubscriptionName $UseUsEduLogicApp
```

For other parameters, see the source file. Here are some common ones:

  - BeginPeakTime: The hh:mm in local time when peak time begins.
  - EndPeakTime: The hh:mm in local time when peak time ends.
  - TimeDifference: + or - hh:mm difference between UTC and local time.
  - SessionTresholdPerCPU: Ideally matches or is close to the [Number of CPUs per session host] / [Number of users per host]
  - MinimumNumberOfRDSH: Minimum number of hosts in the running state at the start of peak time
