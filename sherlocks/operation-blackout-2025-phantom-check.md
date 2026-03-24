# Operation Blackout 2025: Phantom Check

**Sherlock Scenario**

Talion suspects that the threat actor carried out anti-virtualization checks to avoid detection in sandboxed environments. Your task is to analyze the event logs and identify the specific techniques used for virtualization detection. Byte Doctor requires evidence of the registry checks or processes the attacker executed to perform these checks.

<details>

<summary>Which WMI class did the attacker use to retrieve model and manufacturer information for virtualization detection?</summary>

```shellscript
┌──(jagerr㉿kali)-[~/Downloads/PhantomCheck]
└─$ evtxexport Windows-Powershell-Operational.evtx >> windows_powershell_operational.txt
┌──(jagerr㉿kali)-[~/Downloads/PhantomCheck]
└─$ evtxexport Microsoft-Windows-Powershell.evtx >> microsoft_windows_powershell.txt 
┌──(jagerr㉿kali)-[~/Downloads/PhantomCheck]
└─$ cat microsoft_windows_powershell.txt | grep -i wmi
String: 1                       : $Manufacturer = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Manufacturer"
        CommandLine=$Manufacturer = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Manufacturer"
String: 3                       : CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Class"; value="Win32_ComputerSystem"
String: 1                       : $Model = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Model"
        CommandLine=$Model = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Model"
String: 3                       : CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Class"; value="Win32_ComputerSystem"
String: 1                       : Get-WmiObject -Query "SELECT * FROM MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
        CommandLine=Get-WmiObject -Query "SELECT * FROM MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
String: 3                       : CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Query"; value="SELECT * FROM MSAcpi_ThermalZoneTemperature"
ParameterBinding(Get-WmiObject): name="ErrorAction"; value="SilentlyContinue"
NonTerminatingError(Get-WmiObject): "Invalid class "MSAcpi_ThermalZoneTemperature""
```

<figure><img src="../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

> Win32\_ComputerSystem

</details>

<details>

<summary>Which WMI query did the attacker execute to retrieve the current temperature value of the machine?</summary>

```shellscript
┌──(jagerr㉿kali)-[~/Downloads/PhantomCheck]
└─$ cat microsoft_windows_powershell.txt | grep -i wmi
String: 1                       : $Manufacturer = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Manufacturer"
        CommandLine=$Manufacturer = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Manufacturer"
String: 3                       : CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Class"; value="Win32_ComputerSystem"
String: 1                       : $Model = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Model"
        CommandLine=$Model = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Model"
String: 3                       : CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Class"; value="Win32_ComputerSystem"
String: 1                       : Get-WmiObject -Query "SELECT * FROM MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
        CommandLine=Get-WmiObject -Query "SELECT * FROM MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
String: 3                       : CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Query"; value="SELECT * FROM MSAcpi_ThermalZoneTemperature"
ParameterBinding(Get-WmiObject): name="ErrorAction"; value="SilentlyContinue"
NonTerminatingError(Get-WmiObject): "Invalid class "MSAcpi_ThermalZoneTemperature""
```

<figure><img src="../.gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

> SELECT \* FROM MSAcpi\_ThermalZoneTemperature

</details>

<details>

<summary>The attacker loaded a PowerShell script to detect virtualization. What is the function name of the script?</summary>

Inside `windows_powershell_operational.txt` , searching for `virtual` gave me this result:

<figure><img src="../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

> Check-VM

</details>

<details>

<summary>Which registry key did the above script query to retrieve service details for virtualization detection?</summary>

Checking out the code below the function name leads to:

<figure><img src="../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

> HKLM:\SYSTEM\ControlSet001\Services

</details>

<details>

<summary>The VM detection script can also identify VirtualBox. Which processes is it comparing to determine if the system is running VirtualBox?</summary>

<figure><img src="../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

> vboxservice.exe, vboxtray.exe

</details>

<details>

<summary>The VM detection script prints any detection with the prefix 'This is a'. Which two virtualization platforms did the script detect?</summary>

<figure><img src="../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

> hyper-v, vmware

</details>









