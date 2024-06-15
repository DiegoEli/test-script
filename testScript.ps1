
# Policy Execution Enable
#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

#****************************************************
#	ABOUT_SCRIPT
#****************************************************

# Show script info
$WPName = "WinPerf"
$WPVersion = "v1.50.3"
$repositoryPath = "https://raw.githubusercontent.com/DiegoEli/test-script/main/testScript.ps1"
# RUTA ORIGINAL
# $repositoryPath = "https://raw.githubusercontent.com/DiegoEli/test-script/main/WinPerf.ps1"

<#
.NOTES
	Author  : Diego Mendoza(JuanPerez)
	Github  : https://raw.githubusercontent.com/DiegoEli/test-script/main/WinPerf.ps1
	Name    : WinPerf
	Version : 1.50.3

.PARAMETER [Aliases]
    irm = Invoke-RestMethod
    iex = Invoke-Expression

.EXAMPLE
	# Run the script from the repository.
	-------------
    Since GitHub:
    irm https://raw.githubusercontent.com/DiegoEli/test-script/main/WinPerf.ps1 | iex

	-------------
    Since GitLab:
    irm https://gitlab.com/DiegoEli/test-script/-/raw/main/WinPerf.ps1?ref_type=heads | iex

.FUNCTIONALITY
	# Skip LockScreen
	$path_1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Personalization'

	New-Item -Path $path_1 -Name $item -Force

	$path_2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
	$property = 'NoLockScreen'
	$value = 1

	New-ItemProperty -Path $path_2 -Name $property -Value $value -PropertyType DWORD -Force

.FUNCTIONALITY
	# Customizar Folder in FileExplorer
	$path_1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
	$item = 'Shell Icons'
	
	New-Item -Path $path_1 -Name $item -Force
	
	$path_2 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons'
	$value = 3

	New-ItemProperty -Path $path_2 -Name $value -PropertyType DWORD -Force

.LINK
	https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys
	https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users
	https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings
	https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update?toc=%2Fwindows%2Fdeployment%2Ftoc.json&bc=%2Fwindows%2Fdeployment%2Fbreadcrumb%2Ftoc.json#allowmuupdateservice
	
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-arrays?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-hashtable?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-module?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_editions?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.4
	https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsbuiltinrole?view=net-8.0

	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.4
	https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
	https://learn.microsoft.com/en-us/powershell/module/mmagent/enable-mmagent?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps

	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-service?view=powershell-7.4
	https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/powershell/module/dism/get-windowsoptionalfeature?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/powershell/module/dism/disable-windowsoptionalfeature?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature?view=windowsserver2022-ps

	https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/powershell/module/dism/get-appxprovisionedpackage?view=windowsserver2022-ps
	https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-app-package--appx-or-appxbundle--servicing-command-line-options?view=windows-11#remove-provisionedappxpackage
	https://learn.microsoft.com/es-es/windows/package-manager/winget/
	https://docs.chocolatey.org/en-us/getting-started

#>

#****************************************************
#	ALL_FUNCTIONS
#****************************************************

# funcion Test Item
function Test_Item {
	param (
		[string]$pathItem,
		[string]$item
	)

	if (!(Test-Path -Path "$pathItem\$item")) {

		New-Item -Path $pathItem -Name $item -Force
	}
}

# function Test Property
function Test_Property {
	param (
		[string]$pathProperty,
		[string]$property
	)
	$type = 'DWORD'
	$value = 0

	if (!(Get-ItemProperty -Path $pathProperty -Name $property -ErrorAction SilentlyContinue)) {

		New-ItemProperty -Path $pathProperty -Name $property -PropertyType $type -Value $value -Force
	}
}

# Mensaje de confirmacion global
function Invoke-Confirmation {
	param (
		[scriptblock]$operation
	)
	
	$opt = Read-Host "[Y] Yes [N] No";
	
	if ($opt -eq "y") {
		& $operation
	} 
	elseif ($opt -eq "n") {
		Write-Host "Operation cancelled." -ForegroundColor Red
	} 
	else {
		Invoke-Confirmation $operation
	}
}

function Test-WinVersion {
	param (
		[scriptblock]$Operation,
		[int]$OSNumber
	)

	# $WinOSVersion = (Get-ComputerInfo).OsName
	$WinOSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
	
	if ($WinOSVersion -match "Microsoft Windows $OSNumber") {
		& $Operation
	}
}

# Modification 1.0: Remove Folder Gallery
function Remove_Gallery {
	$pathGallery = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_41040327'
	$item = '{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}'

	if (Test-Path -Path "$pathGallery\$item") {

		"Removing Folder [Gallery] from File Explorer."
		Remove-Item -Path "$pathGallery\$item" -Force
	}
	else {
		"Error removing Folder [Gallery], Key not found."
	}
}

# Modification 1.1: Show CortanaResults in Windows Search
function Disable_CortanaResults {
	$pathFolder = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Windows Search'

	Test_Item $pathFolder $item

	$pathProperty = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
	$property = 'AllowCortana'
	$allCortana = (Get-ItemProperty -Path $pathProperty).$property
	$value = 0

	Test_Property $pathProperty $property
		
	if ($allCortana -ne $value) {

		"Setting feature [$property] to Disabled."
		Set-ItemProperty -Path $pathProperty -Name $property -Value $value -Force
	} 
	else {
		"Feature [$property] has already been Disabled."
	}
}

# Modification 1.2: Show WebResults in Windows Search
function Disable_WebResults {
	$pathWebResults = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
	$property1 = 'BingSearchEnabled'
	$property2 = 'CortanaConsent'
	$BingSearch = (Get-ItemProperty -Path $pathWebResults).$property1
	$CortanaSearch = (Get-ItemProperty -Path $pathWebResults).$property2
	$value = 0

	Test_Property $pathWebResults $property1
	Test_Property $pathWebResults $property2

	if (($BingSearch -ne $value) -or ($CortanaSearch -ne $value)) {

		"Setting feature [$property1] to Disabled."
		Set-ItemProperty -Path $pathWebResults -Name $property1 -Value $value -Force
		
		"Setting feature [$property2] to Disabled."
		Set-ItemProperty -Path $pathWebResults -Name $property2 -Value $value -Force
	} 
	else {
		"Feature [$property1] has already been Disabled."
		"Feature [$property2] has already been Disabled."
	}
}

# Modification 1.3: DiagnosticData
function Disable_DiagnosticData {
	$pathTelemetry = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
	$property = 'AllowTelemetry'
	$telemetry = (Get-ItemProperty -Path $pathTelemetry).$property
	$value = 0

	Test_Property $pathTelemetry $property

	if ($telemetry -ne $value) {

		"Setting option [$property] to Disabled."
		Set-ItemProperty -Path $pathTelemetry -Name $property -Value $value -Force
	} 
	else {
		"Option [$property] has already been Disabled."
	}
}

# Modification
function Disable_ActivityHistory {
	$pathActivityHistory = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
	$property1 = 'EnableActivityFeed'
	$property2 = 'PublishUserActivities'
	$property3 = 'UploadUserActivities'
    $EnableActFeed = (Get-ItemProperty -Path $pathActivityHistory).$property1
    $PublishUserAct = (Get-ItemProperty -Path $pathActivityHistory).$property2
    $UploadUserAct = (Get-ItemProperty -Path $pathActivityHistory).$property3
	$value = 0
	
	Test_Property $pathActivityHistory $property1
	Test_Property $pathActivityHistory $property2
	Test_Property $pathActivityHistory $property3

    if (($EnableActFeed -ne $value) -or ($PublishUserAct -ne $value) -or ($UploadUserAct -ne $value)) {
		
		"Setting option [$property1] to Disabled."
		Set-ItemProperty -Path $pathActivityHistory -Name $property1 -Value $value -Force

		"Setting option [$property2] to Disabled."
		Set-ItemProperty -Path $pathActivityHistory -Name $property2 -Value $value -Force

		"Setting option [$property3] to Disabled."
		Set-ItemProperty -Path $pathActivityHistory -Name $property3 -Value $value -Force
    }
    else {
		"Option [$property1] has already been Disabled."
		"Option [$property2] has already been Disabled."
		"Option [$property3] has already been Disabled."
    }
}

$privacyFnList = [ordered]@{
	"Cortana Results"  = "Disable_CortanaResults"
	"Web Results"      = "Disable_WebResults"
	"Diagnostic Data"  = "Disable_DiagnosticData"
	"Activity History" = "Disable_ActivityHistory"
}

function Set_Privacy_Security () {

	Test-WinVersion -Operation {

		Write-Host "Do you want to Remove [" -NoNewline
		Write-Host "Folder Gallery" -ForegroundColor Cyan -NoNewline; "]?"
	
		Invoke-Confirmation {
			Remove_Gallery
		}
		Write-Host ""

	} -OSNumber 11;
	
	foreach ($privacyFn in $privacyFnList.Keys) {
		$privacyFnName = $privacyFnList[$privacyFn]

		Write-Host "Do you want to Disable [" -NoNewline
		Write-Host $privacyFn -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			& $privacyFnName
		}
		Write-Host ""
	}
}

# Modification 1.4: Update Type in Windows
function Set_UpdateType {
	$pathFolder = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item1 = 'WindowsUpdate'
	$pathSubFolder = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	$item2 = 'AU'
	
	Test_Item $pathFolder $item1
	Test_Item $pathSubFolder $item2
	
	$pathUpdateType = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
	$property1 = 'AUOptions'
	$property2 = 'NoAutoUpdate'
	$AUOptions = (Get-ItemProperty -Path $pathUpdateType).$property1
	$valueAUO = 2 #$valueNAU = 2; status = Notificar
	$NoAutoUpdate = (Get-ItemProperty -Path $pathUpdateType).$property2
	$valueNAU = 0 #$valueNAU = 1; status = Disabled

	Test_Property $pathUpdateType $property1
	Test_Property $pathUpdateType $property2

	if (($AUOptions -ne $valueAUO) -or ($NoAutoUpdate -ne $valueNAU)) {

		"Setting Group Policy [$property1] to Manual."
		Set-ItemProperty -Path $pathUpdateType -Name $property1 -Value $valueAUO -Force
		
		"Setting Group Policy [$property2] to Enabled."
		Set-ItemProperty -Path $pathUpdateType -Name $property2 -Value $valueNAU -Force
	} 
	else {
		"Group Policy [$property1] has already been Manual."
		"Group Policy [$property2] has already been Enabled."
	}
}

# Modification
function Set_PreliminaryUpdates {
	$pathPreliminary = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	$property = 'ManagePreviewBuildsPolicyValue'
	$preliminary = (Get-ItemProperty -Path $pathPreliminary).$property
	$value = 1

	Test_Property $pathPreliminary $property

	if ($preliminary -ne $value) {

		"Setting Group Policy [$property] to Disabled."
		Set-ItemProperty -Path $pathPreliminary -Name $property -Value $value -Force
	} 
	else {
		"Group Policy [$property] has already been Disabled."
	}
}

# Modification
function Set_UpdateOtherProduct {
	$MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
	$serviceId = '7971f918-a847-4430-9279-4a52d1efe18d'

	$service = $MUSM.Services | Where-Object { $_.ServiceID -eq "$serviceId" }

	if ($service) {

		"Setting service [RegisteredWithAU] to Disabled."
		$MUSM.RemoveService("$serviceId")
	} 
	else {
		"Service [RegisteredWithAU] has already been Disabled."
	}
}

# Modification
function Set_DownloadsOtherPCs {
	$HKU = "Registry::HKEY_USERS"
	$pathDownloadsPC = "$HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings"
	$property = 'DownloadMode'
	$downloadsPC = (Get-ItemProperty -Path $pathDownloadsPC).$property
	$value = 0

	if ($downloadsPC -ne $value) {

		"Setting option [$property] to Disabled."
		Set-ItemProperty -Path $pathDownloadsPC -Name $property -Value $value -Force
	} 
	else {
		"Option [$property] has already been Disabled."
	}
}

# Modification
function Set_LimitBandwidthUpdates {
	$folderPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Psched'

	Test_Item $folderPath $item

	$bandwidthPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched'
	$property = 'NonBestEffortLimit'
	$bandwidth = (Get-ItemProperty -Path $bandwidthPath).$property
	$value = 0

	Test_Property $bandwidthPath $property

	if ($bandwidth -ne $value) {

		"Setting Group Policy [$property] to Disabled."
		Set-ItemProperty -Path $bandwidthPath -Name $property -Value $value -Force
	} 
	else {
		"Group Policy [$property] has already been Disabled."
	}
}

$updateFnList = [ordered]@{
	"Automatic Updates"          = "Set_UpdateType"
	"Preliminary Updates"        = "Set_PreliminaryUpdates"
	"Updates for other products" = "Set_UpdateOtherProduct"
	"Downloads from other PCs"   = "Set_DownloadsOtherPCs"
	"Limit reservable bandwidth" = "Set_LimitBandwidthUpdates"
}

function Set_Update_Behavior () {

	foreach ($updateFn in $updateFnList.Keys) {
		$updateFnName = $updateFnList[$updateFn]

		Write-Host "Do you want to Disable [" -NoNewline
		Write-Host $updateFn -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			& $updateFnName
		}
		Write-Host ""
	}
}

# function Test Status Color
function Test_StatusColor {
	param (
		[string]$status
	)

	$color = ($status -eq '[OFF]') ? $('Red') : $('Cyan')
	Write-Host $status -ForegroundColor $color
}

# function Set Option Status
function Set_OptionStatus {
	param (
		[string]$path,
		[string]$property,
		[string]$value
	)

	$currentValue = (Get-ItemProperty -Path $path).$property

	if ($currentValue -ne $value) {

		"Option [`$property] has been `$status, Cambiando..."
		# Set-ItemProperty -Path $path -Name $property -Value $value -Force
	} 
	else {
		"Option [`$property] remains `$status, Ya fue cambiado"
	}
}

# Modification 2.1: Configure netplwiz in Windows
function Set_Opt_Netplwiz {
	$pathNetplwiz = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
	$property = 'DevicePasswordLessBuildVersion'
	$netplwiz = (Get-ItemProperty -Path $pathNetplwiz).$property
	$value = 0

	$status = ($netplwiz -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Netplwiz                  " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathNetplwiz $property $value
	#"Netplwiz has been Enabled"
}

# Modification 2.2: Configure fastStartup in Windows
function Set_Opt_FastStartup {
	$pathFastStartup = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
	$property = 'HiberbootEnabled'
	$fastStartup = (Get-ItemProperty -Path $pathFastStartup).$property
	$value = 0

	$status = ($fastStartup -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Fast Startup              " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathFastStartup $property $value
	#"FastStartup has been Disabled"
}

# Modification 1: StorageSense in Windows(revisar si existe)
function Set_Opt_StorageSense {
	$pathStorageSense = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
	$property = '01'
	$storageSense = (Get-ItemProperty -Path $pathStorageSense).$property
	$value = 0

	$status = ($storageSense -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Storage Sense             " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathStorageSense $property $value
	#"StorageSense has been Disabled"
}

# Modification 1: Snap in Windows
function Set_Opt_SnapSuggest {
	$pathSnapSuggest = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'SnapAssist'
	$snapSuggest = (Get-ItemProperty -Path $pathSnapSuggest).$property
	$value = 0

	$status = ($snapSuggest -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Suggest Next Snap         " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathSnapSuggest $property $value
	#"SnapSuggest has been Disabled"
}

# Modification 1: Show file extensions
function Set_Opt_ShowFileExtensions {
    $pathFileExt = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'HideFileExt'
    $fileExt = (Get-ItemProperty -Path $pathFileExt).$property
	$value = 0

	$status = ($fileExt -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Show File Extensions      " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathFileExt $property $value
	#"Show FileExtensions has been Enabled"
}

# Modification: Show hidden files and folders
function Set_Opt_ShowHiddenFiFo {
    $pathHiddenFiFo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'Hidden'
    $hiddenFiFo = (Get-ItemProperty -Path $pathHiddenFiFo).$property
	$value = 1

	$status = ($hiddenFiFo -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Show Hidden FilesFolders  " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathHiddenFiFo $property $value
	#"Show HiddenFilesFolders has been Enabled"
}

# Modification
function Set_Opt_ShowSyncProvider {
    $pathSyncProvider = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSyncProviderNotifications'
    $syncProvider = (Get-ItemProperty -Path $pathSyncProvider).$property
	$value = 0

	$status = ($syncProvider -ne $value) ? $('[ON]') : $('[OFF]')
	
	Write-Host "[+] Show Sync Provider        " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathSyncProvider $property $value
	#"Show SyncProvider has been Disabled"
}

# Modification 2.0: End Task in Windows
function Set_Opt_ShowEndTask {
    $pathEndTask = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'
	$property = 'TaskbarEndTask'
    $endTask = (Get-ItemProperty -Path $pathEndTask).$property
	$value = 1

	$status = ($endTask -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Enable End Task           " -NoNewline
	Test_StatusColor $status
	#"Show EndTask has been Enabled"
	Set_OptionStatus $pathEndTask $property $value
}

# Modification 0: Command Sudo in Windows
function Set_Opt_SudoCommand {
	$sudoCommandPath = '---'
	$property = '---'
	$sudoCommand = (Get-ItemProperty -Path $sudoCommandPath).$property
	$value = #

	$status = ($sudoCommand -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Enable Sudo Command       " -NoNewline
	Test_StatusColor $status; "[No disponible... :v]"
	Set_OptionStatus $sudoCommandPath $property $value

}

# Modification 0: Verificar el modo oscuro
function Set_Opt_DarkMode {
	$pathDarkModeAll = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property1 = 'AppsUseLightTheme'
	$property2 = 'SystemUsesLightTheme'
	$darkModeApps = (Get-ItemProperty -Path $pathDarkModeAll).$property1
	$darkModeSystem = (Get-ItemProperty -Path $pathDarkModeAll).$property2
	$value = 0

	$status = (($darkModeApps -ne $value) -or ($darkModeSystem -ne $value)) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Dark Mode                 " -NoNewline
	Test_StatusColor $status
	# "ThemeDark Apps has been Enabled"
	Set_OptionStatus $pathDarkModeAll $property1 $value
	# "ThemeDark System has been Enabled"
	Set_OptionStatus $pathDarkModeAll $property2 $value
}

# Modification: Get fun facts, tips, tricks...
function Set_Opt_GetTipsTricks {
    $pathTipsTricks = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$property1 = 'RotatingLockScreenOverlayEnabled'
	$property2 = 'SubscribedContent-338387Enabled'
    $tipsTricks = (Get-ItemProperty -Path $pathTipsTricks).$property1
	$value = 0

	$status = (($tipsTricks -ne $value) -or ($tipsTricks -ne $value)) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Get Facts, Tips, Tricks   " -NoNewline
	Test_StatusColor $status
	#"Facts, Tips & Tricks has been Disabled"
	Set_OptionStatus $pathTipsTricks $property1 $value
	#"Facts, Tips & Tricks has been Disabled"
	Set_OptionStatus $pathTipsTricks $property2 $value
}

# Modification: Show the lock ...
function Set_Opt_ShowSignInScreen {
    $pathSignInScreen = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-1-5-21-3918609171-3129487852-610721345-1001\AnyoneRead\LockScreen'
	$property = 'HideLogonBackgroundImage'
    $signInScreen = (Get-ItemProperty -Path $pathSignInScreen).$property
	$value = 0

	$status = ($signInScreen -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Show Sign-In Screen       " -NoNewline
	Test_StatusColor $status
	#"ShowSignInScreen has been Enabled"
	Set_OptionStatus $pathSignInScreen $property $value
}

# Modification
function Set_Opt_ShowItemSearch {
	$pathItemSearch = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
	$property = 'SearchboxTaskbarMode'
	$itemSearch = (Get-ItemProperty -Path $pathItemSearch).$property
	$value = 0

	$status = ($itemSearch -ne $value) ? $('[ON]') : $('[OFF]')
	
	Write-Host "[+] Show Item Search          " -NoNewline
	Test_StatusColor $status
	#"Show Item Search has been Disabled"
	Set_OptionStatus $pathItemSearch $property $value
}

# Modification
function Set_Opt_ShowItemTaskView {
	$pathItemTaskView = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowTaskViewButton'
	$itemTaskView = (Get-ItemProperty -Path $pathItemTaskView).$property
	$value = 0

	$status = ($itemTaskView -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Show Item TaskView        " -NoNewline
	Test_StatusColor $status
	#"Show Item TaskView has been Disabled"
	Set_OptionStatus $pathItemTaskView $property $value
}

# Modification 2.0: Hide Taskbar in Windows
function Set_Opt_HideTaskbar {
	$pathHideTaskbar = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
	$property = 'Settings'
	$hideTaskbar = (Get-ItemProperty -Path $pathHideTaskbar).$property
	$value = 0x7A

	$status = ($hideTaskbar[8] -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Hide Taskbar              " -NoNewline
	Test_StatusColor $status
	#"HideTaskbar has been Disabled"
	$hideTaskbar[8] = $value
	Set_OptionStatus $pathHideTaskbar $property $hideTaskbar
}

function Test_Set_Opt_HideTaskbar {
	Write-Host ""
	$pathHideTaskbar = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
	$property = 'Settings'
	$hideTaskbar = (Get-ItemProperty -Path $pathHideTaskbar).$property
	$value = 0x7A

	$status = ($hideTaskbar[8] -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Hide Taskbar              " -NoNewline
	Test_StatusColor $status
	
	if ($hideTaskbar[8] -ne 0x7A) {

		$hideTaskbar[8] = $value
		"Option [`$property] has been `$status, Cambiando..."
		# Set-ItemProperty -Path $pathHideTaskbar -Name $property -Value $hideTaskbar -Force
	}
	else {
		"Option [`$property] remains `$status, Ya fue cambiado"
	}
	Write-Host ""
}

function Set_Opt_ShowDesktop {
	$pathDesktop = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'TaskbarSd'
	$desktop = (Get-ItemProperty -Path $pathDesktop).$property
	$value = 1

	$status = ($desktop -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Option Show the Desktop   " -NoNewline
	Test_StatusColor $status
	#"ShowDesktop has been Enabled"
	Set_OptionStatus $pathDesktop $property $value
}

# Modification 2.0: ShowSeconds in SystemClock
function Set_Opt_ShowSeconds {
    $pathSecondsClock = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSecondsInSystemClock'
    $secondsClock = (Get-ItemProperty -Path $pathSecondsClock).$property
	$value = 1

	Test_Property $pathSecondsClock $property
	$status = ($secondsClock -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Show Seconds in Clock     " -NoNewline
	Test_StatusColor $status
	#"ShowSeconds has been Enabled"
	Set_OptionStatus $pathSecondsClock $property $value
}

# Modification 0: Game Bar in Windows
function Set_Opt_GameBar {
	$pathGameBar = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'UseNexusForGameBarEnabled'
	$gameBar = (Get-ItemProperty -Path $pathGameBar).$property
	$value = 0

	$status = ($gameBar -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Game Bar                  " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathGameBar $property $value
	#"GameBar has been Disabled"
}

# Modification 0: Game Mode in Windows
function Set_opt_GameMode {
	$pathGameMode = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'AutoGameModeEnabled'
	$gameMode = (Get-ItemProperty -Path $pathGameMode).$property
	$value = 0

	$status = ($gameMode -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Game Mode                 " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathGameMode $property $value
	#"GameMode has been Disabled"
}

# Modification 0:
function Set_Opt_TransparencyEffects {
    $pathTransparency = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property = 'EnableTransparency'
    $transparency = (Get-ItemProperty -Path $pathTransparency),$property
	$value = 0

	$status = ($transparency -ne $value) ? $('[ON]') : $('[OFF]')

	Write-Host "[+] Transparency Effects      " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathTransparency $property $value
	# "Transparency has been Disabled"
}

# Modification
function Set_Opt_AlwaysShowScrollbars {
	$pathShowScrollbars = 'HKCU:\Control Panel\Accessibility'
	$property = 'DynamicScrollbars'
	$showScrollbars = (Get-ItemProperty -Path $pathShowScrollbars).$property
	$value = 0

	$status = ($showScrollbars -ne $value) ? $('[OFF]') : $('[ON]')

	Write-Host "[+] Always Show Scrollbars    " -NoNewline
	Test_StatusColor $status
	Set_OptionStatus $pathShowScrollbars $property $value
	#"ShowScrollbars has been Enabled"
	Write-Host ""
}

<#
function Set_Opt_DeviceEncryption () {
    #rest of the code...
}
#>

function Set_Default_Option () {
	Set_Opt_Netplwiz
	Set_Opt_FastStartup
	Set_Opt_StorageSense
	Set_Opt_SnapSuggest
	Set_Opt_ShowFileExtensions
	Set_Opt_ShowHiddenFiFo
	Set_Opt_ShowSyncProvider
	Set_Opt_ShowEndTask
	# Set_Opt_SudoCommand
	Set_Opt_DarkMode
	Set_Opt_TransparencyEffects
	Set_Opt_GetTipsTricks
	Set_Opt_ShowSignInScreen
	Set_Opt_ShowItemSearch
	Set_Opt_ShowItemTaskView
	Set_Opt_HideTaskbar

	Test_Set_Opt_HideTaskbar

	Set_Opt_ShowDesktop
	Set_Opt_ShowSeconds
	Set_Opt_GameBar
	Set_opt_GameMode
	Set_Opt_AlwaysShowScrollbars
}

#function Show InfoService
function InfoService ($service, $serviceName) {
	if ($service) {
        return [PSCustomObject]@{
			"Service Found....." = $serviceName
            "Service Name......" = $service.DisplayName
            "Startup Type......" = $service.StartType
            "Status Type......." = $service.Status
        }
    } else {
        return [PSCustomObject]@{
            "Service not Found." = $serviceName
            "Service Name......" = "Unknown"
            "Startup Type......" = "Unknown"
            "Status Type......." = "Unknown"
        }
    }
}

#function Set Service
function ServiceConfig ($serviceName, $startupType) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    InfoService $service $serviceName | Format-List

	$Cmd1 = "Set-Service -Name '$serviceName' -StartupType $startupType"
	$Cmd2 = "Stop-Service -Name '$serviceName'"
    if ($service) {

		"[*] Setting service [$serviceName] to $startupType."
		Invoke-Expression $Cmd1

		"[*] Stopping service [$serviceName]."
		Invoke-Expression $Cmd2
    } 
    else {
		"[-] Error setting service [$serviceName] to $startupType, Service not found."
		"[-] Error stopping service [$serviceName], Service not found."
		# "Cannot find path 'HKCU:\Software\Microsoft' because it does not exist."
    }
	Write-Host ""
}

#Get-Service | Sort-Object Status, DisplayName | Format-Table -GroupBy Status -Property Status, Name, DisplayName
$servicesDisList = @(
    "XblAuthManager",         #Administración de autenticación de Xbox Live
    "MapsBroker",             #Administrador de mapas descargados
    "SEMgrSvc",               #Administrador de pagos y NFC/SE
    "lmhosts",                #Aplicación auxiliar de NetBIOS sobre TCP/IP
    "iphlpsvc",               #Aplicación auxiliar IP(Error: Tiene servicios que dependen de el)
    "NaturalAuthentication",  #Autenticación natural
    "tzautoupdate",           #Auto Time Zone Updater
    "SNMPTRAP",               #Captura de SNMP
    "autotimesvc",            #Cellular Time
    "Spooler",                #Cola de impresión
    "WpcMonSvc",              #Control parental
    "diagsvc",                #Diagnostic Execution Service
    "SCPolicySvc",            #Directiva de extracción de tarjetas inteligentes
    "DiagTrack",              #Experiencias del usuario y telemetría asociadas
    "PrintNotify",            #Extensiones y notificaciones de impresora
    "W32Time",                #Hora de Windows
    "WdiSystemHost",          #Host de sistema de diagnóstico
    "WdiServiceHost",         #Host del servicio de diagnóstico
    "uhssvc",                 #Microsoft Update Health Service
    #"NgcSvc",                 #Microsoft Passport - (win11 bloqueado)
    #"NgcCtnrSvc",             #Microsoft Passport Container - (win11 bloqueado)
    "Netlogon",               #Net Logon
    "XblGameSave",            #Partida guardada en Xbox Live
    "wercplsupport",          #Problem Reports Control Panel Support
    "CertPropSvc",            #Propagación de certificados
    "RemoteRegistry",         #Remote Registry
    "RetailDemo",             #Retail Demo Service
    "RemoteAccess",           #Routing and Remote Access
    "WbioSrvc",               #Servicio biométrico de Windows
    "BDESVC",                 #Servicio Cifrado de unidad BitLocker
    "DPS",                    #Servicio de directivas de diagnóstico
    "AJRouter",               #Servicio de enrutador de AllJoyn
    "dmwappushservice",       #Servicio de enrutamiento de mensajes de inserción .. (WAP) ..
    "ScDeviceEnum",           #Servicio de enumeración de dispositivos de tarjeta inteligente
    "XboxNetApiSvc",          #Servicio de red de Xbox Live
    "wisvc",                  #Servicio de Windows Insider
    "MSiSCSI",                #Servicio del iniciador iSCSI de Microsoft
    "SmsRouter",              #Servicio enrutador de SMS de Microsoft Windows.
    "PhoneSvc",               #Servicio telefónico
    "VacSvc",                 #Servicio Volumetric Audio Compositor
    "shpamsvc",               #Shared PC Account Manager--si existe
    "SCardSvr",               #Tarjeta inteligente
    "TapiSrv",                #Telefonía
    "WalletService",          #WalletService
    "MixedRealityOpenXRSvc",  #Windows Mixed Reality OpenXR Service
    "WSearch",                #Windows Search
    "XboxGipSvc"              #Xbox Accessory Management Service
)

$servicesManList = @(
    "lfsvc",                          #Servicio de geolocalización
    "MicrosoftEdgeElevationService",  #Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)
    "edgeupdate",                     #Microsoft Edge Update Service (edgeupdate)
    "edgeupdatem",                    #Microsoft Edge Update Service (edgeupdatem)
    "wuauserv"                        #Windows Update
)

function Set_Service_Startup () {
	Write-Host "SET SERVICES`n------------"
	foreach ($serviceName in $servicesDisList) {
		ServiceConfig $serviceName Disabled
	}
	
	foreach ($serviceName in $servicesManList) {
		ServiceConfig $serviceName Manual
	}
}

function InfoTask ($task, $taskName) {
    if ($task) {
		return [PSCustomObject]@{
			"Task Found....." = $taskName
			"Task Path......" = $task.TaskPath
			"Task URI......." = $task.URI
			"State Type....." = $task.State
		}
    } else {
		return [PSCustomObject]@{
			"Task not Found." = $taskName
			"Task Path......" = "Unknown"
			"Task URI......." = "Unknown"
			"State Type....." = "Unknown"
		}
    }
}

function TaskConfig ($taskPath, $taskName, $stateType) {
    $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName

    InfoTask $task $taskName | Format-List

	$newState = $stateType.Substring(0, $stateType.Length - 1)
	$Cmd = "$newState-ScheduledTask -TaskPath '$taskPath' -TaskName '$taskName'"
    if ($task) {

		"[*] Setting task [$taskName] to $stateType."
		$null = Invoke-Expression $Cmd
	}
	else {
		"[-] Error setting task [$taskName] to $stateType, Task not found."
		# "Cannot find path 'HKCU:\Software\Microsoftkkkk' because it does not exist."
	}
	Write-Host ""
}

$tasksDisList = @(
    @{ 
		Path = "\" 
		Name = "MicrosoftEdgeUpdateTaskMachineCore" 
	},
	@{ 
		Path = "\" 
		Name = "MicrosoftEdgeUpdateTaskMachineUA" 
	},
	@{ 
		Path = "\Microsoft\Windows\Application Experience\" 
		Name = "Microsoft Compatibility Appraiser" 
	},
	@{ 
		Path = "\Microsoft\Windows\Application Experience\" 
		Name = "StartupAppTask" 
	},
	@{ 
		Path = "\Microsoft\Windows\Customer Experience Improvement Program\" 
		Name = "Consolidator" 
	},
	@{ 
		Path = "\Microsoft\Windows\Customer Experience Improvement Program\" 
		Name = "UsbCeip" 
	},
    @{ 
		Path = "\Microsoft\Windows\Maps\" 
		Name = "MapsUpdateTask" 
	},
	@{ 
		Path = "\Microsoft\Windows\Windows Defender\" 
		Name = "Windows Defender Verification" 
	},
	@{ 
		Path = "\Microsoft\Windows\WindowsUpdate\" 
		Name = "Scheduled Start" 
	},
    @{ 
		Path = "\Microsoft\XblGameSave\" 
		Name = "XblGameSaveTask" 
	},
	@{
		Path = "\Microsoft\Office\" 
		Name = "Office Performance Monitor" 
	},
	@{
		Path = "\Microsoft\Office\" 
		Name = "Office Feature Updates Logon" 
	},
	@{
		Path = "\Microsoft\Office\" 
		Name = "Office Feature Updates" 
	},
	@{
		Path = "\Microsoft\Office\" 
		Name = "Office Automatic Updates 2.0" 
	}
)

# Modifcate 4.0: Task Sheduler
function Set_Scheduled_Task () {
	Write-Host "SET SCHEDULED TASKS`n-------------------"
	foreach ($task in $tasksDisList) {
		TaskConfig $task.Path $task.Name Disabled
	}
}

function Install_Module_Appx {

	Write-Host "PS Module Appx`n--------------"
	InstallModule "Appx"
	ActivateModule "Appx"
	Write-Host ""
}

#function Remove AppxPackage
#Get-AppxPackage | Select Name, PackageFullName | Format-List
function RemoveUserAppx ($appxName) {
	$appx = Get-AppxPackage | Where-Object { $_.Name -like "*$appxName*" }
	
	$appx | Format-List Name, Version, Architecture, ResourceId, PackageFullName, Status
    if ($appx) {

		"Removing userAppx [$appxName] from the current user account."
		"$($appx.PackageFullName)" | Remove-AppxPackage
    } 
    else {
        "Error removing userAppx [$appxName], Appx not found."
    }
}

# HideApps 4.1: Blotware in Windows
#Get-AppxPackage | Select Name, PackageFullName
$userPackageList = [ordered]@{
    "Microsoft Clipchamp"     = "Clipchamp.Clipchamp"
    "Cortana"                 = "Microsoft.549981C3F5F10"
    "Microsoft News"          = "Microsoft.BingNews"
    "MSN Weather"             = "Microsoft.BingWeather"
    "Xbox App"                = "Microsoft.GamingApp"
    "Get Help"                = "Microsoft.GetHelp"
    "Get Started"             = "Microsoft.Getstarted"
	"HEIF Image Extension"    = "Microsoft.HEIFImageExtension"
	"HEVC Video Extension"    = "Microsoft.HEVCVideoExtension"
	"Paint 3D"                = "Microsoft.Microsoft3DViewer"
    # "Microsoft Edge"          = "Microsoft.MicrosoftEdge.Stable"        #QUITARLO ROMPE COSAS
    "Microsoft 365 (PWA)"     = "Microsoft.MicrosoftOfficeHub"
    "Solitaire Collection"    = "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft Sticky Notes"  = "Microsoft.MicrosoftStickyNotes"
	"Mixed Reality Portal"    = "Microsoft.MixedReality.Portal"
	"Paint (OLD)"             = "Microsoft.MSPaint"
    "Outlook for Windows"     = "Microsoft.OutlookForWindows"
    "Microsoft People"        = "Microsoft.People"
    "Power Automate"          = "Microsoft.PowerAutomateDesktop"
	"Raw Image Extension"     = "Microsoft.RawImageExtension"
	"Snipping Tool"           = "Microsoft.ScreenSketch"
    "Microsoft To Do"         = "Microsoft.Todos"
	"VP9 Video Extension"     = "Microsoft.VP9VideoExtensions"
    "Microsoft Wallet"        = "Microsoft.Wallet"
	"Web Media Extension"     = "Microsoft.WebMediaExtensions"
	"Webp Image Extension"    = "Microsoft.WebpImageExtension"
    "Dev Home"                = "Microsoft.Windows.DevHome"
    "Microsoft Photos"        = "Microsoft.Windows.Photos"
	"Windows Clock"           = "Microsoft.WindowsAlarms"
	"Windows Calculator"      = "Microsoft.WindowsCalculator"
	"Windows Camera"          = "Microsoft.WindowsCamera"
	"Mail and Calendar"       = "microsoft.windowscommunicationsapps"
    "Feedback Hub"            = "Microsoft.WindowsFeedbackHub"
    "Windows Maps"            = "Microsoft.WindowsMaps"
	"Windows Notepad"         = "Microsoft.WindowsNotepad"
	"Windows Sound Recorder"  = "Microsoft.WindowsSoundRecorder"
    "Xbox TCUI"               = "Microsoft.Xbox.TCUI"
    "Xbox App (OLD)"          = "Microsoft.XboxApp"
    "Xbox Game Overlay"       = "Microsoft.XboxGameOverlay"
    "Game Bar"                = "Microsoft.XboxGamingOverlay"
    "Xbox Provider"           = "Microsoft.XboxIdentityProvider"
    "Xbox Text Overlay"       = "Microsoft.XboxSpeechToTextOverlay"
    "Phone Link"              = "Microsoft.YourPhone"
    "Windows Media Player"    = "Microsoft.ZuneMusic"
	"Movies & TV"             = "Microsoft.ZuneVideo"
    "Microsoft Family Safety" = "MicrosoftCorporationII.MicrosoftFamily"
    "Quick Assist"            = "MicrosoftCorporationII.QuickAssist"
    "Widgets"                 = "MicrosoftWindows.Client.WebExperience"
    "Spotify Music"           = "SpotifyAB.SpotifyMusic"

    #"linkedin"               = "linkedin_searchId"                       #BUSCAR ID COMPLETO
    #"Camo Studio"            = "CamoStudio_searchId"                     #BUSCAR ID COMPLETO
}

function Remove_User_Appx () {

	Write-Host "REMOVE USER APPX`n----------------"
	foreach ($appxName in $userPackageList.Keys) {
		$appxId = $userPackageList[$appxName]

		Write-Host "Remove AppxUser [" -NoNewline
		Write-Host $appxName -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			RemoveUserAppx $appxId
		}
		Write-Host ""
	}
}

# Uninstall 5.0: ProvisionedAppxPackages list
<#
# Function Get PackageFullName
function Get-PackageFullName ($packageName){
    $output = DISM /Online /Get-ProvisionedAppxPackages | Select-String Packagename
    $lines = $output -split "`n"

    foreach ($line in $lines) {
        if ($line -match "PackageName : ($packageName.*)") {
            return $matches[1]
        }
    }
	return $null
}
#>

#function Remove ProvisionedAppxPackage
#Get-AppxProvisionedPackage -Online | Select DisplayName, PackageName | Format-List
function RemoveProAppx ($appxName) {
	$appx = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$appxName*" }

	$appx | Format-List
	if ($appx) {

        "Removing provisionedAppx [$appxName] from Windows image."
        DISM /Online /Remove-ProvisionedAppxPackage /PackageName:"$($appx.PackageName)"
		# "$($appx.PackageName)" | Remove-AppxProvisionedPackage -Online
    } 
	else {
        "Error removing provisionedAppx [$appxName], Appx not found."
    }
}

# Uninstall 5.0: Blotware in Windows
#DISM /Online /Get-ProvisionedAppxPackages | select-string Packagename
$provPackageList = [ordered]@{
	"Microsoft Clipchamp"     = "Clipchamp.Clipchamp"
    "Cortana"                 = "Microsoft.549981C3F5F10"
    "Microsoft News"          = "Microsoft.BingNews"
    "MSN Weather"             = "Microsoft.BingWeather"
    "Xbox App"                = "Microsoft.GamingApp"
    "Get Help"                = "Microsoft.GetHelp"
    "Get Started"             = "Microsoft.Getstarted"
	"HEIF Image Extension"    = "Microsoft.HEIFImageExtension"
	"HEVC Video Extension"    = "Microsoft.HEVCVideoExtension"
	"Paint 3D"                = "Microsoft.Microsoft3DViewer"
    #"Microsoft Edge"          = "Microsoft.MicrosoftEdge.Stable"         #QUITARLO ROMPE COSAS
    "Microsoft 365 (PWA)"     = "Microsoft.MicrosoftOfficeHub"
    "Solitaire Collection"    = "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft Sticky Notes"  = "Microsoft.MicrosoftStickyNotes"
	"Mixed Reality Portal"    = "Microsoft.MixedReality.Portal"
	"Paint (OLD)"             = "Microsoft.MSPaint"
	"OneNote"                 = "Microsoft.Office.OneNote"
    "Outlook for Windows"     = "Microsoft.OutlookForWindows"
	"Paint"                   = "Microsoft.Paint"
    "Microsoft People"        = "Microsoft.People"
    "Power Automate"          = "Microsoft.PowerAutomateDesktop"
	"Raw Image Extension"     = "Microsoft.RawImageExtension"
	"Snipping Tool"           = "Microsoft.ScreenSketch"
	"Skype"                   = "Microsoft.SkypeApp"
    "Microsoft To Do"         = "Microsoft.Todos"
	"VP9 Video Extension"     = "Microsoft.VP9VideoExtensions"
    "Microsoft Wallet"        = "Microsoft.Wallet"
	"Web Media Extension"     = "Microsoft.WebMediaExtensions"
	"Webp Image Extension"    = "Microsoft.WebpImageExtension"
    "Dev Home"                = "Microsoft.Windows.DevHome"
    "Microsoft Photos"        = "Microsoft.Windows.Photos"
	"Windows Clock"           = "Microsoft.WindowsAlarms"
	"Windows Calculator"      = "Microsoft.WindowsCalculator"
	"Windows Camera"          = "Microsoft.WindowsCamera"
	"Mail and Calendar"       = "microsoft.windowscommunicationsapps"
    "Feedback Hub"            = "Microsoft.WindowsFeedbackHub"
    "Windows Maps"            = "Microsoft.WindowsMaps"
	"Windows Notepad"         = "Microsoft.WindowsNotepad"
	"Windows Sound Recorder"  = "Microsoft.WindowsSoundRecorder"
    "Xbox TCUI"               = "Microsoft.Xbox.TCUI"
    "Xbox Game Overlay"       = "Microsoft.XboxGameOverlay"
    "Game Bar"                = "Microsoft.XboxGamingOverlay"
    "Xbox Provider"           = "Microsoft.XboxIdentityProvider"
    "Xbox Text Overlay"       = "Microsoft.XboxSpeechToTextOverlay"
    "Phone Link"              = "Microsoft.YourPhone"
    "Windows Media Player"    = "Microsoft.ZuneMusic"
	"Movies & TV"             = "Microsoft.ZuneVideo"
    "Microsoft Family Safety" = "MicrosoftCorporationII.MicrosoftFamily"
    "Quick Assist"            = "MicrosoftCorporationII.QuickAssist"
    "Widgets"                 = "MicrosoftWindows.Client.WebExperience"

    #"linkedin"               = "linkedin_searchId"                       #BUSCAR ID COMPLETO
    #"Camo Studio"            = "CamoStudio_searchId"                     #BUSCAR ID COMPLETO
}

function Remove_Provisioned_Appx () {
	Write-Host "REMOVE PROVISIONED APPX`n-----------------------"
	foreach ($appxName in $provPackageList.Keys) {
		$appxId = $provPackageList[$appxName]

		Write-Host "Remove AppxProvisioned [" -NoNewline
		Write-Host $appxName -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			RemoveProAppx $appxId
		}
		Write-Host ""
	}
}

# FeatureWindow 5: Enable or Disable features
#function ...
function InfoFeature ($feature, $featureName) {
	if ($feature) {
		return [PSCustomObject]@{
			"Feature Found......." = $featureName
			"Feature Name........" = $feature.DisplayName
			"Feature Description." = $feature.Description
			"State Type.........." = $feature.State
		}
	} else {
		return [PSCustomObject]@{
			"Feature not Found..." = $featureName
			"Feature Name........" = "Unknown"
			"Feature Description." = "Unknown"
			"State Type.........." = "Unknown"
		}
	}
}

# function...
function FeatureConfig ($featureName, $stateType) {
	$feature = Get-WindowsOptionalFeature -FeatureName $featureName -Online

	InfoFeature $feature $featureName | Format-List
	
	$newState = $stateType.Substring(0, $stateType.Length - 1)
	$acctionCmd = "$newState-WindowsOptionalFeature -FeatureName '$featureName' -Online"
	if ($feature) {
		
		"Setting feature [$featureName] to $stateType."
		$null = Invoke-Expression $acctionCmd
    } 
	else {
		"Error setting feature [$featureName] to $stateType, Feature not found."
		# "Cannot find path 'HKCU:\Software\Microsoft' because it does not exist."
    }
}

# Features 5.3: Turn on/off
function Set_Optional_Feature () {
    Write-Host "SET OPTIONAL FEATURES`n---------------------"

	Write-Host "Disable Feature [" -NoNewline
	Write-Host "Media Features" -ForegroundColor Cyan -NoNewline; "]?"

	Invoke-Confirmation {
		FeatureConfig "MediaPlayback" Disabled
	}
	Write-Host ""

	# FeatureConfig "WindowsMediaPlayer" Disabled #[Reproductor de Windows Media]

	Write-Host "Disable Feature [" -NoNewline
	Write-Host "Internet Explorer 11" -ForegroundColor Cyan -NoNewline; "]?"

	Invoke-Confirmation {
		FeatureConfig "Internet-Explorer-Optional-amd64" Disabled
	}
	Write-Host ""

	Write-Host "Enbale Feature [" -NoNewline
	Write-Host ".NET Framework 3.5" -ForegroundColor Cyan -NoNewline; "]?"

	Invoke-Confirmation {
		FeatureConfig "NetFx3" Enabled
	}
	Write-Host ""
	
	Write-Host "Enbale Feature [" -NoNewline
	Write-Host "Windows Sandbox" -ForegroundColor Cyan -NoNewline; "]?"

	Invoke-Confirmation {
		FeatureConfig "Containers-DisposableClientVM" Enabled
	}
	Write-Host ""
}

# Install 6: App list
#function Install App
function InstallApp ($appId, $sourceType) {
	$listCmd = "$sourceType list --id $appId"
	$outputGet = Invoke-Expression $listCmd -ErrorAction SilentlyContinue
	$installed = $outputGet | Where-Object { $_.contains("$appId") }
	
	$installCmd = "$sourceType install --id '$appId'"
    if (!$installed) {
		
        Write-Host "App [$appId] Installing..."
		Invoke-Expression $installCmd
    } 
	else {
		Write-Host "App [$appId] Already Installed."
		Write-Host "Found an existing package already installed."
    }
}

# winget search [Manufacture.AppName]
$wingetList = [ordered]@{
    #"Visual C++ 2005(x86)"       = "Microsoft.VCRedist.2005.x86"
    #"Visual C++ 2005(x64)"       = "Microsoft.VCRedist.2005.x64"
    #"Visual C++ 2008(x86)"       = "Microsoft.VCRedist.2008.x86"
    #"Visual C++ 2008(x64)"       = "Microsoft.VCRedist.2008.x64"
    "Visual C++ 2010(x86)"        = "Microsoft.VCRedist.2010.x86"
    "Visual C++ 2010(x64)"        = "Microsoft.VCRedist.2010.x64"
    #"Visual C++ 2012(x86)"       = "Microsoft.VCRedist.2012.x86"
    #"Visual C++ 2012(x64)"       = "Microsoft.VCRedist.2012.x64"
    #"Visual C++ 2013(x86)"       = "Microsoft.VCRedist.2013.x86"
    #"Visual C++ 2013(x64)"       = "Microsoft.VCRedist.2013.x64"
    "Visual C++ 2015+(x86)"       = "Microsoft.VCRedist.2015+.x86"
    "Visual C++ 2015+(x64)"       = "Microsoft.VCRedist.2015+.x64"
    #"hide.me VPN"                = "eVenture.HideMe"
    "Bitwarden"                   = "Bitwarden.Bitwarden"
    "Firefox Browser"             = "Mozilla.Firefox"
    "Vivaldi Browser"             = "Vivaldi.Vivaldi"
	"Brave Browser"               = "Brave.Brave"
	"Opera Browser"               = "Opera.Opera"
	"OperaGX Browser"             = "Opera.OperaGX"
	"Microsoft Edge"              = "Microsoft.Edge"
	"Google Chrome"               = "Google.Chrome"
    "AutoHotkey"                  = "AutoHotkey.AutoHotkey"
    "ZoomIt"                      = "Microsoft.Sysinternals.ZoomIt"
    "Energy Star X"               = "9NF7JTB3B17P"
	"Everything x64"              = "voidtools.Everything"
	"Microsoft PC Manager"        = "9PM860492SZD"
    "Lightshot"                   = "Skillbrains.Lightshot"                # USO TEMPORAL
    "QuickLook"                   = "QL-Win.QuickLook"                     # USO TEMPORAL
    "Quick Share Google"          = "Google.QuickShare"
    "PowerToys (Preview)"         = "Microsoft.PowerToys"
	"FxSound"                     = "FxSoundLLC.FxSound"
	"Fan Control"                 = "Rem0o.FanControl"
    "MSI Afterburner"             = "Guru3D.Afterburner"
    "Git"                         = "Git.Git"
	"Python 3.12"                 = "Python.Python.3.12"
	# "Rustup: toolchain"           = "Rustlang.Rustup"
	"Rust (MSVC)"                 = "Rustlang.Rust.MSVC"                   # (v1.78.0)
	"7-Zip"                       = "7zip.7zip"
	"WinRAR"                      = "RARLab.WinRAR"
	"Box Desktop"                 = "Box.Box"
	"MEGA Desktop"                = "Mega.MEGASync"
	"Google Drive"                = "Google.GoogleDrive"
	"TeraBox Desktop"             = "Baidu.TeraBox"
	"GitHub Desktop"              = "GitHub.GitHubDesktop"
	"Docker Desktop"              = "Docker.DockerDesktop"
    "Neovim"                      = "Neovim.Neovim"
    "Notepad++"                   = "Notepad++.Notepad++"
	"GIMP"                        = "GIMP.GIMP"
	"Audacity"                    = "Audacity.Audacity"
    "IrfanView x64"               = "IrfanSkiljan.IrfanView"
	"VLC Media Player"            = "VideoLAN.VLC"
    "SumatraPDF"                  = "SumatraPDF.SumatraPDF"
	"Microsoft 365 Apps"          = "Microsoft.Office"
	"OnlyOffice"                  = "ONLYOFFICE.DesktopEditors"
	"LibreOffice LTS"             = "TheDocumentFoundation.LibreOffice.LTS"
    "Steam"                       = "Valve.Steam"
    "Epic Games Launcher"         = "EpicGames.EpicGamesLauncher"
	"Ubisoft Connect"             = "Ubisoft.Connect"
	"BlueStacks"                  = "BlueStack.BlueStacks"
    "qBittorrent"                 = "qBittorrent.qBittorrent"
    "WhatsApp"                    = "9NKSQGP7F2NH"
    "Telegram"                    = "Telegram.TelegramDesktop"
	"Mozilla Thunderbird"         = "Mozilla.Thunderbird"
    "scrcpy"                      = "Genymobile.scrcpy"
    "Discord"                     = "Discord.Discord"
    "Zoom Workplace"              = "Zoom.Zoom"
	"Microsoft Teams (New)"       = "Microsoft.Teams"
	"Slack"                       = "SlackTechnologies.Slack"
	"OBS Studio"                  = "OBSProject.OBSStudio"
	"Blender"                     = "BlenderFoundation.Blender"
	#"MiniTool Partition Wizard"  = "MiniTool.PartitionWizard.Free"
    "PuTTY"                       = "PuTTY.PuTTY"
    "WinSCP"                      = "WinSCP.WinSCP"
	"TeamViewer"                  = "TeamViewer.TeamViewer"
	"Oracle VM VirtualBox"        = "Oracle.VirtualBox"
	"VMware Workstation Pro"      = "VMware.WorkstationPro"
    "TechPowerUp GPU-Z"           = "TechPowerUp.GPU-Z"
    #"NVCleanstall"               = "TechPowerUp.NVCleanstall"
    "WinDirStat"                  = "WinDirStat.WinDirStat"
    "BleachBit"                   = "BleachBit.BleachBit"
    "Recuva"                      = "Piriform.Recuva"
    "Visual Studio Code"          = "Microsoft.VisualStudioCode"           # revisar opcion seteada
    "Node.js LTS"                 = "OpenJS.NodeJS.LTS"
    "Visual Studio Community"     = "Microsoft.VisualStudio.2022.Community"
    # "SQLServer Express"           = "Microsoft.SQLServer.2022.Express"
    "SQLServer Management Studio" = "Microsoft.SQLServerManagementStudio"
    "Java SDK"                    = "Oracle.JDK.22"
    "Apache NetBeans IDE"         = "Apache.NetBeans"
    "MySQL"                       = "Oracle.MySQL"
    # "PostgreSQL 16"               = "PostgreSQL.PostgreSQL"              # revisar compilacion seteada
    "Android Studio"              = "Google.AndroidStudio"
    "App Installer"               = "Microsoft.AppInstaller"
	"Windows Terminal"            = "Microsoft.WindowsTerminal"
}

# choco search [AppName]
$chocoList = [ordered]@{
	"Fing Desktop"        = "fing"
    "Keypirinha Launcher" = "keypirinha"
    "AIMP Music Player"   = "aimp"
	"FileZilla Client"    = "filezilla"
}

function Install_Apps () {
	Write-Host "Winget Search Apps`n------------------"
	foreach ($app in $wingetList.Keys) {
		$appId = $wingetList[$app]

		Write-Host "Install App [" -NoNewline
		Write-Host $app -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			InstallApp $appId winget
		}
		Write-Host ""
	}

	Write-Host "Choco Search Apps`n-----------------"
	foreach ($app in $chocoList.Keys) {
		$appId = $chocoList[$app]
		
		Write-Host "Install App [" -NoNewline
		Write-Host $app -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			InstallApp $appId choco
		}
		Write-Host ""
	}
}

function DownloadApp ($toolUrl, $toolFile) {
	$pathLocation = "$HOME\Documents"
	$item = 'APP-PC'# 'APP-TOOLS'
	$filePath = "$pathLocation\$item\$toolFile"
	
	Test_Item $pathLocation $item

	if (!(Test-Path -Path $filePath)) {
		
		Write-Host "Tool [$toolFile] Downloading...`nUrl: $toolUrl"
		Invoke-WebRequest -Uri $toolUrl -OutFile $filePath
		Get-ChildItem $filePath
	} 
	else {
		Write-Host "Tool [$toolFile] Already Downloaded"
		Write-Host "Found an existing tool already downloaded."
	}
}

$toolList = @(
	@{
		Name = "AnyDesk"
		TUrl = "https://download.anydesk.com/AnyDesk.exe"
		File = "AnyDesk.exe"
	},
	@{
		Name = "Autoruns"
		TUrl = "https://download.sysinternals.com/files/Autoruns.zip"
		File = "Autoruns.zip"
	},
	@{
		Name = "Process Explorer"
		TUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
		File = "ProcessExplorer.zip"
	},
	@{
		Name = "TCPView"
		TUrl = "https://download.sysinternals.com/files/TCPView.zip"
		File = "TCPView.zip"
	},
	@{
		Name = "pestudio"
		TUrl = "https://www.winitor.com/tools/pestudio/current/pestudio-9.58.zip"
		File = "pestudio-9.58.zip"
	},
	@{
		Name = "Rufus"
		TUrl = "https://github.com/pbatard/rufus/releases/download/v4.5/rufus-4.5p.exe"
		File = "rufus-4.5p.exe"
	},
	@{
		Name = "Crucial Scan"
		TUrl = "https://www.crucial.com/content/dam/crucial/support/scan/downloads/CrucialScan.exe"
		File = "CrucialScan.exe"
	},
	@{
		Name = "CPU-Z"
		TUrl = "https://download.cpuid.com/cpu-z/cpu-z_2.09-en.zip"
		File = "cpu-z_2.09-en.zip"
	},
	@{
		Name = "HWMonitor"
		TUrl = "https://download.cpuid.com/hwmonitor/hwmonitor_1.53.zip"
		File = "hwmonitor_1.53.zip"
	},
	@{
		Name = "HWiNFO"
		TUrl = "https://www.sac.sk/download/utildiag/hwi_802.zip"
		File = "hwi_802.zip"
	},
	@{
		Name = "CrystalDiskInfo"
		TUrl = "https://downloads.sourceforge.net/project/crystaldiskinfo/9.3.0/CrystalDiskInfo9_3_0.zip?ts=gAAAAABmVQXR9RjeNxz_DObPbCgIlEDUHIwkG8HfdNZy1fM-Yto8gwcF7wyCJFJv7eAxoq5_DZhJLbQ-nWE7Jj11MEXsanNC7A%3D%3D&use_mirror=sitsa&r=https%3A%2F%2Fcrystalmark.info%2F"
		File = "CrystalDiskInfo9_3_0.zip"
	},
	@{
		Name = "Hard Disk Sentinel"
		TUrl = "https://www.harddisksentinel.com/hdsentinel_pro_portable.zip"
		File = "hdsentinel_pro_portable.zip"
	},
	@{
		Name = "Revo Uninstaller"
		TUrl = "https://download.revouninstaller.com/download/RevoUninstaller_Portable.zip"
		File = "RevoUninstaller_Portable.zip"
	},
	@{
		Name = "Bulk Crap Uninstaller"
		TUrl = "https://github.com/Klocman/Bulk-Crap-Uninstaller/releases/download/v5.8/BCUninstaller_5.8_portable.zip"
		File = "BCUninstaller_5.8_portable.zip"
	},
	@{
		Name = "Android SDK Tools"
		TUrl = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
		File = "platform-tools-latest-windows.zip"
	},
	@{
		Name = "Display Driver Uninstaller"
		TUrl = "https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.7.6.exe"
		File = "DDU v18.0.7.6.exe"
	}
)

#function Download App Portable
function Download_Tools () {
	Write-Host "Url Search Tools`n------------------"
	foreach ($tool in $toolList) {

		Write-Host "Download App Portable [" -NoNewline
		Write-Host $tool.Name -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			DownloadApp $tool.TUrl $tool.File
		}
		Write-Host ""
	}
}

function Get-StatusValue {
	param (
		[string]$trimString
	)
	
	if ($trimString -match "DisableDeleteNotify = 1") {
		return 1
	} 
	else {
		return 0
	}
}

# Modification 3.0: Configure TRIM for SSD
function Set_Config_TurnTrimSSD {
    $trimCmd = fsutil behavior query DisableDeleteNotify
	$trimString = $trimCmd -match "NTFS DisableDeleteNotify = (\d)"
	$value = 0

	$trimValue = Get-StatusValue $trimString

	"The current value [TRIM operations] is [$trimValue]"
    if ($trimValue -ne $value) {
    	
    	"Setting status [TRIM operations] to Enabled."
    	fsutil behavior set DisableDeleteNotify $value
    }
    else {
    	"Status [TRIM operations] has already been Enabled."
    }
}

# Modification 3.0: Configure Memory Management Agent
function Set_Config_MemoryCompression {
	$property = 'MemoryCompression'
    $mcValue = (Get-MMAgent).$property

    "The current status [$property] is [$mcValue]"
    if (!$mcValue) {
        
        "Setting status [$property] to Enabled."
        Enable-MMAgent -MemoryCompression
    } 
	else {
        "Status [$property] has already been Enabled."
    }
}

# Modification 3.0: Configure Windows Defender
function Set_Config_ScanCpuLoad {
	$property = 'ScanAvgCPULoadFactor'
    $preference = (Get-MpPreference).$property
    $value = 1
    
    "The current value [$property] is [$preference]"
    if ($preference -ne $value) {

        "Setting value [$property] to [1]."
        Set-MpPreference -ScanAvgCPULoadFactor $value
    } 
	else {
        "Value [$property] has already been set to [1]."
    }
}

function Minimum_Preferences {
	$pathPreferencesMask = 'HKCU:\Control Panel\Desktop'
	$property1 = 'UserPreferencesMask'
	$preferMask = (Get-ItemProperty -Path $pathPreferencesMask).$property1
	$value = 0x90
	
	if ($preferMask[0] -ne $value) {
		$preferMask[0] = 0x90 ; $preferMask[1] = 0x12
		$preferMask[2] = 0x03 ; $preferMask[4] = 0x10

		"Setting options minimum [$property1] to Disabled."
		Set-ItemProperty -Path $pathPreferencesMask -Name $property1 -Value $preferMask -Force
	} 
	else {
		"Options minimum [$property1] has already been Disabled."
	}
}

function Animate_MinMax {
	$pathAnimateMinMax = 'HKCU:\Control Panel\Desktop\WindowMetrics'
	$property2 = 'MinAnimate'
	$animateMinMax = (Get-ItemProperty -Path $pathAnimateMinMax).$property2
	$value = 0

	if ($animateMinMax -ne $value) {

		"Setting option [$property2] to Disabled."
		Set-ItemProperty -Path $pathAnimateMinMax -Name $property2 -Value $value -Force
	} 
	else {
		"Option [$property2] has already been Disabled."
	}
}

function Animate_Taskbar {
	$pathTaskbarAnimations = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property3 = 'TaskbarAnimations'
	$taskbarAnimations = (Get-ItemProperty -Path $pathTaskbarAnimations).$property3
	$value = 0

	if ($taskbarAnimations -ne $value) {

		"Setting option [$property3] to Disabled."
		Set-ItemProperty -Path $pathTaskbarAnimations -Name $property3 -Value $value -Force
	} 
	else {
		"Option [$property3] has already been Disabled."
	}
}

function Enable_Peek {
	$pathEnablePeek = 'HKCU:\Software\Microsoft\Windows\DWM'
	$property4 = 'EnableAeroPeek'
	$enablePeek = (Get-ItemProperty -Path $pathEnablePeek).$property4
	$value = 0

	if ($enablePeek -ne $value) {

		"Setting option [$property4] to Disabled."
		Set-ItemProperty -Path $pathEnablePeek -Name $property4 -Value $value -Force
	} 
	else {
		"Option [$property4] has already been Disabled."
	}
}

function Show_Translucent {
	$pathTranslucent = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property5 = 'ListviewAlphaSelect'
	$translucent = (Get-ItemProperty -Path $pathTranslucent).$property5
	$value = 0

	if ($translucent -ne $value) {

		"Setting option [$property5] to Disabled."
		Set-ItemProperty -Path $pathTranslucent -Name $property5 -Value $value -Force
	} 
	else {
		"Option [$property5] has already been Disabled."
	}
}

function Drop_Shadows {
	$pathDropShadows = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property6 = 'ListviewShadow'
	$dropShadows = (Get-ItemProperty -Path $pathDropShadows).$property6
	$value = 0
	
	if ($dropShadows -ne $value) {

		"Setting option [$property6] to Disabled."
		Set-ItemProperty -Path $pathDropShadows -Name $property6 -Value $value -Force
	} 
	else {
		"Option [$property6] has already been Disabled."
	}
}

function Set_Appearance_Custom {
	$pathVisualEffects = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
	$property = 'VisualFXSetting'
    $visualEffects = (Get-ItemProperty -Path $pathVisualEffects).$property
	$value = 3

	if ($visualEffects -ne $value) {

		"Setting appearance [$property] to Custom."
		Set-ItemProperty -Path $pathVisualEffects -Name $property -Value $value -Force
	} 
	else {
		"Appearance [$property] has already been set to Custom."
	}

	#************************************************************************

	# Efectos visuales minimos
	Minimum_Preferences
	Animate_MinMax
	Animate_Taskbar
	Enable_Peek
	Show_Translucent
	Drop_Shadows
}

$performanceFnList = [ordered]@{
	"Turn Trim SSD"      = "Set_Config_TurnTrimSSD"
	"Memory Compression" = "Set_Config_MemoryCompression"
	"Scan CPU Load"      = "Set_Config_ScanCpuLoad"
	"Appearance Custom"  = "Set_Appearance_Custom"
}

function Set_Performance_Mode () {

	foreach ($performanceFn in $performanceFnList.Keys) {
		$performanceFnName = $performanceFnList[$performanceFn]

		Write-Host "Do you want to Apply [" -NoNewline
		Write-Host $performanceFn -ForegroundColor Cyan -NoNewline; "]?"

		Invoke-Confirmation {
			& $performanceFnName
		}
		Write-Host ""
	}
}

# MyTheme 7: Custom Terminal
#function Install module
function InstallModule ($moduleName) {
	$modComand = $moduleName -eq "Terminal-Icons" ? " -Repository PSGallery" : ""
	
	$moduleComand = 'Install-Module -Name ' + $moduleName + $modComand + ' -Force'
	if (!(Get-Module -ListAvailable -Name $moduleName)) {
		Write-Host "Module [$moduleName] not found, Installing."
		
		Write-Host "Module [$moduleName] has been Installed."
		Invoke-Expression $moduleComand
	} 
	else {
		Write-Host "Module [$moduleName] found, Already Exists."
		Write-Host "Module [$moduleName] remains Installed."
	}
}

#function Activate module
function ActivateModule ($moduleName) {

	$iconsComand = "Import-Module -Name $moduleName"
	if (!(Get-Module -Name $moduleName)) {
		
		Write-Host "Module [$moduleName] has been Activated."
		Invoke-Expression $iconsComand
	} 
	else {
		Write-Host "Module [$moduleName] remains Activated."
	}

	return $iconsComand
}

# var Deprecated
$VersionNumber = $PSVersionTable.PSVersion.Major
# function Deprecated
function Get-PoshTheme {

	$PoshThemeName = switch ($VersionNumber) {
		7 { 
			'kushal'
		}
		5 { 
			'kali'
		}
		Default { 
			'jandedobbeleer'
		}
	}

	return $PoshThemeName
}

# MyTheme 7.1: Verificar si OhMyPosh está instalado [Get-PoshThemes]
function Install_Prompt_Terminal {
	param (
		[string]$themeName
	)

	Write-Host "Prompt Oh-My-Posh`n-----------------"
	# Instalar Oh-My-Posh en la terminal
	InstallApp "JanDeDobbeleer.OhMyPosh" winget
	Write-Host ""
	
	# $themeName = Get-PoshTheme
	$initPrompt = 'oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\' + $themeName + '.omp.json"'
	$activatePrompt = Invoke-Expression $initPrompt
	
	# Iniciar y Activar Oh-My-Posh en la terminal
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Initializing...`n$initPrompt`n"
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Activating...`n$activatePrompt`n"
	
	return $activatePrompt
}

# MyTheme 7.2: Verificar si los Modulos estan instalados
function Install_Module_Terminal {
	
	Write-Host "PS Module TerminalIcons`n-----------------------"
	# MyTheme 7.2: Module Terminal-Icons	
	InstallModule "Terminal-Icons"
	$iconsComand = ActivateModule "Terminal-Icons"
	Write-Host ""
	
	Write-Host "PS Module Z`n-----------"
	# MyTheme 7.2: Module z
	InstallModule "z"
	Write-Host ""

	return $iconsComand
}

# MyTheme 7.3: Activar la vista del historial
function Enable_ListView_Terminal {
	
	$modeName = 'ListView'
	$option = Get-PSReadLineOption | Where-Object { $_.PredictionViewStyle -notlike "$modeName" }

	Write-Host "PSReadLineOption`n----------------"
	Write-Host "The PSVersion is: $VersionNumber"
	$predictionComand = "Set-PSReadLineOption -PredictionViewStyle $modeName"
	if ($option) {
		
		Write-Host "Setting the [$modeName] mode to Enabled."
		Invoke-Expression $predictionComand
	}
	else {
		Write-Host "The [$modeName] mode has already been Enabled."
	}
	Write-Host ""

	return $predictionComand
}

# Function: Creacion de archivo si no existe
function Test_FilePath {
	param (
		[string]$pathFile
	)

	$fileInfo = Get-ChildItem $pathFile

	Write-Host "Profile Shell`n-------------"
	if (!(Test-Path -Path $pathFile)) {
		"[*] Current File not found, Creating...   : $($fileInfo.Name)"
		
		New-Item -Path $pathFile -Type File -Force
		"+- Message ------------------------------+"
		"|      A new file has been created!      |"
		"+----------------------------------------+"
	} 
	else {
		"[-] Current File found, Already Exists    : $($fileInfo.Name)"

		$fileInfo
		"+- Message ------------------------------+"
		"|    A new file has not been created!    |"
		"+----------------------------------------+"
	}
	Write-Host ""
}

function Test_FileContent {
	param (
		[string]$filePath,
		[string]$valueToCompare,
		[string]$valueToAdd
	)
	# Lee el contenido del archivo de perfil en una variable
	$fileContent = Get-Content -Path $filePath -Raw
	# Reduce el comando de ejecucion a un Alias
	$addContent = { Add-Content -Path $filePath -Value $args[0] }

	if (!($fileContent -match [regex]::escape($valueToCompare))) {

		Write-Host "String not found, Adding" -ForegroundColor Yellow
		& $addContent $valueToAdd
	}
}

# MyTheme 7.5: Agregar el contenido de configuración al perfil
function Custom_Shell_Pwsh () {

	$activatePrompt = Install_Prompt_Terminal "kushal"
	$iconsComand = Install_Module_Terminal
	$predictionComand = Enable_ListView_Terminal

	Test_FilePath $PROFILE
	
	#************************************************************************
	
	$fileInfo = Get-ChildItem $PROFILE
	Write-Host "[*] Current File found, Adding Content... : $($fileInfo.Name)"

	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test_FileContent $PROFILE $stringReduce $activatePrompt

	Test_FileContent $PROFILE $iconsComand $iconsComand

	Test_FileContent $PROFILE $predictionComand $predictionComand

	Write-Host "`n$(Get-Content -Path $PROFILE -Raw)" -ForegroundColor Cyan -NoNewline
	Write-Host "+- Message ------------------------------+"
	Write-Host "|   The content was added to the file!   |"
	Write-Host "+----------------------------------------+`n"
}

function Custom_Shell_Powershell () {
	
	$activatePrompt = Install_Prompt_Terminal "kali"

	$PROFILE_TEMP = "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
	Test_FilePath $PROFILE_TEMP
	
	#************************************************************************
	
	$fileInfo = Get-ChildItem $PROFILE_TEMP
	Write-Host "[*] Current File found, Adding Content... : $($fileInfo.Name)"

	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test_FileContent $PROFILE_TEMP $stringReduce $activatePrompt

	Write-Host "`n$(Get-Content -Path $PROFILE_TEMP -Raw)" -ForegroundColor Cyan -NoNewline
	Write-Host "+- Message ------------------------------+"
	Write-Host "|   The content was added to the file!   |"
	Write-Host "+----------------------------------------+`n"
}

function Install_Prompt_Shell {
	param (
		[string]$themeName
	)

	Write-Host "App Clink`n---------"
	# Instalar Clink en la terminal
	InstallApp "chrisant996.Clink" winget          # (clink set clink.logo none)
	Write-Host ""

	Write-Host "Prompt Oh-My-Posh`n-----------------"
	# Instalar Oh-My-Posh en la terminal
	InstallApp "JanDeDobbeleer.OhMyPosh" winget
	Write-Host ""

	# $themeName = Get-PoshTheme
	$initPrompt = 'oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\' + $themeName + '.omp.json"'
	$null = Invoke-Expression $initPrompt

	# Iniciar Oh-My-Posh en la terminal
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Initializing...`n$initPrompt`n"

	$env:POSH_THEMES_PATH_TEMP = $env:POSH_THEMES_PATH -replace '\\', '/'
	# $themeName = 'stelbent.minimal'
	$loadPrompt = "load(io.popen('oh-my-posh.exe --config=`"$env:POSH_THEMES_PATH_TEMP/$themeName.omp.json`" --init --shell cmd'):read(`"*a`"))()"

	# Cargar Oh-My-Posh en la terminal
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Loading Config...`n$loadPrompt`n"

	return $loadPrompt
}

function Custom_Shell_Cmd () {

	$addComment = "-- oh-my-posh.lua"
	$loadPrompt = Install_Prompt_Shell "stelbent.minimal"

	$CONFIG = "$env:LOCALAPPDATA\clink\oh-my-posh.lua"
	Test_FilePath $CONFIG
	
	#************************************************************************
	
	$fileInfo = Get-ChildItem $CONFIG
	Write-Host "[*] Current File found, Adding Content... : $($fileInfo.Name)"

	Test_FileContent $CONFIG $addComment $addComment

	Test_FileContent $CONFIG $loadPrompt $loadPrompt

	Write-Host "`n$(Get-Content -Path $CONFIG -Raw)" -ForegroundColor Cyan -NoNewline
	Write-Host "+- Message ------------------------------+"
	Write-Host "|   The content was added to the file!   |"
	Write-Host "+----------------------------------------+`n"
}

#****************************************************
#	PRINT_MENUS
#****************************************************

# drawing SubMenu1
function Show-SubMenu1 {
	Write-Host 
	"╔════════════════════════════╗"
	"║          SUB-MENU          ║"
	"╠════════════════════════════╣"
	"║ [1] Set Options            ║"
	"║ [2] Set Services           ║"
	"║ [3] Set ScheduledTasks     ║"
	"║ [4] Set OptionalFeatures   ║"
	"║ [5] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu2
function Show-SubMenu2 {
	Write-Host 
	"╔════════════════════════════╗"
	"║          SUB-MENU          ║"
	"╠════════════════════════════╣"
	"║ [1] Privacy & Security     ║"
	"║ [2] WindowsUpdate Behavior ║"
	"║ [3] Performance Mode       ║"
	"║ [4] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu3
function Show-SubMenu3 {
	Write-Host 
	"╔════════════════════════════╗"
	"║          SUB-MENU          ║"
	"╠════════════════════════════╣"
	"║ [1] Remove AppxUser        ║"
	"║ [2] Remove AppxProvisioned ║"
	"║ [3] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu4
function Show-SubMenu4 {
	Write-Host 
	"╔════════════════════════════╗"
	"║          SUB-MENU          ║"
	"╠════════════════════════════╣"
	"║ [1] Install App            ║"
	"║ [2] Download Tool          ║"
	"║ [3] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu4
function Show-SubMenu5 {
	Write-Host 
	"╔════════════════════════════╗"
	"║          SUB-MENU          ║"
	"╠════════════════════════════╣"
	"║ [1] Customize pwsh         ║"
	"║ [2] Customize powershell   ║"
	"║ [3] Customize cmd          ║"
	"║ [4] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing MainMenu
function Show-MainMenu {
	Write-Host 
	"         $WPName $WPVersion          "
	"╔════════════════════════════════╗"
	"║           MAIN-MENU            ║"
	"╠════════════════════════════════╣"
	"║ [1] Set Preferences            ║"
	"║ [2] Essential Tweaks           ║"
	"║ [3] Remove Bloatware           ║"
	"║ [4] Add Apps/Tools             ║"
   #"║ ![5] Customize PowerPlan        ║"
	"║ [5] Customize Terminal         ║"
	"║ [6] Exit                       ║"
	"╚════════════════════════════════╝"
}

#****************************************************
#	MENU_OPTIONS
#****************************************************

# call option SubMenu1
function Invoke-SubMenu1 () {

	Show-SubMenu1
	$optionMenu1 = Read-Host "Choose an option_1"
	
	switch ($optionMenu1) {
		1 {
			Clear-Host
			Write-Host "Set Options"
			Write-Host "Do you want to change the state?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Set_Default_Option
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		2 {
			Clear-Host
			Write-Host "Set Services"
			Write-Host "Do you want to change the state?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Set_Service_Startup
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		3 {
			Clear-Host
			Write-Host "Set ScheduledTasks"
			Write-Host "Do you want to change the state?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Set_Scheduled_Task
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		4 {
			Clear-Host
			Write-Host "Set OptionalFeatures"
			Write-Host "Do you want to change the state?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Set_Optional_Feature
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		5 {
			Clear-Host
			Invoke-MainMenu
			break
		}
		Default {
			do {
				Clear-Host
				Write-Warning "Error_1. Unknown value!"
				break
			} while ( $optionMenu1 -lt 1 -or $optionMenu1 -gt 5 )
			Invoke-SubMenu1
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-SubMenu1
}

# call option SubMenu2
function Invoke-SubMenu2 () {
	
	Show-SubMenu2
	$optionMenu2 = Read-Host "Choose an option_2"

	switch ($optionMenu2) {
		1 {
			Clear-Host
			Write-Host "Set Privacy"
			Write-Host "Do you want disable Web results, Cortana results, Diagnoctics data, Activity history?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Set_Privacy_Security
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		2 {
			Clear-Host
			Write-Host "Set Windows Update Behavior"
			Write-Host "Do you want enable Manual Update, disable Preliminary Updates & Product Updates?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Set_Update_Behavior
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		3 {
			Clear-Host
			Write-Host "Set Performance Mode"
			Write-Host "Do you want enable the TRIM, MemoryCompression, Minimum VisualEffects. Change the CPU usage for Windows Defender?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Set_Performance_Mode
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		4 {
			Clear-Host
			Invoke-MainMenu
			break
		}
		Default {
			do {
				Clear-Host
				Write-Warning "Error_2. Unknown value!"
				break
			} while ( $optionMenu2 -lt 1 -or $optionMenu2 -gt 4 )
			Invoke-SubMenu2
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-SubMenu2
}

# call option SubMenu3
function Invoke-SubMenu3 () {
	
	Show-SubMenu3
	$optionMenu3 = Read-Host "Choose an option_3"

	switch ($optionMenu3) {
		1 {
			Clear-Host
			Write-Host "Remove AppxUserPackages"
			Write-Host "Do you want to remove Appx from the current user account?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Remove_User_Appx
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		2 {
			Clear-Host
			Write-Host "Remove AppxProvisionedPackages"
			Write-Host "Do you want to remove Appx from Windows image?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Remove_Provisioned_Appx
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		3 {
			Clear-Host
			Invoke-MainMenu
			break
		}
		Default {
			do {
				Clear-Host
				Write-Warning "Error_3. Unknown value!"
				break
			} while ( $optionMenu3 -lt 1 -or $optionMenu3 -gt 3 )
			Invoke-SubMenu3
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-SubMenu3
}

# call option SubMenu4
function Invoke-SubMenu4 () {

	Show-SubMenu4
	$optionMenu4 = Read-Host "Choose an option_4"

	switch ($optionMenu4) {
		1 {
			Clear-Host
			Write-Host "Install Apps"
			Write-Host "Do you want to install Apps?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Install_Apps
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		2 {
			Clear-Host
			Write-Host "Download Tools"
			Write-Host "Do you want to download Tools?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Download_Tools
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		3 {
			Clear-Host
			Invoke-MainMenu
			break
		}
		Default {
			do {
				Clear-Host
				Write-Warning "Error_4. Unknown value!"
				break
			} while ( $optionMenu4 -lt 1 -or $optionMenu4 -gt 3 )
			Invoke-SubMenu4
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-SubMenu4
}

function Invoke-SubMenu5 () {

	Show-SubMenu5
	$optionMenu5 = Read-Host "Choose an option_5"

	switch ($optionMenu5) {
		1 {
			Clear-Host
			Write-Host "Customize pwsh"
			Write-Host "Do you want to customize pwsh?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Custom_Shell_Pwsh
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		2 {
			Clear-Host
			Write-Host "Customize powershell"
			Write-Host "Do you want to customize powershell?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Custom_Shell_Powershell
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		3 {
			Clear-Host
			Write-Host "Customize cmd"
			Write-Host "Do you want to customize cmd?"

			$opt = Read-Host "[Y] Yes [N] No"; ""
			if ($opt -eq "y") {
				Custom_Shell_Cmd
			} 
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		4 {
			Clear-Host
			Invoke-MainMenu
			break
		}
		Default {
			do {
				Clear-Host
				Write-Warning "Error_5. Unknown value!"
				break
			} while ( $optionMenu5 -lt 1 -or $optionMenu5 -gt 4 )
			Invoke-SubMenu5
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-SubMenu5
}

# call option MainMenu
function Invoke-MainMenu () {
	
	Show-MainMenu
	$optionMenu = Read-Host "Choose an option"

	switch ($optionMenu) {
		1 {
			Clear-Host
			Invoke-SubMenu1
			Break
		}
		2 {
			Clear-Host
			Invoke-SubMenu2
			Break
		}
		3 {
			Clear-Host
			Test-WinVersion -Operation { Install_Module_Appx } -OSNumber 10;
			Invoke-SubMenu3
			Break
		}
		4 {
			Clear-Host
			Invoke-SubMenu4
			break
		}
		<#
		!5 {
			Clear-Host
			Write-Host "Customize Power Plan"
			Write-Host "Do you want to customize your Power Plan?"

			$opt = Read-Host "[Y] yes [N] No"; ""
			if ($opt -eq "y") {
				"[Set_Power_Plan] En desarrollo... :3`n"
			}
			else {
				Write-Host "Operation cancelled.`n" -ForegroundColor Red
			}
			break
		}
		#>
		5 {
			Clear-Host
			Invoke-SubMenu5
			break
		}
		6 {
			Write-Host "`nExiting the program..."
			Write-Host "Restart your PC now to apply all changes." -ForegroundColor Yellow
			exit
		}
		Default {
			do {
				Clear-Host
				Write-Warning "Error. Unknown value!"
				break
			} while ( $optionMenu -lt 1 -or $optionMenu -gt 6 )
			Invoke-MainMenu
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-MainMenu
}

#****************************************************
#	MAIN_FUNCTION
#****************************************************

function Get-CommandType {
	param (
		[string]$scriptPath
	)

	if ($scriptPath -match "^C:\.*") {
			
		Write-Host " -Ejecutando Archivo_Local"
		return "-File `"$scriptPath`""
	} 
	else {
		
		Write-Host " -Ejecutando Archivo_Remoto"
		return "-Command `"irm $repositoryPath | iex`""
	}
}

# Test Rol Admin
function Test-CurrentRol {
	$userCurrent = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	$roleCurrent = ([Security.Principal.WindowsBuiltInRole] "Administrator")
	
	$adminCondition = $userCurrent.IsInRole($roleCurrent)
	if (!$adminCondition) {

		Write-Host " -The script requires to run as Administrator" -ForegroundColor Yellow

		$scriptPath = $PSCommandPath
		$command = Get-CommandType $scriptPath
		Write-Host " -Type Argument -> {$command}"
		
		Start-Process -FilePath "wt.exe" -ArgumentList "pwsh $command" -Verb RunAs
		Start-Sleep -Milliseconds 3000
		exit
	}
}

# Test Winget
function Test-WingetVersion {
	try {

		$wingetCondition = winget --version
	} 
	catch {

		Write-Host "Error: $_" -ForegroundColor Red
		$packageFile = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
		$packageUrl = "https://github.com/microsoft/winget-cli/releases/download/v1.7.11261/$packageFile"
		
		if (!$wingetCondition) {

			Write-Host " -Installing the package manager Winget" -ForegroundColor Yellow
			Invoke-WebRequest -Uri $packageUrl -OutFile $packageFile
			Add-AppxPackage -Path $packageFile
		}
	}
}

# Test Choco
function Test-ChocoVersion {
	try {

		$chocoCondition = choco --version
	} 
	catch {

		Write-Host "Error: $_" -ForegroundColor Red
		$chocoPackage = "Chocolatey.Chocolatey"

		if (!$chocoCondition) {

			Write-Host " -Installing the package manager Chocolatey" -ForegroundColor Yellow
			InstallApp $chocoPackage winget
		}
	}
}

# Test Choco Feature
function Test-ChocoFeature {
	$featureList = choco feature list
	$featureCurrent = "\[x\] allowGlobalConfirmation"
	
	$featureCondition = $featureList -match $featureCurrent
	if (!$featureCondition) {

		Write-Host " -Enabling feature allowGlobalConfirmation" -ForegroundColor Yellow
		choco feature enable -n allowGlobalConfirmation
	}
}

Clear-Host
$Host.UI.RawUI.WindowTitle = "Dead Script [ x__x ]"

# Checking if Rol is Administrator
Write-Host "Checking if Rol is Administrator..."
Test-CurrentRol

# Checking if Winget is installed
Write-Host "Checking if PM Winget is Installed..."
Test-WingetVersion

# Checking if Chocolatey is installed
Write-Host "Checking if PM Chocolatey is Installed..."
Test-ChocoVersion

# Checking if allowGlobalConfirmation is Enabled
Write-Host "Checking if allowGlobalConfirmation is Enabled..."
Test-ChocoFeature

#"Invoke the Main Menu the Script."
Invoke-MainMenu

# Sleep for 2 seconds
Start-Sleep -Milliseconds 3000

# Policy Execution Restart
#Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser
#Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope Process
