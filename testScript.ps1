
# Policy Execution Enable
#Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope "Process" -Force
#Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope "CurrentUser" -Force

#****************************************************
#	ABOUT_SCRIPT
#****************************************************

# Show script info
$WPName = "WinPerf (Preview)"
$WPVersion = "v1.50.5"
$repositoryPath = "https://raw.githubusercontent.com/DiegoEli/test-script/test-(preview)/testScript.ps1"
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

# function Set Option Status
function Set_OptionStatus {
	param (
		[string]$path,
		[string]$property,
		[string]$value
	)

	$currentValue = (Get-ItemProperty -Path $path).$property

	if ($currentValue -ne $value) {

		"Setting value [$property], Changing..."
		Set-ItemProperty -Path $path -Name $property -Value $value -Force
	} 
	else {
		"Value [$property] remains Changed"
	}
}

<# function Deprecated
#Mensaje de confirmacion global
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
#>
function Add-AppSelection ($valueName) {

	$opt = Read-Host "[Y] Yes [N] No";

	if ($opt -eq "y") {
		Write-Host "Add selection to List!"
		return $valueName
	} 
	elseif ($opt -eq "n") {
		Write-Host "Operation cancelled." -ForegroundColor Red
		return $null
	} 
	else {
		Add-AppSelection $valueName
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
function Remove_GalleryIcon {
	$pathFolder = 'HKCU:\Software\Classes\CLSID'
	$item = '{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}'

	Test_Item $pathFolder $item

	$pathProperty = "HKCU:\Software\Classes\CLSID\$item"
	$property = 'System.IsPinnedToNamespaceTree'
	$value = 0

	Test_Property $pathProperty $property
	
	# Change value option
	Set_OptionStatus $pathProperty $property $value
}

# Modification 1.1: Show CortanaResults in Windows Search
function Disable_CortanaResults {
	$pathFolder = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Windows Search'

	Test_Item $pathFolder $item

	$pathProperty = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property = 'AllowCortana'
	$value = 0

	Test_Property $pathProperty $property

	# Change value option
	Set_OptionStatus $pathProperty $property $value
}

# Modification 1.2: Show WebResults in Windows Search
function Disable_WebResults {
	$pathWebResults = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
	$property1 = 'BingSearchEnabled'
	$property2 = 'CortanaConsent'
	$value = 0

	Test_Property $pathWebResults $property1
	Test_Property $pathWebResults $property2

	# Change value option
	Set_OptionStatus $pathWebResults $property1 $value
	Set_OptionStatus $pathWebResults $property2 $value
}

function Disable_PersonalizeAds {
	$pathFolder = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'AdvertisingInfo'

	Test_Item $pathFolder $item

	$pathProperty = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property = 'DisabledByGroupPolicy'
	$value = 1

	Test_Property $pathProperty $property

	# Change value option
	Set_OptionStatus $pathProperty $property $value
}

# Modification 1.3: DiagnosticData
function Disable_DiagnosticData {
	$pathTelemetry1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
	$pathTelemetry2 = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
	$property = 'AllowTelemetry'
	$value = 0

	Test_Property $pathTelemetry2 $property

	# Change value option
	Set_OptionStatus $pathTelemetry1 $property $value
	Set_OptionStatus $pathTelemetry2 $property $value
}

# Modification
function Disable_ActivityHistory {
	$pathActivityHistory = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
	$property1 = 'EnableActivityFeed'
	$property2 = 'PublishUserActivities'
	$property3 = 'UploadUserActivities'
	$value = 0
	
	Test_Property $pathActivityHistory $property1
	Test_Property $pathActivityHistory $property2
	Test_Property $pathActivityHistory $property3

	# Change value option
	Set_OptionStatus $pathActivityHistory $property1 $value
	Set_OptionStatus $pathActivityHistory $property2 $value
	Set_OptionStatus $pathActivityHistory $property3 $value
}

$privacyFnList = [ordered]@{
	"Remove Gallery Folder"    = "Remove_GalleryIcon"
	"Disable Cortana Results"  = "Disable_CortanaResults"
	"Disable Web Results"      = "Disable_WebResults"
	"Disable Personalize Ads"  = "Disable_PersonalizeAds"
	"Disable Diagnostic Data"  = "Disable_DiagnosticData"
	"Disable Activity History" = "Disable_ActivityHistory"
}

function Set_Privacy_Security () {

	$ListToChanged = @()
	foreach ($privacyFn in $privacyFnList.Keys) {

		Write-Host "Do you want to Apply [" -NoNewline
		Write-Host $privacyFn -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $privacyFnList[$privacyFn]
		if ($selectedApp) {
			$ListToChanged += $selectedApp
		}
		Write-Host ""
	}
	
	"*******************************"
	"SETTING SELECTED PRIVACY TWEAKS"
	"*******************************"
	foreach ($operation in $ListToChanged) {
		& $operation
	}
	Write-Host ""
}

# Modification 1.4: Update Type in Windows
function Set_UpdateType {
	$pathFolder = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item1 = 'WindowsUpdate'
	$pathSubFolder = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item1"
	$item2 = 'AU'
	
	Test_Item $pathFolder $item1
	Test_Item $pathSubFolder $item2
	
	$pathUpdateType = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item1\$item2"
	$property1 = 'AUOptions'
	$property2 = 'NoAutoUpdate'
	$valueAUO = 2 #$valueAUO = 2 ; status = Notificar
	$valueNAU = 1 #$valueNAU = 1 ; status = Disabled

	Test_Property $pathUpdateType $property1
	Test_Property $pathUpdateType $property2

	# Change value option
	Set_OptionStatus $pathUpdateType $property1 $valueAUO
	Set_OptionStatus $pathUpdateType $property2 $valueNAU
}

# Modification
function Set_PreliminaryUpdates {
	$pathPreliminary = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	$property = 'ManagePreviewBuildsPolicyValue'
	$value = 1

	Test_Property $pathPreliminary $property

	# Change value option
	Set_OptionStatus $pathPreliminary $property $value
}

function Set_GetLatestUpdates {
	$latestUpdatesPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property = 'IsContinuousInnovationOptedIn'
	$value = 0

	# Change value option
	Set_OptionStatus $latestUpdatesPath $property $value
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
	$value = 0

	# Change value option
	Set_OptionStatus $pathDownloadsPC $property $value
}

# Modification
function Set_LimitBandwidthUpdates {
	$folderPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Psched'

	Test_Item $folderPath $item

	$bandwidthPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property = 'NonBestEffortLimit'
	$value = 0

	Test_Property $bandwidthPath $property

	# Change value option
	Set_OptionStatus $bandwidthPath $property $value
}

$updateFnList = [ordered]@{
	"Automatic Updates"          = "Set_UpdateType"
	"Preliminary Updates"        = "Set_PreliminaryUpdates"
	"Get the latest Updates"     = "Set_GetLatestUpdates"
	"Updates for other products" = "Set_UpdateOtherProduct"
	"Downloads from other PCs"   = "Set_DownloadsOtherPCs"
	"Limit reservable bandwidth" = "Set_LimitBandwidthUpdates"
}

function Set_Update_Behavior () {

	$ListToChanged = @()
	foreach ($updateFn in $updateFnList.Keys) {

		Write-Host "Do you want to Disable [" -NoNewline
		Write-Host $updateFn -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $updateFnList[$updateFn]
		if ($selectedApp) {
			$ListToChanged += $selectedApp
		}
		Write-Host ""
	}

	"********************************"
	"SETTING SELECTED UPDATE BEHAVIOR"
	"********************************"
	foreach ($operation in $ListToChanged) {
		& $operation
	}
	Write-Host ""
}

<# function Deprecated
# Test Status Color
function Test_StatusColor {
	param (
		[string]$status
	)
	$color = ($status -eq '[OFF]') ? $('Red') : $('Cyan')
	Write-Host $status -ForegroundColor $color
}
#>

# Modification 2.1: Configure netplwiz in Windows
function Opt_Netplwiz {
	$pathNetplwiz = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
	$property = 'DevicePasswordLessBuildVersion'
	$value = 0
	
	Write-Host "[+] Netplwiz                  "
	#"Netplwiz has been Enabled"
	Set_OptionStatus $pathNetplwiz $property $value
}

# Modification 2.2: Configure fastStartup in Windows
function Opt_FastStartup {
	$pathFastStartup = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
	$property = 'HiberbootEnabled'
	$value = 0

	Write-Host "[+] Fast Startup              "
	#"FastStartup has been Disabled"
	Set_OptionStatus $pathFastStartup $property $value
}

# Modification 1: StorageSense in Windows(revisar si existe)
function Opt_StorageSense {
	$pathStorageSense = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
	$property = '01'
	$value = 0

	Write-Host "[+] Storage Sense             "
	#"StorageSense has been Disabled"
	Set_OptionStatus $pathStorageSense $property $value
}

# Modification 1: Snap in Windows
function Opt_SnapSuggest {
	$pathSnapSuggest = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'SnapAssist'
	$value = 0

	Write-Host "[+] Suggest Next Snap         "
	#"SnapSuggest has been Disabled"
	Set_OptionStatus $pathSnapSuggest $property $value
}

# Modification 1: Show file extensions
function Opt_ShowFileExtensions {
	$pathFileExt = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'HideFileExt'
	$value = 0

	Write-Host "[+] Show File Extensions      "
	#"Show FileExtensions has been Enabled"
	Set_OptionStatus $pathFileExt $property $value
}

# Modification: Show hidden files and folders
function Opt_ShowHiddenFiFo {
	$pathHiddenFiFo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'Hidden'
	$value = 1

	Write-Host "[+] Show Hidden FilesFolders  "
	#"Show HiddenFilesFolders has been Enabled"
	Set_OptionStatus $pathHiddenFiFo $property $value
}

# Modification
function Opt_ShowSyncProvider {
	$pathSyncProvider = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSyncProviderNotifications'
	$value = 0

	Write-Host "[+] Show Sync Provider        "
	#"Show SyncProvider has been Disabled"
	Set_OptionStatus $pathSyncProvider $property $value
}

# Modification 2.0: End Task in Windows
function Opt_ShowEndTask {
	$pathEndTask = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'
	$property = 'TaskbarEndTask'
	$value = 1

	Write-Host "[+] Enable End Task           "
	#"Show EndTask has been Enabled"
	Set_OptionStatus $pathEndTask $property $value
}

# Modification 0: Command Sudo in Windows
function Opt_SudoCommand {
	$sudoCommandPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
	$property = 'Enabled'
	$value = 3

	Write-Host "[+] Enable Sudo Command       "
	# Option change value
	Set_OptionStatus $sudoCommandPath $property $value
}

# Modification 0: Verificar el modo oscuro
function Opt_DarkMode {
	$pathDarkModeAll = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property1 = 'AppsUseLightTheme'
	$property2 = 'SystemUsesLightTheme'
	$value = 0
	
	Write-Host "[+] Dark Mode                 "
	# "ThemeDark Apps has been Enabled"
	Set_OptionStatus $pathDarkModeAll $property1 $value
	# "ThemeDark System has been Enabled"
	Set_OptionStatus $pathDarkModeAll $property2 $value
}

# Modification: Get fun facts, tips, tricks...
function Opt_GetTipsTricks {
	$pathTipsTricks = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$property1 = 'RotatingLockScreenOverlayEnabled'
	$property2 = 'SubscribedContent-338387Enabled'
	$value = 0
	
	Write-Host "[+] Get Facts, Tips, Tricks   "
	#"Facts, Tips & Tricks has been Disabled"
	Set_OptionStatus $pathTipsTricks $property1 $value
	#"Facts, Tips & Tricks has been Disabled"
	Set_OptionStatus $pathTipsTricks $property2 $value
}

# Modification: Show the lock ...
function Opt_ShowSignInScreen {
	$pathSignInScreen = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-1-5-21-3918609171-3129487852-610721345-1001\AnyoneRead\LockScreen'
	$property = 'HideLogonBackgroundImage'
	$value = 0

	Write-Host "[+] Show Sign-In Screen       "
	#"ShowSignInScreen has been Enabled"
	Set_OptionStatus $pathSignInScreen $property $value
}

# Modification
function Opt_ShowItemSearch {
	$pathItemSearch = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
	$property = 'SearchboxTaskbarMode'
	$value = 0

	Write-Host "[+] Show Item Search          "
	#"Show Item Search has been Disabled"
	Set_OptionStatus $pathItemSearch $property $value
}

# Modification
function Opt_ShowItemTaskView {
	$pathItemTaskView = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowTaskViewButton'
	$value = 0
	
	Write-Host "[+] Show Item TaskView        "
	#"Show Item TaskView has been Disabled"
	Set_OptionStatus $pathItemTaskView $property $value
}

# Modification 2.0: Hide Taskbar in Windows
function Opt_HideTaskbar {
	$pathHideTaskbar = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
	$property = 'Settings'
	$hideTaskbar = (Get-ItemProperty -Path $pathHideTaskbar).$property
	$value = 0x7A

	Write-Host "[+] Hide Taskbar              "
	#"HideTaskbar has been Disabled"
	if ($hideTaskbar[8] -ne $value) {

		$hideTaskbar[8] = $value
		"Option [$property] has been Changing..."
		Set-ItemProperty -Path $pathHideTaskbar -Name $property -Value $hideTaskbar -Force
	}
	else {
		"Option [$property] remains Changed"
	}
}

function Opt_ShowDesktop {
	$pathDesktop = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'TaskbarSd'
	$value = 1

	Write-Host "[+] Option Show the Desktop   "
	#"ShowDesktop has been Enabled"
	Set_OptionStatus $pathDesktop $property $value
}

# Modification 2.0: ShowSeconds in SystemClock
function Opt_ShowSeconds {
	$pathSecondsClock = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSecondsInSystemClock'
	$value = 1

	Test_Property $pathSecondsClock $property

	Write-Host "[+] Show Seconds in Clock     "
	#"ShowSeconds has been Enabled"
	Set_OptionStatus $pathSecondsClock $property $value
}

# Modification 0: Game Bar in Windows
function Opt_GameBar {
	$pathGameBar = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'UseNexusForGameBarEnabled'
	$value = 0

	Write-Host "[+] Game Bar                  "
	#"GameBar has been Disabled"
	Set_OptionStatus $pathGameBar $property $value
}

# Modification 0: Game Mode in Windows
function Opt_GameMode {
	$pathGameMode = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'AutoGameModeEnabled'
	$value = 0

	Write-Host "[+] Game Mode                 "
	#"GameMode has been Disabled"
	Set_OptionStatus $pathGameMode $property $value
}

# Modification 0:
function Opt_TransparencyEffects {
	$pathTransparency = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property = 'EnableTransparency'
	$value = 0

	Write-Host "[+] Transparency Effects      "
	# "Transparency has been Disabled"
	Set_OptionStatus $pathTransparency $property $value
}

# Modification
function Opt_AlwaysShowScrollbars {
	$pathShowScrollbars = 'HKCU:\Control Panel\Accessibility'
	$property = 'DynamicScrollbars'
	$value = 0

	Write-Host "[+] Always Show Scrollbars    "
	#"ShowScrollbars has been Enabled"
	Set_OptionStatus $pathShowScrollbars $property $value
	Write-Host ""
}

# Disables Bitlocker Auto Encryption on Windows(REVISAR)
function Opt_DeviceEncryption {
	$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
	$path2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices'
	$property1 = 'PreventDeviceEncryption'
	$property2 = 'TCGSecurityActivationDisabled'
	$value = 1
	
	Test_Property $path1 $property1

	#"Bitlocker has been Disabled"
	Set_OptionStatus $path1 $property1 $value
	Set_OptionStatus $path2 $property2 $value
}

function Set_Default_Option () {

	"***************************"
	"SETTING SELECTED PREFERENCE"
	"***************************"
	Opt_Netplwiz
	Opt_FastStartup
	Opt_StorageSense
	# Opt_DeviceEncryption
	Opt_SnapSuggest
	Opt_ShowFileExtensions
	Opt_ShowHiddenFiFo
	Opt_ShowSyncProvider
	Opt_ShowEndTask
	# Opt_SudoCommand
	Opt_DarkMode
	Opt_TransparencyEffects
	Opt_GetTipsTricks
	Opt_ShowSignInScreen
	Opt_ShowItemSearch
	Opt_ShowItemTaskView
	Opt_HideTaskbar
	Opt_ShowDesktop
	Opt_ShowSeconds
	Opt_GameBar
	Opt_GameMode
	Opt_AlwaysShowScrollbars
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
	
	$Cmd1 = "Set-Service -Name `"$serviceName`" -StartupType $startupType"
	$Cmd2 = "Stop-Service -Name `"$serviceName`""
	if ($service) {
		
		Write-Host "[*] Setting service [$serviceName] to $startupType."
		Write-Host "[*] Stopping service [$serviceName]." -NoNewline
		InfoService $service $serviceName | Format-List
		
		Invoke-Expression $Cmd1
		Invoke-Expression $Cmd2
	} 
	else {
		Write-Host "[-] Error setting service [$serviceName] to $startupType, Service not found."
		Write-Host "[-] Error stopping service [$serviceName], Service not found." -NoNewline
		InfoService $service $serviceName | Format-List
		# "Cannot find path 'HKCU:\Software\Microsoft' because it does not exist."
	}
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
	
	$newState = $stateType.Substring(0, $stateType.Length - 1)
	$Cmd = "$newState-ScheduledTask -TaskPath `"$taskPath`" -TaskName `"$taskName`""
	if ($task) {
		
		Write-Host "[*] Setting task [$taskName] to $stateType." -NoNewline
		InfoTask $task $taskName | Format-List

		$null = Invoke-Expression $Cmd
	}
	else {
		Write-Host "[-] Error setting task [$taskName] to $stateType, Task not found." -NoNewline
		InfoTask $task $taskName | Format-List
		# "Cannot find path 'HKCU:\Software\Microsoftkkkk' because it does not exist."
	}
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
		Name = "MareBackup"
	},
	@{ 
		Path = "\Microsoft\Windows\Application Experience\"
		Name = "Microsoft Compatibility Appraiser"
	},
	@{
		Path = "\Microsoft\Windows\Application Experience\"
		Name = "PcaPatchDbTask"
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
		Path = "\Microsoft\Windows\DiskDiagnostic\"
		Name = "Microsoft-Windows-DiskDiagnosticDataCollector"
	},
	@{
		Path = "\Microsoft\Windows\Feedback\Siuf\"
		Name = "DmClient"
	},
	@{
		Path = "\Microsoft\Windows\Feedback\Siuf\"
		Name = "DmClientOnScenarioDownload"
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

	if ($appx) {
		
		Write-Host "Removing userAppx [$appxName] from the current user account." -NoNewline
		$appx | Format-List Name, Version, Architecture, ResourceId, PackageFullName, Status

		"$($appx.PackageFullName)" | Remove-AppxPackage
	} 
	else {
		Write-Host "Error removing userAppx [$appxName], Appx not found."
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
    "Microsoft Edge"          = "Microsoft.MicrosoftEdge.Stable"        #QUITARLO ROMPE COSAS
	"Microsoft Edge Tools"    = "Microsoft.MicrosoftEdgeDevToolsClient"
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
	# "Spotlight"               = "MicrosoftWindows.LKG.DesktopSpotlight" #REVISAR
	"Microsoft Teams"         = "MSTeams"
    "Spotify Music"           = "SpotifyAB.SpotifyMusic"

    #"linkedin"               = "linkedin_searchId"                       #BUSCAR ID COMPLETO
    #"Camo Studio"            = "CamoStudio_searchId"                     #BUSCAR ID COMPLETO
}

function Remove_User_Appx () {

	Write-Host "REMOVE USER APPX`n----------------"
	$ListToRemoveU = @()
	foreach ($appx in $userPackageList.Keys) {

		Write-Host "Remove AppxUser [" -NoNewline
		Write-Host $appx -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $userPackageList[$appx]
		if ($selectedApp) {
			$ListToRemoveU += $selectedApp
		}
		Write-Host ""
	}

	"****************************"
	"REMOVING SELECTED APPXS USER"
	"****************************"
	foreach ($appxId in $ListToRemoveU) {
		RemoveUserAppx $appxId
	}
	Write-Host ""
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

	if ($appx) {
		
		Write-Host "Removing provisionedAppx [$appxName] from Windows image." -NoNewline
		$appx | Format-List

		$null = DISM /Online /Remove-ProvisionedAppxPackage /PackageName:"$($appx.PackageName)"
		# "$($appx.PackageName)" | Remove-AppxProvisionedPackage -Online
	} 
	else {
		Write-Host "Error removing provisionedAppx [$appxName], Appx not found."
	}
}

# Uninstall 5.0: Blotware in Windows
#DISM /Online /Get-ProvisionedAppxPackages | select-string Packagename
$provPackageList = [ordered]@{
	"Microsoft Clipchamp"     = "Clipchamp.Clipchamp"
    "Cortana"                 = "Microsoft.549981C3F5F10"
    "Microsoft News"          = "Microsoft.BingNews"
	"Bing Search (Edge)"      = "Microsoft.BingSearch"
    "MSN Weather"             = "Microsoft.BingWeather"
    "Xbox App"                = "Microsoft.GamingApp"
    "Get Help"                = "Microsoft.GetHelp"
    "Get Started"             = "Microsoft.Getstarted"
	"HEIF Image Extension"    = "Microsoft.HEIFImageExtension"
	"HEVC Video Extension"    = "Microsoft.HEVCVideoExtension"
	"Paint 3D"                = "Microsoft.Microsoft3DViewer"
    "Microsoft Edge"          = "Microsoft.MicrosoftEdge.Stable"         #QUITARLO ROMPE COSAS
	"Microsoft Edge Tools"    = "Microsoft.MicrosoftEdgeDevToolsClient"
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
	"Windows Meet Now (Icon)" = "Microsoft.WindowsMeetNow"
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
	"Microsoft Teams"         = "MSTeams"

    #"linkedin"               = "linkedin_searchId"                       #BUSCAR ID COMPLETO
    #"Camo Studio"            = "CamoStudio_searchId"                     #BUSCAR ID COMPLETO
}

function Remove_Provisioned_Appx () {

	Write-Host "REMOVE PROVISIONED APPX`n-----------------------"
	$ListToRemoveP = @()
	foreach ($appx in $provPackageList.Keys) {

		Write-Host "Remove AppxProvisioned [" -NoNewline
		Write-Host $appx -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $provPackageList[$appx]
		if ($selectedApp) {
			$ListToRemoveP += $selectedApp
		}
		Write-Host ""
	}

	"***********************************"
	"REMOVING SELECTED APPXS PROVISIONED"
	"***********************************"
	foreach ($appxId in $ListToRemoveP) {
		RemoveProAppx $appxId
	}
	Write-Host ""
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
	
	$newState = $stateType.Substring(0, $stateType.Length - 1)
	$actionCmd = "$newState-WindowsOptionalFeature -FeatureName `"$featureName`" -Online"
	if ($feature) {
		
		Write-Host "Setting feature [$featureName] to $stateType." -NoNewline
		InfoFeature $feature $featureName | Format-List

		$null = Invoke-Expression $actionCmd
	} 
	else {
		Write-Host "Error setting feature [$featureName] to $stateType, Feature not found."
		# "Cannot find path 'HKCU:\Software\Microsoft' because it does not exist."
	}
}

$featureDisList = [ordered]@{
	"Internet Explorer 11" = "Internet-Explorer-Optional-amd64"
	"Media Features"       = "MediaPlayback"
	"Windows Media Player" = "WindowsMediaPlayer"
}

$featureEnaList = [ordered]@{
	".NET Framework 3.5" = "NetFx3"
	"Windows Sandbox"    = "Containers-DisposableClientVM"
}

# Features 5.3: Turn on/off
function Set_Optional_Feature () {

	Write-Host "SET OPTIONAL FEATURES`n---------------------"
	$ListToDisable = @()
	foreach ($feature in $featureDisList.Keys) {
		
		Write-Host "Disable Feature [" -NoNewline
		Write-Host $feature -ForegroundColor Cyan -NoNewline; "]?"

		$selectedFeature = Add-AppSelection $featureDisList[$feature]
		if ($selectedFeature) {
			$ListToDisable += $selectedFeature
		}
		Write-Host ""
	}

	$ListToEnable = @()
	foreach ($feature in $featureEnaList.Keys) {
		
		Write-Host "Enbale Feature [" -NoNewline
		Write-Host $feature -ForegroundColor Cyan -NoNewline; "]?"

		$selectedFeature = Add-AppSelection $featureEnaList[$feature]
		if ($selectedFeature) {
			$ListToEnable += $selectedFeature
		}
		Write-Host ""
	}
	
	"*************************"
	"SETTING SELECTED FEATURES"
	"*************************"
	foreach ($featureId in $ListToDisable) {
		FeatureConfig $featureId Disabled
	}

	foreach ($featureId in $ListToEnable) {
		FeatureConfig $featureId Enabled
	}
	Write-Host ""
}

# Install 6: App list
#function Install App
function InstallApp ($appId, $sourceType) {
	$listCmd = "$sourceType list --id $appId"
	$outputGet = Invoke-Expression $listCmd -ErrorAction SilentlyContinue
	$installed = $outputGet | Where-Object { $_.contains("$appId") }
	
	$installCmd = "$sourceType install --id `"$appId`""  #--accept-source-agreements
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
	"Rust (MSVC)"                 = "Rustlang.Rust.MSVC"                   # (v1.79.0)
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
	# "VMware Workstation Pro"      = "VMware.???"
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
    # "PostgreSQL 16"               = "PostgreSQL.PostgreSQL.16"           # revisar compilacion seteada
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

	Write-Host "INSTALL APP`n-----------"
	$ListToInstallW = @()
	foreach ($app in $wingetList.Keys) {
		
		Write-Host "Install App [" -NoNewline
		Write-Host $app -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $wingetList[$app]
		if ($selectedApp) {
			$ListToInstallW += $selectedApp
		}
		Write-Host ""
	}

	$ListToInstallC = @()
	foreach ($app in $chocoList.Keys) {
		
		Write-Host "Install App [" -NoNewline
		Write-Host $app -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $chocoList[$app]
		if ($selectedApp) {
			$ListToInstallC += $selectedApp
		}
		Write-Host ""
	}
	
	"************************"
	"INSTALLING SELECTED APPS"
	"************************"
	foreach ($appId in $ListToInstallW) {
		InstallApp $appId winget
	}

	foreach ($appId in $ListToInstallC) {
		InstallApp $appId choco
	}
	Write-Host ""
}

function DownloadApp ($toolUrl, $toolFile) {
	$pathLocation = "$HOME\Documents"
	$item = 'APP-PC'# 'APP-TOOLS'
	$filePath = "$pathLocation\$item\$toolFile"
	
	Test_Item $pathLocation $item

	if (!(Test-Path -Path $filePath)) {
		
		Write-Host "Tool [$toolFile] Downloading...`nUrl: " -NoNewline
		Write-Host $toolUrl -ForegroundColor Blue -NoNewline
		Invoke-WebRequest -Uri $toolUrl -OutFile $filePath
		Get-ChildItem $filePath | Select-Object Mode, LastWriteTime, Length, Name | Format-List
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
		TUrl = "https://www.winitor.com/tools/pestudio/current/pestudio-9.59.zip"
		File = "pestudio-9.59.zip"
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
		TUrl = "https://download.cpuid.com/cpu-z/cpu-z_2.10-en.zip"
		File = "cpu-z_2.10-en.zip"
	},
	@{
		Name = "HWMonitor"
		TUrl = "https://download.cpuid.com/hwmonitor/hwmonitor_1.54.zip"
		File = "hwmonitor_1.54.zip"
	},
	@{
		Name = "HWiNFO"
		TUrl = "https://www.sac.sk/download/utildiag/hwi_806.zip"
		File = "hwi_806.zip"
	},
	@{
		Name = "CrystalDiskInfo"
		TUrl = "https://downloads.sourceforge.net/project/crystaldiskinfo/9.3.2/CrystalDiskInfo9_3_2.zip?ts=gAAAAABmxATDiGgHn2taCOQBwlpedDQDGc3qkdVb4nl_wlSmHAeP5yBneUjs08rklYZo14DpHd5AdO5KetJwKGLbAJV0ERxkmQ%3D%3D&use_mirror=cfhcable&r=https%3A%2F%2Fcrystalmark.info%2F"
		File = "CrystalDiskInfo9_3_2.zip"
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
		TUrl = "https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.8.0.exe"
		File = "DDU v18.0.8.0.exe"
	}
)

#function Download App Portable
function Download_Tools () {
	
	Write-Host "Url Search Tools`n------------------"
	$ListToDownload = @()
	foreach ($tool in $toolList) {

		Write-Host "Download App Portable [" -NoNewline
		Write-Host $tool.Name -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $tool
		if ($selectedApp) {
			$ListToDownload += $selectedApp
		}
		Write-Host ""
	}

	"**************************"
	"DOWNLOADING SELECTED TOOLS"
	"**************************"
	foreach ($toolId in $ListToDownload) {
		DownloadApp $toolId.TUrl $toolId.File
	}
	Write-Host ""
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

function Set_Disable_BackgroundApp {
	$backgroundAppPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
	$property = 'GlobalUserDisabled'
	$value = 1

	Test_Property $backgroundAppPath $property
	
	# Change value option
	Set_OptionStatus $backgroundAppPath $property $value
}
function Minimum_Preferences {
	$pathPreferencesMask = 'HKCU:\Control Panel\Desktop'
	$property1 = 'UserPreferencesMask'
	$preferMask = (Get-ItemProperty -Path $pathPreferencesMask).$property1
	$value = 0x90
	
	if ($preferMask[0] -ne $value) {
		$preferMask[0] = 0x90 ; $preferMask[1] = 0x12
		$preferMask[2] = 0x03 ; $preferMask[4] = 0x10

		# "Setting options minimum [$property1] to Disabled."
		"Option [$property1] has been Changing..."
		Set-Itemproperty1 -Path $pathPreferencesMask -Name $property1 -Value $preferMask -Force
	} 
	else {
		# "Options minimum [$property1] has already been Disabled."
		"Option [$property] remains Changed"
	}
}

function Animate_MinMax {
	$pathAnimateMinMax = 'HKCU:\Control Panel\Desktop\WindowMetrics'
	$property2 = 'MinAnimate'
	$value = 0

	# Change value option
	Set_OptionStatus $pathAnimateMinMax $property2 $value
}

function Animate_Taskbar {
	$pathTaskbarAnimations = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property3 = 'TaskbarAnimations'
	$value = 0

	# Change value option
	Set_OptionStatus $pathTaskbarAnimations $property3 $value
}

function Enable_Peek {
	$pathEnablePeek = 'HKCU:\Software\Microsoft\Windows\DWM'
	$property4 = 'EnableAeroPeek'
	$value = 0

	# Change value option
	Set_OptionStatus $pathEnablePeek $property4 $value
}

function Show_Translucent {
	$pathTranslucent = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property5 = 'ListviewAlphaSelect'
	$value = 0

	# Change value option
	Set_OptionStatus $pathTranslucent $property5 $value
}

function Drop_Shadows {
	$pathDropShadows = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property6 = 'ListviewShadow'
	$value = 0

	# Change value option
	Set_OptionStatus $pathDropShadows $property6 $value
}

function Set_Appearance_Custom {
	$pathVisualEffects = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
	$property = 'VisualFXSetting'
	$value = 3

	# Change value option
	Set_OptionStatus $pathVisualEffects $property $value
	
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
	"Scan CPU Load"           = "Set_Config_ScanCpuLoad"
	"Memory Compression"      = "Set_Config_MemoryCompression"
	"Turn Trim SSD"           = "Set_Config_TurnTrimSSD"
	"Disable Background Apps" = "Set_Disable_BackgroundApp"
	"Minimal Visual Effects"  = "Set_Appearance_Custom"
}

function Set_Performance_Mode () {

	$ListToChanged = @()
	foreach ($performanceFn in $performanceFnList.Keys) {

		Write-Host "Do you want to Apply [" -NoNewline
		Write-Host $performanceFn -ForegroundColor Cyan -NoNewline; "]?"

		$selectedApp = Add-AppSelection $performanceFnList[$performanceFn]
		if ($selectedApp) {
			$ListToChanged += $selectedApp
		}
		Write-Host ""
	}

	"******************************"
	"SETTING SELECTED OPTIMIZATIONS"
	"******************************"
	foreach ($operation in $ListToChanged) {
		& $operation
	}
	Write-Host ""
}

# MyTheme 7: Custom Terminal
#function Install module
function InstallModule ($moduleName) {
	$modComand = if ($moduleName -eq "Terminal-Icons") { " -Repository PSGallery" } else { "" }
	
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

<# function Deprecated
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
#>

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

function Show-FileContent {
	param (
		[string]$filePath
	)

	Write-Host "`n$(Get-Content -Path $filePath -Raw)" -ForegroundColor Cyan -NoNewline
	Write-Host "+- Message ------------------------------+"
	Write-Host "|   The content was added to the file!   |"
	Write-Host "+----------------------------------------+`n"
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

	# Add File Content
	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test_FileContent $PROFILE $stringReduce $activatePrompt
	Test_FileContent $PROFILE $iconsComand $iconsComand
	Test_FileContent $PROFILE $predictionComand $predictionComand

	# Show File Content
	Show-FileContent $PROFILE
}

function Custom_Shell_Powershell () {
	
	$activatePrompt = Install_Prompt_Terminal "kali"

	$PROFILE_TEMP = "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
	Test_FilePath $PROFILE_TEMP
	
	#************************************************************************
	
	$fileInfo = Get-ChildItem $PROFILE_TEMP
	Write-Host "[*] Current File found, Adding Content... : $($fileInfo.Name)"

	# Add File Content
	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test_FileContent $PROFILE_TEMP $stringReduce $activatePrompt

	# Show File Content
	Show-FileContent $PROFILE_TEMP
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

	# Add File Content
	Test_FileContent $CONFIG $addComment $addComment
	Test_FileContent $CONFIG $loadPrompt $loadPrompt

	# Show File Content
	Show-FileContent $CONFIG
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
	# "║ ![5] Customize PowerPlan        ║"
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

# Establecer la página de códigos a UTF-8
chcp 65001 > $null

# Invoke the Main Menu the Script.
Invoke-MainMenu

# Sleep for 2 seconds
Start-Sleep -Milliseconds 3000

# Policy Execution Restart
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "CurrentUser" -Force
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "Process" -Force
