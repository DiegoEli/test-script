
# Policy Execution Enable
#Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope "Process" -Force
#Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope "CurrentUser" -Force

#####################################################
#	ABOUT_SCRIPT
#####################################################

# Show script info
$WPName = "WinPerf"
$WPVersion = "v2.5.0"
$WPRepository = "https://raw.githubusercontent.com/DiegoEli/test-script/dev/testScript.ps1"
# $WPRepository = "https://raw.githubusercontent.com/DiegoEli/WinPerf/main/Win11Perfect.ps1"

<#
.NOTES
	Author  : Diego Mendoza(JuanPerez)
	Github  : https://github.com/DiegoEli
	Name    : WinPerf
	Version : 2.5.0

.PARAMETER [Aliases]
	irm = Invoke-RestMethod
	iex = Invoke-Expression

.EXAMPLE
	::Run the script from the repository.

	Command : irm https://raw.githubusercontent.com/DiegoEli/test-script/main/WinPerf.ps1 | iex

.FUNCTIONALITY
	::Customizar Folder in FileExplorer
	
	$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
	$item = 'Shell Icons'
	New-Item -Path $path -Name $item -ItemType "Directory" -Force
	
	$proPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons'
	$proName = 3
	$proType = 'DWord'
	New-ItemProperty -Path $proPath -Name $proName -PropertyType $proType -Value 0 -Force

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

#####################################################
#	ALL_FUNCTIONS
#####################################################

# funcion Test Item
function Test-ItemPath {
	param (
		[string]$itemPath,
		[string]$itemName,
		[string]$itemType
	)

	if ( -not (Test-Path -Path "$itemPath\$itemName") ) {

		Write-Host "Item [$itemName] not found, Creating..." -ForegroundColor Yellow
		New-Item -Path $itemPath -Name $itemName -ItemType $itemType -Force
	}
}

# function Test Property
function Test-PropertyPath {
	param (
		[string]$proPath,
		[string]$proName,
		[string]$proType
	)

	$propertyTest = Get-ItemProperty -Path $proPath -Name $proName -ErrorAction SilentlyContinue
	
	if ( -not $propertyTest ) {

		Write-Host "Property [$proName] not found, Creating..." -ForegroundColor Yellow
		$null = New-ItemProperty -Path $proPath -Name $proName -PropertyType $proType -Value "0" -Force
	}
}

# function Set Option Status
function Set-OptionValue {
	param (
		[string]$path,
		[string]$property,
		[string]$value
	)

	$currentValue = (Get-ItemProperty -Path $path).$property

	if ( $currentValue -ne $value ) {

		Write-Host "Setting value [$property], Changing..."
		Set-ItemProperty -Path $path -Name $property -Value $value -Force
	} 
	else {
		Write-Host "Value [$property] remains Changed."
	}
}

function Add-ItemSelection {
	param (
		$valueMessage,
		$valueName
	)

	$opt = Read-Host "$valueMessage `b? [Y/N]"

	if ( $opt -eq "y" ) {
		Write-Host "...DONE!" -ForegroundColor Green
		return $valueName
	} 
	elseif ( $opt -eq "n" ) {
		Write-Host "...CANCELED!" -ForegroundColor Red
		return $null
	} 
	else {
		Add-ItemSelection $valueMessage $valueName
	}
}

function Invoke-Confirmation {
	param (
		[scriptblock]$Operation
	)

	$opt = Read-Host "[Y] Yes [N] No";

	if ( $opt -eq "y" ) {
		Write-Host ""
		& $Operation; ""
	} 
	elseif ( $opt -eq "n" ) {
		Write-Host ""
		Write-Host "Operation cancelled." -ForegroundColor Red; ""
	} 
	else {
		Invoke-Confirmation $Operation
	}
}

<# function Deprecated
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
#>

# Modification #: Configure preference in Windows
function Opt_AutoLogon {
	$pathNetplwiz = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
	$property = 'DevicePasswordLessBuildVersion'
	$value = 0
	
	#"Show checkbox Netplwiz"
	Set-OptionValue $pathNetplwiz $property $value
	
	$AutoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
	$property1 = 'AutoAdminLogon'
	$value1 = 1

	#"Enable Auto Logon"
	Set-OptionValue $AutoPath $property1 $value1
}

function Opt_FastStartup {
	$pathFastStartup = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
	$property = 'HiberbootEnabled'
	$value = 0

	#"FastStartup has been Disabled"
	Set-OptionValue $pathFastStartup $property $value
}

function Opt_VerboseLogon {
	$pathVerboseLogon = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	$property = 'VerboseStatus'
	$value = 1

	Test-PropertyPath $pathVerboseLogon $property "DWord"
	
	#"VerboseLogon has been Enabled"
	Set-OptionValue $pathVerboseLogon $property $value
}

function Opt_ShowBuildVersion {
	$shoVersionPath = 'HKCU:\Control Panel\Desktop'
	$property = 'PaintDesktopVersion'
	$value = 1

	#"ShowVersion has been Enabled"
	Set-OptionValue $shoVersionPath $property $value
}

function Opt_HibernateMode {
	$pathHibernateOption = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings'
	$property1 = 'ShowHibernateOption'
	$value1 = 0

	#"Don´t Show Option Hibernate"
	Set-OptionValue $pathHibernateOption $property1 $value1

	$pathHibernateMode = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
	$property2 = 'HibernateEnabled'
	$value2 = 0

	Test-PropertyPath $pathHibernateMode $property2 "DWord"

	#"Hibernate has been Disabled"
	Set-OptionValue $pathHibernateMode $property2 $value2

	#"Disable Hibernate Mode"
	powercfg /hibernate off
}

function Opt_StartupSound {
	$path1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation'
	$path2 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EditionOverrides'
	$property1 = 'DisableStartupSound'
	$property2 = 'UserSetting_DisableStartupSound'
	$value = 1

	# Option change value
	Set-OptionValue $path1 $property1 $value
	Set-OptionValue $path2 $property2 $value
}

function Opt_CommunicationsActivity {
	$path = 'HKCU:\Software\Microsoft\Multimedia\Audio'
	$property = 'UserDuckingPreference'
	$value = 3

	# Option change value
	Set-OptionValue $path $property $value
}

function Opt_MousePrecision {
	$path = 'HKCU:\Control Panel\Mouse'
	$property1 = 'MouseSpeed'
	$property2 = 'MouseThreshold1'
	$property3 = 'MouseThreshold2'
	$value = 0
	
	# Option change value
	Set-OptionValue $path $property1 $value
	Set-OptionValue $path $property2 $value
	Set-OptionValue $path $property3 $value
}

# Modification 1: StorageSense in Windows(revisar si existe)
function Opt_StorageSense {
	$pathStorageSense = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
	$property = '01'
	$value = 0

	#"StorageSense has been Disabled"
	Set-OptionValue $pathStorageSense $property $value
}

function Opt_SnapSuggest {
	$pathSnapSuggest = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property1 = 'SnapAssist'  # 1-Suggest Snap Next
	$property2 = 'EnableSnapAssistFlyout'  # 2-Show snap layouts I hover
	$property3 = 'EnableSnapBar'  # 3-Show snap layouts I drag
	$value = 0

	#"SnapSuggest has been Disabled"
	Set-OptionValue $pathSnapSuggest $property1 $value
	Set-OptionValue $pathSnapSuggest $property2 $value
	Set-OptionValue $pathSnapSuggest $property3 $value
}

function Opt_ShowFileExtensions {
	$pathFileExt = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'HideFileExt'
	$value = 0

	#"Show FileExtensions has been Enabled"
	Set-OptionValue $pathFileExt $property $value
}

function Opt_ShowHiddenFiles {
	$pathHiddenFiFo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'Hidden'
	$value = 1

	#"Show HiddenFilesFolders has been Enabled"
	Set-OptionValue $pathHiddenFiFo $property $value
}

function Opt_ShowSyncProvider {
	$pathSyncProvider = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSyncProviderNotifications'
	$value = 0

	#"Show SyncProvider has been Disabled"
	Set-OptionValue $pathSyncProvider $property $value
}

function Opt_ShowEndTask {
	$pathEndTask = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'
	$property = 'TaskbarEndTask'
	$value = 1

	#"Show EndTask has been Enabled"
	Set-OptionValue $pathEndTask $property $value
}

function Opt_SudoCommand {
	$sudoCommandPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
	$property = 'Enabled'
	$value = 3

	# Option change value
	Set-OptionValue $sudoCommandPath $property $value
}

function Opt_DarkMode {
	$pathDarkModeAll = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property1 = 'SystemUsesLightTheme'  # 1-Choose Windows Mode
	$property2 = 'AppsUseLightTheme'  # 2-Choose App Mode
	$property3 = 'ColorPrevalence'  # 3-Show Accent color
	$value = 0
	
	#"Dark Mode has been Enabled"
	Set-OptionValue $pathDarkModeAll $property1 $value
	Set-OptionValue $pathDarkModeAll $property2 $value
	Set-OptionValue $pathDarkModeAll $property3 $value
}

function Opt_ShowItemSearch {
	$pathItemSearch = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
	$property = 'SearchboxTaskbarMode'
	$value = 0

	#"Show Item Search has been Disabled"
	Set-OptionValue $pathItemSearch $property $value
}

function Opt_ShowItemTaskView {
	$pathItemTaskView = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowTaskViewButton'
	$value = 0
	
	#"Show Item TaskView has been Disabled"
	Set-OptionValue $pathItemTaskView $property $value
}

function Opt_HideTaskbar {
	$pathHideTaskbar = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
	$property = 'Settings'
	$hideTaskbar = (Get-ItemProperty -Path $pathHideTaskbar).$property

	#"HideTaskbar has been Disabled"
	if ( $hideTaskbar[8] -ne 0x7A ) {

		$hideTaskbar[8] = 0x7A
		"Setting value [$property], Changing..."
		Set-ItemProperty -Path $pathHideTaskbar -Name $property -Value $hideTaskbar -Force
	}
	else {
		"Value [$property] remains Changed."
	}
}

function Opt_ShowDesktop {
	$pathDesktop = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'TaskbarSd'
	$value = 1

	#"ShowDesktop has been Enabled"
	Set-OptionValue $pathDesktop $property $value
}

function Set-LanguageBarS {
	param (
		[string]$property,
		[string]$state
	)

	if ( (Get-WinLanguageBarOption).$property -notlike $state ) {

		"Setting value [$property], Changing..."
		Set-WinLanguageBarOption -UseLegacyLanguageBar
	} 
	else {
		"Value [$property] remains Changed."
	}
}

function Opt_ShowLanguageBar {
	# 1-Switching input methods
	$propertyM = 'IsLegacySwitchingMode'
	$propertyB = 'IsLegacyLanguageBar'
	$stateM = $false
	$stateB = $true

	# Option change state
	Set-LanguageBarS $propertyM $stateM  # IsLegacySwitchingMode: False
	Set-LanguageBarS $propertyB $stateB  # IsLegacyLanguageBar: True

	# 2-Language Bar
	$LanguageBarPath = 'HKCU:\Software\Microsoft\CTF\LangBar'
	$property1 = 'ShowStatus'
	$property2 = 'Transparency'
	$property3 = 'ExtraIconsOnMinimized'
	$property4 = 'Label'
	$value1 = 3
	$value2 = 255
	$value3 = 0

	# Option change value
	Set-OptionValue $LanguageBarPath $property1 $value1
	Set-OptionValue $LanguageBarPath $property2 $value2
	Set-OptionValue $LanguageBarPath $property3 $value3
	Set-OptionValue $LanguageBarPath $property4 $value3
}

function Opt_ShowSeconds {
	$pathSecondsClock = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSecondsInSystemClock'
	$value = 1

	Test-PropertyPath $pathSecondsClock $property "DWord"

	#"ShowSeconds has been Enabled"
	Set-OptionValue $pathSecondsClock $property $value
}

function Opt_GameBar {
	$pathGameBar = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'UseNexusForGameBarEnabled'
	$value = 0

	#"GameBar has been Disabled"
	Set-OptionValue $pathGameBar $property $value
}

function Opt_GameMode {
	$pathGameMode = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'AutoGameModeEnabled'
	$value = 0

	#"GameMode has been Disabled"
	Set-OptionValue $pathGameMode $property $value
}

# Disables Bitlocker Auto Encryption on Windows(REVISAR)
function Opt_DeviceEncryption {
	$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
	$path2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices'
	$property1 = 'PreventDeviceEncryption'
	$property2 = 'TCGSecurityActivationDisabled'
	$value = 1
	
	Test-PropertyPath $path1 $property1 "DWord"

	#"Bitlocker has been Disabled"
	Set-OptionValue $path1 $property1 $value
	Set-OptionValue $path2 $property2 $value
}

function Remove_GalleryIcon {
	$path = 'HKCU:\Software\Classes\CLSID'
	$item = '{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}'

	Test-ItemPath $path $item "Directory"

	$pathProperty = "HKCU:\Software\Classes\CLSID\$item"
	$property = 'System.IsPinnedToNamespaceTree'
	$value = 0

	Test-PropertyPath $pathProperty $property "DWord"
	
	# Change value option
	Set-OptionValue $pathProperty $property $value
}

function Remove_DesktopIcons {
	$classicPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
	$property1 = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'  # Show Computer Icon
	$property2 = '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}'  # Show Control Panel Icon
	$property3 = '{59031a47-3f72-44a7-89c5-5595fe6b30ee}'  # Show User´s Files Icon
	$property4 = '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'  # Show Network Icon
	$value1 = 1

	# Change value option
	Set-OptionValue $classicPath $property1 $value1
	Set-OptionValue $classicPath $property2 $value1
	Set-OptionValue $classicPath $property3 $value1
	Set-OptionValue $classicPath $property4 $value1
}

$optionList = [ordered]@{
	"Enable Auto Logon"               = "Opt_AutoLogon"
	"Disable Fast Startup"            = "Opt_FastStartup"
	"Enable Verbose Logon Messages"   = "Opt_VerboseLogon"
	"Enable Show Version in Desktop"  = "Opt_ShowBuildVersion"
	"Disable Hibernate Mode(Desktop)" = "Opt_HibernateMode"
	"Disable Windows Startup Sound"   = "Opt_StartupSound"
	"Disable Adjust Volume of Sounds" = "Opt_CommunicationsActivity"
	"Disable Pointer Precision"       = "Opt_MousePrecision"
	"Disable Storage Sense"           = "Opt_StorageSense"
	# "Disable Device Encryption"       = "Opt_DeviceEncryption"
	"Disable Suggest Snap"            = "Opt_SnapSuggest"
	"Enable Show File Extensions"     = "Opt_ShowFileExtensions"
	"Enable Show Hidden System Files" = "Opt_ShowHiddenFiles"
	"Disable Show Sync Provider"      = "Opt_ShowSyncProvider"
	"Enable End Task in Taskbar"      = "Opt_ShowEndTask"
	# "Enable Sudo Command"             = "Opt_SudoCommand"
	"Enable Dark Mode"                = "Opt_DarkMode"
	"Enable Hide Item Search"         = "Opt_ShowItemSearch"
	"Disable Show Item TaskView"      = "Opt_ShowItemTaskView"
	"Disable Hide the Taskbar"        = "Opt_HideTaskbar"
	"Enable Show the Desktop"         = "Opt_ShowDesktop"
	"Disable Show Language Bar"       = "Opt_ShowLanguageBar"
	"Enable Show Seconds in Clock"    = "Opt_ShowSeconds"
	"Disable Game Bar"                = "Opt_GameBar"
	"Disable Game Mode"               = "Opt_GameMode"
	"Remove Gallery Icon in Explorer" = "Remove_GalleryIcon"
	"Remove System Icons in Desktop"  = "Remove_DesktopIcons"
}

function Set_Default_Option () {

	Write-Host "SET DEFAULT OPTION`n------------------"
	$ListToChanged = @()
	foreach ($listKey in $optionList.Keys) {

		$selectedApp = Add-ItemSelection $listKey $optionList[$listKey]
		if ($selectedApp) {
			$ListToChanged += $selectedApp
		}
	}
	Write-Host ""

	"***************************"
	"SETTING SELECTED PREFERENCE"
	"***************************"
	foreach ($operation in $ListToChanged) {
		& $operation
	}
}

# Modification #: Configure privacity in Windows
function Disable_Spotlight {
	# 1-Disable Spotlight on Desktop
	$spotlightPath1 = 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
	$property1 = 'DisableSpotlightCollectionOnDesktop'
	$Value = 1

	Test-PropertyPath $spotlightPath1 $property1 "DWord"

	# Change value option
	Set-OptionValue $spotlightPath1 $property1 $Value

	# 2-Disable Windows Spotlight
	$path = 'HKLM:\Software\Policies\Microsoft\Windows'
	$item = 'CloudContent'

	Test-ItemPath $path $item "Directory"

	$spotlightPath2 = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
	$property2 = 'DisableWindowsSpotlightOnLockScreen'
	$property3 = 'DisableWindowsConsumerFeatures'
	$property4 = 'DisableWindowsSpotlightActiveUser'
	$Value1 = 1

	Test-PropertyPath $spotlightPath2 $property2 "DWord"
	Test-PropertyPath $spotlightPath2 $property3 "DWord"
	Test-PropertyPath $spotlightPath2 $property4 "DWord"

	# Change value option
	Set-OptionValue $spotlightPath2 $property2 $Value1
	Set-OptionValue $spotlightPath2 $property3 $Value1
	Set-OptionValue $spotlightPath2 $property4 $Value1
}

function Disable_AdditionalSettings {
	$path1 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$path2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'
	$property1 = 'SubscribedContent-310093Enabled'
	$property2 = 'ScoobeSystemSettingEnabled'
	$value = 0

	# Change value option
	Set-OptionValue $path1 $property1 $value
	Set-OptionValue $path2 $property2 $value
}

function Disable_GetTipsTricks {
	$pathTipsTricks = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$property1 = 'RotatingLockScreenOverlayEnabled'
	$property2 = 'SubscribedContent-338387Enabled'
	$value = 0
	
	#"Facts, Tips & Tricks has been Disabled"
	Set-OptionValue $pathTipsTricks $property1 $value
	Set-OptionValue $pathTipsTricks $property2 $value
}

function Disable_WinStartInfo {
	$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property1 = 'Start_TrackDocs'
	$property2 = 'Start_IrisRecommendations'
	$property3 = 'Start_AccountNotifications'
	$value = 0

	# Change value option
	Set-OptionValue $path $property1 $value
	Set-OptionValue $path $property2 $value
	Set-OptionValue $path $property3 $value
}

function Disable_PersonalizeAds {
	$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'AdvertisingInfo'

	Test-ItemPath $path $item "Directory"

	# 1-Disable Advertising ID
	$pathProperty1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property1 = 'DisabledByGroupPolicy'
	$value1 = 1

	Test-PropertyPath $pathProperty1 $property1 "DWord"

	# Change value option
	Set-OptionValue $pathProperty1 $property1 $value1

	# 2-Disable Website Access to Language List
	$pathProperty2 = 'HKCU:\Control Panel\International\User Profile'
	$property2 = 'HttpAcceptLanguageOptOut'
	$value2 = 1

	Test-PropertyPath $pathProperty2 $property2 "DWord"

	# Change value option
	Set-OptionValue $pathProperty2 $property2 $value2

	# 3-Disable App Launch Tracking
	$pathProperty3 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property3 = 'Start_TrackProgs'
	$value3 = 0
	
	# Change value option
	Set-OptionValue $pathProperty3 $property3 $value3

	# 4-Disable Suggested Content in Settings
	$pathProperty4 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$property4 = 'SubscribedContent-338393Enabled'
	$property5 = 'SubscribedContent-353694Enabled'
	$property6 = 'SubscribedContent-353696Enabled'
	$value4 = 0

	# Change value option
	Set-OptionValue $pathProperty4 $property4 $value4
	Set-OptionValue $pathProperty4 $property5 $value4
	Set-OptionValue $pathProperty4 $property6 $value4
}

function Disable_TypingPersonalization {
	$typingPath = 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings'
	$property = 'AcceptedPrivacyPolicy'
	$value = 0

	# Change value option
	Set-OptionValue $typingPath $property $value
}

function Disable_DiagnosticData {
	$pathTelemetry1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
	$pathTelemetry2 = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
	$pathTelemetry3 = 'HKCU:\Software\Microsoft\Siuf\Rules'
	$pathTelemetry4 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'
	$property1 = 'AllowTelemetry'
	$property2 = 'NumberOfSIUFInPeriod'
	$property3 = 'TailoredExperiencesWithDiagnosticDataEnabled'
	$value = 0

	Test-PropertyPath $pathTelemetry2 $property1 "DWord"
	Test-PropertyPath $pathTelemetry3 $property2 "DWord"
	
	# Change value option
	Set-OptionValue $pathTelemetry1 $property1 $value
	Set-OptionValue $pathTelemetry2 $property1 $value
	Set-OptionValue $pathTelemetry3 $property2 $value
	Set-OptionValue $pathTelemetry4 $property3 $value
}

function Disable_ActivityHistory {
	$pathActivityHistory = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
	$property1 = 'EnableActivityFeed'
	$property2 = 'PublishUserActivities'
	$property3 = 'UploadUserActivities'
	$value = 0
	
	Test-PropertyPath $pathActivityHistory $property1 "DWord"
	Test-PropertyPath $pathActivityHistory $property2 "DWord"
	Test-PropertyPath $pathActivityHistory $property3 "DWord"

	# Change value option
	Set-OptionValue $pathActivityHistory $property1 $value
	Set-OptionValue $pathActivityHistory $property2 $value
	Set-OptionValue $pathActivityHistory $property3 $value
}

function Disable_CortanaResults {
	$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Windows Search'

	Test-ItemPath $path $item "Directory"

	$pathProperty = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property = 'AllowCortana'
	$value = 0

	Test-PropertyPath $pathProperty $property "DWord"

	# Change value option
	Set-OptionValue $pathProperty $property $value
}

function Disable_WebResults {
	$pathWebSearch = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
	$property1 = 'SafeSearchMode'
	$property2 = 'IsMSACloudSearchEnabled'
	$property3 = 'IsAADCloudSearchEnabled'
	$value1 = 0

	# Change value option
	Set-OptionValue $pathWebSearch $property1 $value1
	Set-OptionValue $pathWebSearch $property2 $value1
	Set-OptionValue $pathWebSearch $property3 $value1

	$pathWebSuggest = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
	$property4 = 'BingSearchEnabled'
	$property5 = 'CortanaConsent'
	$value2 = 0

	Test-PropertyPath $pathWebSuggest $property4 "DWord"
	Test-PropertyPath $pathWebSuggest $property5 "DWord"

	# Change value option
	Set-OptionValue $pathWebSuggest $property4 $value2
	Set-OptionValue $pathWebSuggest $property5 $value2
}

function Disable_LocalResults {
	$pathLocalResults = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
	$property = 'IsDeviceSearchHistoryEnabled'
	$value = 0

	# Change value option
	Set-OptionValue $pathLocalResults $property $value
}

function Disable_LocationTracking {
	$path_1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
	$property1 = 'Value'
	$value1 = 'Deny'

	# Change value option
	Set-OptionValue $path_1 $property1 $value1

	$path_2 = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
	$property2 = 'SensorPermissionState'
	$value2 = 0
	
	# Change value option
	Set-OptionValue $path_2 $property2 $value2

	$path_3 = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
	$property3 = 'Status'
	$value3 = 0
	
	# Change value option
	Set-OptionValue $path_3 $property3 $value3

	$path_4 = 'HKLM:\SYSTEM\Maps'
	$property4 = 'AutoUpdateEnabled'
	$value4 = 0
	
	# Change value option
	Set-OptionValue $path_4 $property4 $value4
}

$privacyList = [ordered]@{
	"Disable Windows Spotlight"      = "Disable_Spotlight"
	"Disable Welcome Experience"     = "Disable_AdditionalSettings"
	"Disable Get Facts, Tips, Trick" = "Disable_GetTipsTricks"
	"Disable Windows Start Info"     = "Disable_WinStartInfo"
	"Disable Personalize Ads"        = "Disable_PersonalizeAds"
	"Disable Typing Personalization" = "Disable_TypingPersonalization"
	"Disable Diagnostic Data"        = "Disable_DiagnosticData"
	"Disable Activity History"       = "Disable_ActivityHistory"
	"Disable Cortana Results"        = "Disable_CortanaResults"
	"Disable Web Results"            = "Disable_WebResults"
	"Disable Local Results"          = "Disable_LocalResults"
	"Disable Location Tracking"      = "Disable_LocationTracking"
}

function Set_Privacy_Security () {

	Write-Host "SET PRIVACY TWEAKS`n------------------"
	$ListToChanged = @()
	foreach ($listKey in $privacyList.Keys) {

		$selectedApp = Add-ItemSelection $listKey $privacyList[$listKey]
		if ($selectedApp) {
			$ListToChanged += $selectedApp
		}
	}
	Write-Host ""
	
	"*******************************"
	"SETTING SELECTED PRIVACY TWEAKS"
	"*******************************"
	foreach ($operation in $ListToChanged) {
		& $operation
	}
}

# Modification #: Configure Update behavior in Windows
function Set_WinAutoUpdates {
	$path1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item1 = 'WindowsUpdate'
	$path2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item1"
	$item2 = 'AU'
	
	Test-ItemPath $path1 $item1 "Directory"
	Test-ItemPath $path2 $item2 "Directory"
	
	$pathUpdateType = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item1\$item2"
	$property1 = 'AUOptions'  #$valueAUO = 2 ; status = Notificar
	$property2 = 'NoAutoUpdate'  #$valueNAU = 1 ; status = Disabled
	$property3 = 'NoAutoRebootWithLoggedOnUsers'
	$valueAUO = 2
	$valueNAU = 1

	Test-PropertyPath $pathUpdateType $property1 "DWord"
	Test-PropertyPath $pathUpdateType $property2 "DWord"
	Test-PropertyPath $pathUpdateType $property3 "DWord"

	# Change value option
	Set-OptionValue $pathUpdateType $property1 $valueAUO
	Set-OptionValue $pathUpdateType $property2 $valueNAU
	Set-OptionValue $pathUpdateType $property3 $valueNAU
}

function Set_PreliminaryUpdates {
	$pathPreliminary = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	$property = 'ManagePreviewBuildsPolicyValue'
	$value = 1

	Test-PropertyPath $pathPreliminary $property "DWord"

	# Change value option
	Set-OptionValue $pathPreliminary $property $value
}

function Set_DelaySecurityUpdates {
	$pathDelaySecurity = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property = 'DeferQualityUpdatesPeriodInDays'
	$value = 4

	Test-PropertyPath $pathDelaySecurity $property "DWord"

	# Change value option
	Set-OptionValue $pathDelaySecurity $property $value
}

function Set_GetLatestUpdates {
	$latestUpdatesPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property = 'IsContinuousInnovationOptedIn'
	$value = 0

	# Change value option
	Set-OptionValue $latestUpdatesPath $property $value
}

function Set_UpdateOtherProduct {
	$MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
	$serviceId = '7971f918-a847-4430-9279-4a52d1efe18d'

	$service = $MUSM.Services | Where-Object { $_.ServiceID -eq "$serviceId" }

	if ($service) {

		"Setting value [RegisteredWithAU], Changing..."
		$MUSM.RemoveService("$serviceId")
	} 
	else {
		"Value [RegisteredWithAU] remains Changed."
	}
}

function Set_ActiveHours {
	$ActiveHoursPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property1 = 'SmartActiveHoursState'
	$property2 = 'ActiveHoursStart'
	$property3 = 'ActiveHoursEnd'
	$value1 = 0
	$value2 = 6
	$value3 = 23
	
	# Change value option
	Set-OptionValue $ActiveHoursPath $property1 $value1
	Set-OptionValue $ActiveHoursPath $property2 $value2
	Set-OptionValue $ActiveHoursPath $property3 $value3
}

function Set_DownloadsOtherPCs {
	$HKU = "Registry::HKEY_USERS"
	$pathDownloadsPC = "$HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings"
	$property = 'DownloadMode'
	$value = 0

	# Change value option
	Set-OptionValue $pathDownloadsPC $property $value
}

function Set_StoreAutoUpdates {
	$updatesStorePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate'
	$property = 'AutoDownload'
	$value = 2

	# Change value option
	Set-OptionValue $updatesStorePath $property $value
}

function Set_LimitBandwidthUpdates {
	$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Psched'

	Test-ItemPath $path $item

	$bandwidthPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property = 'NonBestEffortLimit'
	$value = 0

	Test-PropertyPath $bandwidthPath $property "DWord"

	# Change value option
	Set-OptionValue $bandwidthPath $property $value
}

$updateList = [ordered]@{
	"Disable Windows AutoUpdates"        = "Set_WinAutoUpdates"
	"Disable Preliminary Updates"        = "Set_PreliminaryUpdates"
	"Enable Delay Security Updates"      = "Set_DelaySecurityUpdates"
	"Disable Get the latest Updates"     = "Set_GetLatestUpdates"
	"Disable Updates for other products" = "Set_UpdateOtherProduct"
	"Enable Active Hours of 06:00-23:00" = "Set_ActiveHours"
	"Disable Downloads from other PCs"   = "Set_DownloadsOtherPCs"
	"Disable Store AutoUpdates"          = "Set_StoreAutoUpdates"
	"Limit reservable bandwidth"         = "Set_LimitBandwidthUpdates"
}

function Set_Update_Behavior () {

	Write-Host "SET UPDATE BEHAVIOR`n-------------------"
	$ListToChanged = @()
	foreach ($listKey in $updateList.Keys) {

		$selectedApp = Add-ItemSelection $listKey $updateList[$listKey]
		if ($selectedApp) {
			$ListToChanged += $selectedApp
		}
	}
	Write-Host ""

	"********************************"
	"SETTING SELECTED UPDATE BEHAVIOR"
	"********************************"
	foreach ($operation in $ListToChanged) {
		& $operation
	}
}

# Modification #: Configure performance in Windows
function Config_ScanCpuLoad {
	$property = 'ScanAvgCPULoadFactor'
	$value = 1

	if ( (Get-MpPreference).$property -ne $value ) {

		"Setting value [$property], Changing..."
		Set-MpPreference -ScanAvgCPULoadFactor $value
	} 
	else {
		"Value [$property] remains Changed."
	}
}

function Config_AutoSample {
	$property = 'SubmitSamplesConsent'
	$value = 2

	if ( (Get-MpPreference).$property -ne $value ) {

		"Setting value [$property], Changing..."
		Set-MpPreference -SubmitSamplesConsent $value
	} 
	else {
		"Value [$property] remains Changed."
	}
}

function Config_MemoryCompression {
	$property = 'MemoryCompression'
	$state = $true

	if ( (Get-MMAgent).$property -notlike $state ) {

		"Setting state [$property], Changing..."
		Enable-MMAgent -MemoryCompression
	} 
	else {
		"State [$property] remains Changed."
	}
}

function Get-StatusValue {
	param (
		[string]$trimString
	)
	
	if ( $trimString -match "DisableDeleteNotify = 1" ) {
		return 1
	} 
	else {
		return 0
	}
}

function Config_TrimSSD {
	$trimCmd = fsutil behavior query DisableDeleteNotify
	$trimString = $trimCmd -match "NTFS DisableDeleteNotify = (\d)"
	$value = 0

	$trimValue = Get-StatusValue $trimString

	if ( $trimValue -ne $value ) {

		"Setting value [TrimOperations], Changing..."
		fsutil behavior set DisableDeleteNotify $value
	} 
	else {
		"Value [TrimOperations] remains Changed."
	}
}

function Disable_BackgroundApp {
	$backgroundAppPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
	$property = 'GlobalUserDisabled'
	$value = 1

	Test-PropertyPath $backgroundAppPath $property "DWord"
	
	# Change value option
	Set-OptionValue $backgroundAppPath $property $value
}

function Disable_TransparencyEffects {
	$pathTransparency = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property = 'EnableTransparency'
	$value = 0

	# "Transparency has been Disabled"
	Set-OptionValue $pathTransparency $property $value
}

function Minimum_Preferences {
	$pathPreferencesMask = 'HKCU:\Control Panel\Desktop'
	$property1 = 'UserPreferencesMask'
	$preferMask = (Get-ItemProperty -Path $pathPreferencesMask).$property1
	
	if ( ($preferMask[0] -ne 0x90) -or ($preferMask[1] -ne 0x12) ) {
		$preferMask[0] = 0x90 ; $preferMask[1] = 0x12
		$preferMask[2] = 0x03 ; $preferMask[4] = 0x10

		"Setting value [$property1], Changing..."
		Set-ItemProperty -Path $pathPreferencesMask -Name $property1 -Value $preferMask -Force
	} 
	else {
		"Value [$property1] remains Changed."
	}
}

function Animate_MinMax {
	$pathAnimateMinMax = 'HKCU:\Control Panel\Desktop\WindowMetrics'
	$property2 = 'MinAnimate'
	$value = 0

	# Change value option
	Set-OptionValue $pathAnimateMinMax $property2 $value
}

function Animate_Taskbar {
	$pathTaskbarAnimations = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property3 = 'TaskbarAnimations'
	$value = 0

	# Change value option
	Set-OptionValue $pathTaskbarAnimations $property3 $value
}

function Enable_Peek {
	$pathEnablePeek = 'HKCU:\Software\Microsoft\Windows\DWM'
	$property4 = 'EnableAeroPeek'
	$value = 0

	# Change value option
	Set-OptionValue $pathEnablePeek $property4 $value
}

function Show_Translucent {
	$pathTranslucent = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property5 = 'ListviewAlphaSelect'
	$value = 0

	# Change value option
	Set-OptionValue $pathTranslucent $property5 $value
}

function Drop_Shadows {
	$pathDropShadows = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property6 = 'ListviewShadow'
	$value = 0

	# Change value option
	Set-OptionValue $pathDropShadows $property6 $value
}

function Set_CustomAppearance {
	$pathVisualEffects = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
	$property = 'VisualFXSetting'
	$value = 3

	# Change value option
	Set-OptionValue $pathVisualEffects $property $value

	# Efectos visuales minimos
	Minimum_Preferences
	Animate_MinMax
	Animate_Taskbar
	Enable_Peek
	Show_Translucent
	Drop_Shadows
}

function Set_GroupProcesses {
	$svchostPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
	$property = "SvcHostSplitThresholdInKB"  # $ram = 3670016 | value default in 8GB RAM
	$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
	
	# Change value option
	Set-OptionValue $svchostPath $property $ram
}

$performanceList = [ordered]@{
	"Reduce Scan CPU Load"         = "Config_ScanCpuLoad"
	"Disable Auto Sample"          = "Config_AutoSample"
	"Enable Memory Compression"    = "Config_MemoryCompression"
	"Enable TRIM SSD"              = "Config_TrimSSD"
	"Disable Background Apps"      = "Disable_BackgroundApp"
	"Disable Transparency Effects" = "Disable_TransparencyEffects"
	"Apply Minimal Visual Effects" = "Set_CustomAppearance"
	"Group Svchost Processes"      = "Set_GroupProcesses"
}

function Set_Performance_Mode () {

	Write-Host "SET PERFORMANCE TWEAKS`n----------------------"
	$ListToChanged = @()
	foreach ($listKey in $performanceList.Keys) {

		$selectedApp = Add-ItemSelection $listKey $performanceList[$listKey]
		if ($selectedApp) {
			$ListToChanged += $selectedApp
		}
	}
	Write-Host ""

	"******************************"
	"SETTING SELECTED OPTIMIZATIONS"
	"******************************"
	foreach ($operation in $ListToChanged) {
		& $operation
	}
}

# Modification #: Configure service in Windows
# Get-Service | Sort-Object DisplayName | Format-Table -Property Status, Name, DisplayName
# Get-Service | Sort-Object Status, DisplayName | Format-Table -GroupBy Status -Property Status, Name, DisplayName
function ConfigService ($serviceId, $startupType) {
	$service = Get-Service -Name $serviceId -ErrorAction SilentlyContinue
	
	if ($service) {
		
		Write-Host "Setting service [$serviceId] to $startupType." -NoNewline
		Invoke-Expression "Set-Service -Name `"$serviceId`" -StartupType $startupType"
		Invoke-Expression "Stop-Service -Name `"$serviceId`""

		$service | Format-List -Property Name, DisplayName, StartType, Status
	} 
	else {
		Write-Host "ERROR: Setting service [$serviceId] to $startupType, Service not found."
	}
}

$disableList = @(
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
	"ssh-agent"               #OpenSSH Authentication Agent
)

$manualList = @(
	"lfsvc",                          #Servicio de geolocalización
	"vmickvpexchange",                #Hyper-V Data Exchange Service
	"vmicguestinterface",             #Hyper-V Guest Service Interface
	"vmicshutdown",                   #Hyper-V Guest Shutdown Service
	"vmicheartbeat",                  #Hyper-V Heartbeat Service
	"vmicvmsession",                  #Hyper-V PowerShell Direct Service
	"vmicrdv",                        #Hyper-V Remote Desktop Virtualization Service
	"vmictimesync",                   #Hyper-V Time Synchronization Service
	"vmicvss",                        #Hyper-V Volume Shadow Copy Requestor
	"MicrosoftEdgeElevationService",  #Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)
	"edgeupdate",                     #Microsoft Edge Update Service (edgeupdate)
	"edgeupdatem",                    #Microsoft Edge Update Service (edgeupdatem)
	"StorSvc",                        #Storage Service
	"wuauserv"                        #Windows Update
)

function Set_Service_Startup () {
	
	Write-Host "SET SERVICES`n------------"
	foreach ($serviceId in $disableList) {
		ConfigService $serviceId Disabled
	}
	
	foreach ($serviceId in $manualList) {
		ConfigService $serviceId Manual
	}
}

# Modification #: Configure Task Sheduler in Windows
# Get-ScheduledTask | Sort-Object TaskPath, TaskName | Format-Table -Property TaskPath, TaskName, State
# Get-ScheduledTask | Sort-Object State, TaskPath, TaskName | Format-Table -GroupBy State -Property TaskPath, TaskName, State
function ConfigTask ($taskPath, $taskName, $stateType) {
	$task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName
	
	$newState = $stateType.Substring(0, $stateType.Length - 1)
	if ($task) {
		
		Write-Host "Setting task [$taskName] to $stateType." -NoNewline
		$null = Invoke-Expression "$newState-ScheduledTask -TaskPath `"$taskPath`" -TaskName `"$taskName`""
		
		$task | Format-List -Property TaskName, TaskPath, URI, State
	}
	else {
		Write-Host "ERROR: Setting task [$taskName] to $stateType, Task not found."
	}
}

$disableTList = @(
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
		Path = "\Microsoft\Windows\Autochk\"
		Name = "Proxy"
	}
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
		Path = "\Microsoft\Windows\Windows Error Reporting\"
		Name = "QueueReporting"
	}
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

function Set_Scheduled_Task () {

	Write-Host "SET SCHEDULED TASKS`n-------------------"
	foreach ($task in $disableTList) {
		ConfigTask $task.Path $task.Name Disabled
	}
}

# Modification #: Configure Remove AppCapability in Windows
function Test-ModuleAppx {

	InstallModule "Appx"
	ActivateModule "Appx"
}
function Test-ModuleDism {

	InstallModule "Dism"
	ActivateModule "Dism"
}

# Get-WindowsCapability -Online | Sort-Object Name | Format-Table -Property Name, State
# Get-WindowsCapability -Online | Sort-Object State, Name | Format-Table -GroupBy State -Property Name, State
function RemoveCapabilityApp ($appName) {
	$appc = Get-WindowsCapability -Online | Where-Object { $_.Name -like "*$appName*" }

	if ( ($null -ne $appc) -and ($appc.State -notlike "NotPresent") ) {

		Write-Host "Capability [$appName] found, Removing..." -NoNewline
		$null = Remove-WindowsCapability -Name "$($appc.Name)" -Online
		
		$appc | Format-List -Property Name, Online, RestartNeeded, LogPath, LogLevel, State
	} 
	elseif ( ($null -ne $appc) -and ($appc.State -notlike "Installed") ) {
		Write-Host "ERROR: Removing Capability [$appName], App not present."
	} 
	else {
		Write-Host "ERROR: Removing Capability [$appName], App not found."
	}
}

$capabilityList = [ordered]@{
	"Analog Holographic"   = "Analog.Holographic.Desktop"
	"Steps Recorder"       = "App.StepsRecorder"
	"Quick Assist"         = "App.Support.QuickAssist"
	"Internet Explorer"    = "Browser.InternetExplorer"
	"Hello Face"           = "Hello.Face.20134"
	"Math Recognizer"      = "MathRecognizer"
	"Windows Media Player" = "Media.WindowsMediaPlayer"
	"Wallpapers Extended"  = "Microsoft.Wallpapers.Extended"
	"MSPaint OLD"          = "Microsoft.Windows.MSPaint"
	"Notepad OLD"          = "Microsoft.Windows.Notepad.System"
	"PowerShell ISE"       = "Microsoft.Windows.PowerShell.ISE"
	"WordPad"              = "Microsoft.Windows.WordPad"
	"Print Fax"            = "Print.Fax.Scan"
	# "WMIC Command"         = "WMIC"
	"XPS Viewer"           = "XPS.Viewer"
}

function Remove_Capability_App () {
	
	Write-Host "REMOVE CAPABILITY APP`n---------------------"
	$ListToRemoveC = @()
	foreach ($listKey in $capabilityList.Keys) {

		$messageS = "Remove Capability $listKey"
		$selectedApp = Add-ItemSelection $messageS $capabilityList[$listKey]
		if ($selectedApp) {
			$ListToRemoveC += $selectedApp
		}
	}

	Write-Host "`n======================="
	Write-Host "  SELECTED CAPABILITY  "
	Write-Host "======================="
	Write-Host "$ListToRemoveC`n"
	foreach ($appcId in $ListToRemoveC) {
		RemoveCapabilityApp $appcId
	}
}

# Modification #: Configure Remove AppxPackage in Windows
# Get-AppxPackage | Where-Object { $_.NonRemovable -like "False" } | Sort-Object Name | Format-Table -Property Name, PackageFullName, NonRemovable
function RemovePackageAppx ($appxName) {
	$appx = Get-AppxPackage | Where-Object { $_.PackageFullName -like "*$appxName*" }

	if ($appx) {
		
		Write-Host "Package [$appxName] found, Removing..." -NoNewline
		Remove-AppxPackage -Package "$($appx.PackageFullName)"
		
		$appx | Format-List -Property Name, Version, Architecture, ResourceId, PackageFullName, Status
	} 
	else {
		Write-Host "ERROR: Removing Package [$appxName], Appx not found."
	}
}

$packageList = [ordered]@{
	"Microsoft Clipchamp"     = "Clipchamp.Clipchamp"
	"Cortana"                 = "Microsoft.549981C3F5F10"
	"Microsoft News"          = "Microsoft.BingNews"
	"MSN Weather"             = "Microsoft.BingWeather"
	# "Copilot"                 = "Microsoft.Copilot"
	"Xbox App"                = "Microsoft.GamingApp"
	"Get Help"                = "Microsoft.GetHelp"
	"Get Started"             = "Microsoft.Getstarted"
	"HEIF Image Extension"    = "Microsoft.HEIFImageExtension"
	"HEVC Video Extension"    = "Microsoft.HEVCVideoExtension"
	"Paint 3D"                = "Microsoft.Microsoft3DViewer"
	# "Microsoft Edge"          = "Microsoft.MicrosoftEdge.Stable"        #QUITARLO ROMPE COSAS
	# "Microsoft Edge Tools"    = "Microsoft.MicrosoftEdgeDevToolsClient"
	"Microsoft 365 (PWA)"     = "Microsoft.MicrosoftOfficeHub"
	"Solitaire Collection"    = "Microsoft.MicrosoftSolitaireCollection"
	"Microsoft Sticky Notes"  = "Microsoft.MicrosoftStickyNotes"
	"Mixed Reality Portal"    = "Microsoft.MixedReality.Portal"
	"Paint (OLD)"             = "Microsoft.MSPaint"
	"OneNote"                 = "Microsoft.Office.OneNote"
	"Outlook for Windows"     = "Microsoft.OutlookForWindows"
	"Microsoft People"        = "Microsoft.People"
	"Power Automate"          = "Microsoft.PowerAutomateDesktop"
	"Raw Image Extension"     = "Microsoft.RawImageExtension"
	# "Store Purchase App"      = "Microsoft.StorePurchaseApp" #REVISAR
	"Skype"                   = "Microsoft.SkypeApp"
	"Microsoft To Do"         = "Microsoft.Todos"
	"VP9 Video Extension"     = "Microsoft.VP9VideoExtensions"
	"Microsoft Wallet"        = "Microsoft.Wallet"
	"Web Media Extension"     = "Microsoft.WebMediaExtensions"
	"Webp Image Extension"    = "Microsoft.WebpImageExtension"
	"Dev Home"                = "Microsoft.Windows.DevHome"
	"Microsoft Photos"        = "Microsoft.Windows.Photos"
	"Mail and Calendar"       = "microsoft.windowscommunicationsapps"
	"Feedback Hub"            = "Microsoft.WindowsFeedbackHub"
	"Windows Maps"            = "Microsoft.WindowsMaps"
	"Xbox TCUI"               = "Microsoft.Xbox.TCUI"
	"Xbox App (OLD)"          = "Microsoft.XboxApp"
	"Xbox Game Overlay"       = "Microsoft.XboxGameOverlay"
	# "Game Bar"                = "Microsoft.XboxGamingOverlay"
	"Xbox Provider"           = "Microsoft.XboxIdentityProvider"
	"Xbox Text Overlay"       = "Microsoft.XboxSpeechToTextOverlay"
	# "Phone Link"              = "Microsoft.YourPhone"
	"Windows Media Player"    = "Microsoft.ZuneMusic"
	"Movies & TV"             = "Microsoft.ZuneVideo"
	"Microsoft Family Safety" = "MicrosoftCorporationII.MicrosoftFamily"
	"Quick Assist"            = "MicrosoftCorporationII.QuickAssist"
	"Widgets"                 = "MicrosoftWindows.Client.WebExperience"
	# "Cross Device Host"       = "MicrosoftWindows.CrossDevice" #REVISAR
	"Widgets PlatformRuntime" = "Microsoft.WidgetsPlatformRuntime"
	"Microsoft Teams"         = "MSTeams"
	"Spotify Music"           = "SpotifyAB.SpotifyMusic"
	#"linkedin"               = "linkedin_searchId"                 #BUSCAR ID COMPLETO
	#"Camo Studio"            = "CamoStudio_searchId"               #BUSCAR ID COMPLETO
}

function Remove_User_Appx () {

	Write-Host "REMOVE USER APPX`n----------------"
	$ListToRemoveU = @()
	foreach ($listKey in $packageList.Keys) {

		$messageS = "Remove Package $listKey"
		$selectedApp = Add-ItemSelection $messageS $packageList[$listKey]
		if ($selectedApp) {
			$ListToRemoveU += $selectedApp
		}
	}

	Write-Host "`n===================="
	Write-Host "  SELECTED PACKAGE  "
	Write-Host "===================="
	Write-Host "$ListToRemoveU`n"
	foreach ($appxId in $ListToRemoveU) {
		RemovePackageAppx $appxId
	}
}

<# function Deprecated
# Uninstall 5.0: ProvisionedAppxPackages list
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

# Modification #: Configure Remove ProvisionedAppxPackage in Windows
# Get-AppxProvisionedPackage -Online | Sort-Object DisplayName | Format-Table -Property DisplayName, PackageName
function RemoveProvisionedAppx ($appxName) {
	$appx = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$appxName*" }

	if ($appx) {
		
		Write-Host "Provisioned [$appxName] found, Removing..." -NoNewline
		$null = Remove-AppxProvisionedPackage -PackageName "$($appx.PackageName)" -Online
		
		$appx | Format-List
	} 
	else {
		Write-Host "ERROR: Removing Provisioned [$appxName], Appx not found."
	}
}

$provisionedList = [ordered]@{
	"Microsoft Clipchamp"     = "Clipchamp.Clipchamp"
	"Cortana"                 = "Microsoft.549981C3F5F10"
	"Microsoft News"          = "Microsoft.BingNews"
	"Bing Search (Edge)"      = "Microsoft.BingSearch"
	"MSN Weather"             = "Microsoft.BingWeather"
	# "Copilot"                 = "Microsoft.Copilot"
	"Xbox App"                = "Microsoft.GamingApp"
	"Get Help"                = "Microsoft.GetHelp"
	"Get Started"             = "Microsoft.Getstarted"
	"HEIF Image Extension"    = "Microsoft.HEIFImageExtension"
	"HEVC Video Extension"    = "Microsoft.HEVCVideoExtension"
	"Paint 3D"                = "Microsoft.Microsoft3DViewer"
	# "Microsoft Edge"          = "Microsoft.MicrosoftEdge.Stable"        #QUITARLO ROMPE COSAS
	# "Microsoft Edge Tools"    = "Microsoft.MicrosoftEdgeDevToolsClient"
	"Microsoft 365 (PWA)"     = "Microsoft.MicrosoftOfficeHub"
	"Solitaire Collection"    = "Microsoft.MicrosoftSolitaireCollection"
	"Microsoft Sticky Notes"  = "Microsoft.MicrosoftStickyNotes"
	"Mixed Reality Portal"    = "Microsoft.MixedReality.Portal"
	"Paint (OLD)"             = "Microsoft.MSPaint"
	"OneNote"                 = "Microsoft.Office.OneNote"
	"Outlook for Windows"     = "Microsoft.OutlookForWindows"
	"Microsoft People"        = "Microsoft.People"
	"Power Automate"          = "Microsoft.PowerAutomateDesktop"
	"Raw Image Extension"     = "Microsoft.RawImageExtension"
	# "Store Purchase App"      = "Microsoft.StorePurchaseApp" #REVISAR
	"Skype"                   = "Microsoft.SkypeApp"
	"Microsoft To Do"         = "Microsoft.Todos"
	"VP9 Video Extension"     = "Microsoft.VP9VideoExtensions"
	"Microsoft Wallet"        = "Microsoft.Wallet"
	"Web Media Extension"     = "Microsoft.WebMediaExtensions"
	"Webp Image Extension"    = "Microsoft.WebpImageExtension"
	"Dev Home"                = "Microsoft.Windows.DevHome"
	"Microsoft Photos"        = "Microsoft.Windows.Photos"
	"Mail and Calendar"       = "microsoft.windowscommunicationsapps"
	"Feedback Hub"            = "Microsoft.WindowsFeedbackHub"
	"Windows Maps"            = "Microsoft.WindowsMaps"
	"Xbox TCUI"               = "Microsoft.Xbox.TCUI"
	"Xbox App (OLD)"          = "Microsoft.XboxApp"
	"Xbox Game Overlay"       = "Microsoft.XboxGameOverlay"
	# "Game Bar"                = "Microsoft.XboxGamingOverlay"
	"Xbox Provider"           = "Microsoft.XboxIdentityProvider"
	"Xbox Text Overlay"       = "Microsoft.XboxSpeechToTextOverlay"
	# "Phone Link"              = "Microsoft.YourPhone"
	"Windows Media Player"    = "Microsoft.ZuneMusic"
	"Movies & TV"             = "Microsoft.ZuneVideo"
	"Microsoft Family Safety" = "MicrosoftCorporationII.MicrosoftFamily"
	"Quick Assist"            = "MicrosoftCorporationII.QuickAssist"
	"Widgets"                 = "MicrosoftWindows.Client.WebExperience"
	# "Cross Device Host"       = "MicrosoftWindows.CrossDevice" #REVISAR
	"Widgets PlatformRuntime" = "Microsoft.WidgetsPlatformRuntime"
	"Microsoft Teams"         = "MSTeams"
}

function Remove_Provisioned_Appx () {

	Write-Host "REMOVE PROVISIONED APPX`n-----------------------"
	$ListToRemoveP = @()
	foreach ($listKey in $provisionedList.Keys) {

		$messageS = "Remove Provisioned $listKey"
		$selectedApp = Add-ItemSelection $messageS $provisionedList[$listKey]
		if ($selectedApp) {
			$ListToRemoveP += $selectedApp
		}
	}

	Write-Host "`n========================"
	Write-Host "  SELECTED PROVISIONED  "
	Write-Host "========================"
	Write-Host "$ListToRemoveP`n"
	foreach ($appxId in $ListToRemoveP) {
		RemoveProvisionedAppx $appxId
	}
}

# Modification #: Configure Enable or Disable features in Windows
# Get-WindowsOptionalFeature -Online | Sort-Object FeatureName | Format-Table -Property FeatureName, State
# Get-WindowsOptionalFeature -Online | Sort-Object State, FeatureName | Format-Table -GroupBy State -Property FeatureName, State
function ConfigFeature ($featureName, $stateType) {
	$feature = Get-WindowsOptionalFeature -FeatureName $featureName -Online
	
	$newState = $stateType.Substring(0, $stateType.Length - 1)
	if ($feature) {
		
		Write-Host "Setting feature [$featureName] to $stateType." -NoNewline
		$null = Invoke-Expression "$newState-WindowsOptionalFeature -FeatureName `"$featureName`" -Online"
		
		$feature | Format-List -Property FeatureName, DisplayName, Description, State
	} 
	else {
		Write-Host "ERROR: Setting feature [$featureName] to $stateType, Feature not found."
		# "Cannot find path 'HKCU:\Software\Microsoft' because it does not exist."
	}
}

$disableFList = [ordered]@{
	"Internet Explorer 11" = "Internet-Explorer-Optional-amd64"
	"Media Features"       = "MediaPlayback"
	"Windows Media Player" = "WindowsMediaPlayer"
}

$enableFList = [ordered]@{
	".NET Framework 3.5" = "NetFx3"
	"Windows Sandbox"    = "Containers-DisposableClientVM"
}

function Set_Optional_Feature () {

	Write-Host "SET OPTIONAL FEATURES`n---------------------"
	$ListToDisable = @()
	foreach ($listKey in $disableFList.Keys) {
		
		$messageS = "Disable Feature $listKey"
		$selectedFeature = Add-ItemSelection $messageS $disableFList[$listKey]
		if ($selectedFeature) {
			$ListToDisable += $selectedFeature
		}
	}

	$ListToEnable = @()
	foreach ($listKey in $enableFList.Keys) {
		
		$messageS = "Enable Feature $listKey"
		$selectedFeature = Add-ItemSelection $messageS $enableFList[$listKey]
		if ($selectedFeature) {
			$ListToEnable += $selectedFeature
		}
	}
	Write-Host "`n===================="
	Write-Host "  SELECTED FEATURE  "
	Write-Host "===================="
	Write-Host "$ListToDisable $ListToEnable`n"
	foreach ($featureId in $ListToDisable) {
		ConfigFeature $featureId Disabled
	}

	foreach ($featureId in $ListToEnable) {
		ConfigFeature $featureId Enabled
	}
}

# Modification #: Configure Install App
# winget list
# winget upgrade --include-unknown
function InstallApp ($appId, $sourceType) {
	$listCmd = "$sourceType list $appId"
	$GetOutput = Invoke-Expression $listCmd -ErrorAction SilentlyContinue
	$installed = $GetOutput | Where-Object { $_.contains("$appId") }
	
	if ( -not $installed ) {
		
		Write-Host "App [$appId] not found, Installing..."
		Invoke-Expression "$sourceType install `"$appId`""
	} 
	else {
		Write-Host "App [$appId] Already Installed."
		Write-Host "Found an existing package already installed."
	}
}

$wingetList = [ordered]@{
	"Visual C++ 2010(x86)"        = "Microsoft.VCRedist.2010.x86"
	"Visual C++ 2010(x64)"        = "Microsoft.VCRedist.2010.x64"
	# "Visual C++ 2012(x86)"        = "Microsoft.VCRedist.2012.x86"
	# "Visual C++ 2012(x64)"        = "Microsoft.VCRedist.2012.x64"
	"Visual C++ 2015+(x86)"       = "Microsoft.VCRedist.2015+.x86"
	"Visual C++ 2015+(x64)"       = "Microsoft.VCRedist.2015+.x64"
	"Bitwarden"                   = "Bitwarden.Bitwarden"
	"Firefox Browser"             = "Mozilla.Firefox"
	"Vivaldi Browser"             = "Vivaldi.Vivaldi"
	"OperaGX Browser"             = "Opera.OperaGX"
	# "Microsoft Edge"              = "Microsoft.Edge"
	"ZoomIt"                      = "Microsoft.Sysinternals.ZoomIt"
	"Energy Star X"               = "9NF7JTB3B17P"
	"Microsoft PC Manager"        = "9PM860492SZD"
	"AutoHotkey"                  = "AutoHotkey.AutoHotkey"
	"Everything x64"              = "voidtools.Everything"
	"QuickLook"                   = "QL-Win.QuickLook"                     # USO TEMPORAL
	"Quick Share Google"          = "Google.QuickShare"
	"PowerToys (Preview)"         = "Microsoft.PowerToys"
	"7-Zip"                       = "7zip.7zip"
	"WinRAR"                      = "RARLab.WinRAR"
	"Google Drive"                = "Google.GoogleDrive"
	"TeraBox Desktop"             = "Baidu.TeraBox"
	"Notepad++"                   = "Notepad++.Notepad++"
	"GIMP"                        = "GIMP.GIMP"
	"Audacity"                    = "Audacity.Audacity"
	"IrfanView x64"               = "IrfanSkiljan.IrfanView"
	"VLC Media Player"            = "VideoLAN.VLC"
	"SumatraPDF"                  = "SumatraPDF.SumatraPDF"
	"Microsoft 365 Apps"          = "Microsoft.Office"
	"OnlyOffice"                  = "ONLYOFFICE.DesktopEditors"
	"LibreOffice LTS"             = "TheDocumentFoundation.LibreOffice.LTS"
	"Steam Launcher"              = "Valve.Steam"
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
	# "MiniTool Partition Wizard"   = "MiniTool.PartitionWizard.Free"
	"PuTTY"                       = "PuTTY.PuTTY"
	"WinSCP"                      = "WinSCP.WinSCP"
	"TeamViewer"                  = "TeamViewer.TeamViewer"
	"Oracle VM VirtualBox"        = "Oracle.VirtualBox"
	# "VMware Workstation Pro"      = "VMware.???"
	"FxSound"                     = "FxSoundLLC.FxSound"
	"Fan Control"                 = "Rem0o.FanControl"
	"MSI Afterburner"             = "Guru3D.Afterburner"
	"TechPowerUp GPU-Z"           = "TechPowerUp.GPU-Z"
	"WinDirStat"                  = "WinDirStat.WinDirStat"
	"BleachBit"                   = "BleachBit.BleachBit"
	# "NVCleanstall"                = "TechPowerUp.NVCleanstall"
	"Recuva"                      = "Piriform.Recuva"
	"Visual Studio Code"          = "Microsoft.VisualStudioCode"           # revisar opcion seteada
	"Git"                         = "Git.Git"
	"Neovim"                      = "Neovim.Neovim"
	"Java SDK"                    = "Oracle.JDK.22"
	"Python 3.12"                 = "Python.Python.3.12"
	"Rust (MSVC)"                 = "Rustlang.Rust.MSVC"                   # (v1.79.0)
	# "Rustup: toolchain"           = "Rustlang.Rustup"
	"Node.js LTS"                 = "OpenJS.NodeJS.LTS"
	"GitHub Desktop"              = "GitHub.GitHubDesktop"
	"Visual Studio Community"     = "Microsoft.VisualStudio.2022.Community"
	"Apache NetBeans IDE"         = "Apache.NetBeans"
	"Android Studio"              = "Google.AndroidStudio"
	"MySQL"                       = "Oracle.MySQL"
	# "PostgreSQL 16"               = "PostgreSQL.PostgreSQL.16"           # revisar compilacion seteada
	# "SQLServer Express"           = "Microsoft.SQLServer.2022.Express"
	"SQLServer Management Studio" = "Microsoft.SQLServerManagementStudio"
	"Docker Desktop"              = "Docker.DockerDesktop"
	# "Windows Terminal"            = "Microsoft.WindowsTerminal"
}

$chocoList = [ordered]@{
	"AIMP Music Player"   = "aimp"
	"Keypirinha Launcher" = "keypirinha"
	"FileZilla Client"    = "filezilla"
	"Fing Desktop"        = "fing"
}

function Install_Apps () {

	Write-Host "INSTALL APP`n-----------"
	$ListToInstallW = @()
	foreach ($listKey in $wingetList.Keys) {
		
		$messageS = "Install App $listKey"
		$selectedApp = Add-ItemSelection $messageS $wingetList[$listKey]
		if ($selectedApp) {
			$ListToInstallW += $selectedApp
		}
	}

	$ListToInstallC = @()
	foreach ($listKey in $chocoList.Keys) {
		
		$messageS = "Install App $listKey"
		$selectedApp = Add-ItemSelection $messageS $chocoList[$listKey]
		if ($selectedApp) {
			$ListToInstallC += $selectedApp
		}
	}
	Write-Host "`n================"
	Write-Host "  SELECTED APP  "
	Write-Host "================"
	if ( $ListToInstallW.Count -gt 0) {

		Write-Host "Winget Packages: $ListToInstallW"
		Start-Process "winget" -ArgumentList "install $ListToInstallW" -NoNewWindow -Wait
		# winget install $ListToInstallW
	}

	if ( $ListToInstallC.Count -gt 0 ) {
		
		Write-Host "Choco Packages: $ListToInstallC"
		Start-Process "choco" -ArgumentList "install $ListToInstallC" -NoNewWindow -Wait
		# choco install $ListToInstallC
	}
	Write-Host "Finished"
	# foreach ($appId in $ListToInstallW) {
	# 	InstallApp $appId winget
	# }

	# foreach ($appId in $ListToInstallC) {
	# 	InstallApp $appId choco
	# }
}

# Modification #: Configure Download App Portable
function DownloadApp ($toolUrl, $toolFile) {
	$pathLocation = "$env:USERPROFILE\Documents"
	$item = 'APP-PC' # 'APP-TOOLS'
	$filePath = "$pathLocation\$item\$toolFile"
	
	Test-ItemPath $pathLocation $item "Directory"

	if ( -not (Test-Path -Path $filePath) ) {
		
		Write-Host "Tool [$toolFile] not found, Downloading...`nUrl: $toolUrl" -ForegroundColor Blue -NoNewline
		Invoke-WebRequest -Uri $toolUrl -OutFile $filePath
		Get-ChildItem $filePath | Format-List -Property Mode, LastAccessTime, Length, Name
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

function Download_Tools () {
	
	Write-Host "Url Search Tools`n------------------"
	$ListToDownload = @()
	foreach ($toolData in $toolList) {

		$messageS = "Download App $($toolData.Name)"
		$selectedApp = Add-ItemSelection $messageS $toolData
		if ($selectedApp) {
			$ListToDownload += $selectedApp
		}
	}
	Write-Host "`n================="
	Write-Host "  SELECTED TOOL  "
	Write-Host "================="
	Write-Host "$ListToDownload`n"
	foreach ($toolId in $ListToDownload) {
		DownloadApp $toolId.TUrl $toolId.File
	}
}

# Modification #: Configure custom system in Windows
function InstallModule ($moduleName) {
	$modComand = if ( $moduleName -eq "Terminal-Icons" ) { " -Repository PSGallery" } else { "" }
	
	if ( -not (Get-Module -ListAvailable -Name $moduleName) ) {
		Write-Host "Module [$moduleName] not found, Installing..."
		
		Invoke-Expression 'Install-Module -Name ' + $moduleName + $modComand + ' -Force'
		Write-Host "Module [$moduleName] has been Installed."
	} 
	else {
		Write-Host "Module [$moduleName] found, Already Exists."
		Write-Host "Module [$moduleName] remains Installed."
	}
}

function ActivateModule ($moduleName) {

	$iconsComand = "Import-Module -Name $moduleName"
	if ( -not (Get-Module -Name $moduleName) ) {
		
		Write-Host "Module [$moduleName] disable, Activating..."
		Invoke-Expression $iconsComand
	} 
	else {
		Write-Host "Module [$moduleName] remains Activated."
	}

	return $iconsComand
}

function Install_PromptT {
	param (
		[string]$themeName
	)

	# Instalar Oh-My-Posh en la terminal
	Write-Host "Prompt Oh-My-Posh`n-----------------"
	InstallApp "JanDeDobbeleer.OhMyPosh" winget
	Write-Host ""
	
	# Iniciar Oh-My-Posh en la terminal
	$initPrompt = 'oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\' + $themeName + '.omp.json"'
	$activatePrompt = Invoke-Expression $initPrompt
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Initializing...`n$initPrompt`n"
	
	# Activar Oh-My-Posh en la terminal
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Activating...`n$activatePrompt`n"
	
	return $activatePrompt
}

function Install_ModuleT {
	
	# MyTheme 7.2: Module Terminal-Icons	
	Write-Host "PS Module TerminalIcons`n-----------------------"
	InstallModule "Terminal-Icons"
	$iconsComand = ActivateModule "Terminal-Icons"
	Write-Host ""
	
	# MyTheme 7.2: Module z
	Write-Host "PS Module Z`n-----------"
	InstallModule "z"
	Write-Host ""

	return $iconsComand
}

function Enable_ListViewT {
	
	$modeName = 'ListView'
	$option = Get-PSReadLineOption | Where-Object { $_.PredictionViewStyle -notlike "$modeName" }

	Write-Host "PS Option PredictionStyle`n-------------------------"
	$predictionComand = "Set-PSReadLineOption -PredictionViewStyle $modeName"
	if ($option) {
		
		Write-Host "Setting option [PredictionViewStyle], Changing..."
		Invoke-Expression $predictionComand
	}
	else {
		Write-Host "Option [PredictionViewStyle] remains Changed."
	}
	Write-Host ""

	return $predictionComand
}

function Test-FileContent {
	param (
		[string]$filePath,
		[string]$valueToCompare,
		[string]$valueToAdd
	)
	# Lee el contenido del archivo de perfil en una variable
	$fileContent = Get-Content -Path $filePath -Raw
	# Reduce el comando de ejecucion a un Alias
	$addContent = { Add-Content -Path $filePath -Value $args[0] }

	if ( -not ($fileContent -match [regex]::escape($valueToCompare)) ) {

		Write-Host "String not found, Adding..." -ForegroundColor Yellow
		& $addContent $valueToAdd
	}
}

# MyTheme 7.5: Agregar imagen de fondo
function Test_ImagePath {
	param (
		[string]$localPath,
		[string]$httpsPath
	)

	if ( -not (Test-Path -Path $localPath) ) {

		Write-Host "File not found, Downloading..." -ForegroundColor Yellow
		Invoke-WebRequest -Uri $httpsPath -OutFile $localPath
	}
}

function Set_BackgroundType {
	$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers'
	$property = 'BackgroundType'
	$value = 0

	# Option change value
	"Enable [Picture] for Background."
	Set-OptionValue $path $property $value
}

function Set_BackgroundImage ( $regeditPath, $property, $filePath ) {

	if ( (Get-ItemProperty -Path $regeditPath).$property -notlike $filePath ) {

		Write-Host "Setting value [$property], Changing..."
		Set-ItemProperty -Path $regeditPath -Name $property -Value $filePath -Force
	} 
	else {
		Write-Host "Value [$property] remains Changed."
	}
}

function Set_FitType {
	$path = 'HKCU:\Control Panel\Desktop'
	$property = 'WallpaperStyle'
	$value = 10  #value = 2 ; option = Stretch

	# Option change value
	"Enable [Fill] for Desktop Image."
	Set-OptionValue $path $property $value
}

function Custom_Background_Picture () {

	# Change to Picture
	Write-Host "Background Type`n---------------"
	Set_BackgroundType

	$filePath = "$env:USERPROFILE\Pictures\wallpaperbetter-3840-2160-3.jpg"
	$webPath = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/wallpaperbetter-3840-2160-3.jpg"

	Test_ImagePath $filePath $webPath

	# Change current picture
	Write-Host "`nBackground Image`n----------------"
	Set_BackgroundImage "HKCU:\Control Panel\Desktop" "WallPaper" $filePath
	
	# Show File
	Get-ChildItem $filePath | Format-List

	# Change to a Fill
	Write-Host "Fit Type`n--------"
	Set_FitType
}

function Custom_Shell_Pwsh () {

	$activatePrompt = Install_PromptT "kushal"
	$iconsComand = Install_ModuleT
	$predictionComand = Enable_ListViewT

	# Create File
	Write-Host "PROFILE Shell`n-------------"
	Write-Host "[*] Current File not found, Creating...   : Microsoft.PowerShell_profile.ps1"
	
	$PROFILE_TEMP1 = "$env:USERPROFILE\Documents\PowerShell"
	Test-ItemPath $PROFILE_TEMP1 "Microsoft.PowerShell_profile.ps1" "File"
	$PROFILE_PATH_1 = "$PROFILE_TEMP1\Microsoft.PowerShell_profile.ps1"

	# Show File
	Get-ChildItem $PROFILE_PATH_1
	"+- Message ------------------------------+"
	"|    A new file has not been created!    |"
	"+----------------------------------------+`n"

	# Add Content
	Write-Host "[*] Current File found, Adding Content... : $((Get-ChildItem $PROFILE_PATH_1).Name)"

	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test-FileContent $PROFILE_PATH_1 $stringReduce $activatePrompt
	Test-FileContent $PROFILE_PATH_1 $iconsComand $iconsComand
	Test-FileContent $PROFILE_PATH_1 $predictionComand $predictionComand

	# Show Content
	Write-Host "`n$(Get-Content -Path $PROFILE_PATH_1 -Raw)" -ForegroundColor Cyan -NoNewline
	"+- Message ------------------------------+"
	"|   The content was added to the file!   |"
	"+----------------------------------------+"
}

function Custom_Shell_Powershell () {
	
	$activatePrompt = Install_PromptT "kali"

	# Create File
	Write-Host "PROFILE Shell`n-------------"
	Write-Host "[*] Current File not found, Creating...   : Microsoft.PowerShell_profile.ps1"

	$PROFILE_TEMP2 = "$env:USERPROFILE\Documents\WindowsPowerShell"
	Test-ItemPath $PROFILE_TEMP2 "Microsoft.PowerShell_profile.ps1" "File"
	$PROFILE_PATH_2 = "$PROFILE_TEMP2\Microsoft.PowerShell_profile.ps1"

	# Show File
	Get-ChildItem $PROFILE_PATH_2
	"+- Message ------------------------------+"
	"|    A new file has not been created!    |"
	"+----------------------------------------+`n"

	# Add Content
	Write-Host "[*] Current File found, Adding Content... : $((Get-ChildItem $PROFILE_PATH_2).Name)"

	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test-FileContent $PROFILE_PATH_2 $stringReduce $activatePrompt

	# Show Content
	Write-Host "`n$(Get-Content -Path $PROFILE_PATH_2 -Raw)" -ForegroundColor Cyan -NoNewline
	"+- Message ------------------------------+"
	"|   The content was added to the file!   |"
	"+----------------------------------------+"
}

function Install_PromptC {
	param (
		[string]$themeName
	)

	# Instalar Clink en la terminal
	Write-Host "App Clink`n---------"
	InstallApp "chrisant996.Clink" winget          # (clink set clink.logo none)
	Write-Host ""

	# Instalar Oh-My-Posh en la terminal
	Write-Host "Prompt Oh-My-Posh`n-----------------"
	InstallApp "JanDeDobbeleer.OhMyPosh" winget
	Write-Host ""

	# Iniciar Oh-My-Posh en la terminal
	$initPrompt = 'oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\' + $themeName + '.omp.json"'
	$null = Invoke-Expression $initPrompt
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Initializing...`n$initPrompt`n"

	# Cargar Oh-My-Posh en la terminal
	$env:POSH_THEMES_PATH_TEMP = $env:POSH_THEMES_PATH -replace '\\', '/'
	$loadPrompt = "load(io.popen('oh-my-posh.exe --config=`"$env:POSH_THEMES_PATH_TEMP/$themeName.omp.json`" --init --shell cmd'):read(`"*a`"))()"
	Write-Host "App [JanDeDobbeleer.OhMyPosh] Loading Config...`n$loadPrompt`n"

	return $loadPrompt
}

function Custom_Shell_Cmd () {

	$addComment = "-- oh-my-posh.lua"
	$loadPrompt = Install_PromptC "stelbent.minimal"

	# Create File
	Write-Host "PROFILE Shell`n-------------"
	Write-Host "[*] Current File not found, Creating...   : oh-my-posh.lua"

	$PROFILE_TEMP3 = "$env:LOCALAPPDATA\clink"
	Test-ItemPath $PROFILE_TEMP3 "oh-my-posh.lua" "File"
	$PROFILE_PATH_3 = "$PROFILE_TEMP3\oh-my-posh.lua"

	# Show File
	Get-ChildItem $PROFILE_PATH_3
	"+- Message ------------------------------+"
	"|    A new file has not been created!    |"
	"+----------------------------------------+`n"
	
	# Add Content
	Write-Host "[*] Current File found, Adding Content... : $((Get-ChildItem $PROFILE_PATH_3).Name)"

	Test-FileContent $PROFILE_PATH_3 $addComment $addComment
	Test-FileContent $PROFILE_PATH_3 $loadPrompt $loadPrompt

	# Show Content
	Write-Host "`n$(Get-Content -Path $PROFILE_PATH_3 -Raw)" -ForegroundColor Cyan -NoNewline
	"+- Message ------------------------------+"
	"|   The content was added to the file!   |"
	"+----------------------------------------+"
}

#####################################################
#	PRINT_MENUS
#####################################################

# drawing SubMenu1
function Show-SubMenu1 {
	Write-Host ""
	"╔════════════════════════════╗"
	"║         SUB-MENU-1         ║"
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
	Write-Host ""
	"╔════════════════════════════╗"
	"║         SUB-MENU-2         ║"
	"╠════════════════════════════╣"
	"║ [1] Privacy & Security     ║"
	"║ [2] WindowsUpdate Behavior ║"
	"║ [3] Performance Mode       ║"
	"║ [4] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu3
function Show-SubMenu3 {
	Write-Host ""
	"╔════════════════════════════╗"
	"║         SUB-MENU-3         ║"
	"╠════════════════════════════╣"
	"║ [1] Remove Capability      ║"
	"║ [2] Remove Package         ║"
	"║ [3] Remove Provisioned     ║"
	"║ [4] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu4
function Show-SubMenu4 {
	Write-Host ""
	"╔════════════════════════════╗"
	"║         SUB-MENU-4         ║"
	"╠════════════════════════════╣"
	"║ [1] Install App            ║"
	"║ [2] Download Tool          ║"
	"║ [3] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu4
function Show-SubMenu5 {
	Write-Host ""
	"╔════════════════════════════╗"
	"║         SUB-MENU-5         ║"
	"╠════════════════════════════╣"
	"║ [1] Customize background   ║"
	"║ [2] Customize pwsh         ║"
	"║ [3] Customize powershell   ║"
	"║ [4] Customize cmd          ║"
	"║ [5] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing MainMenu
function Show-MainMenu {
	Write-Host ""
	"        $WPName $WPVersion      "
	"╔══════════════════════════════╗"
	"║          MAIN-MENU           ║"
	"╠══════════════════════════════╣"
	"║ [1] Change Preferences       ║"
	"║ [2] Essential Tweaks         ║"
	"║ [3] Remove Bloatware         ║"
	"║ [4] Add Apps/Tools           ║"
	# "║ [5] Customize PowerPlan      ║"
	"║ [5] Customize System         ║"
	"║ [6] Exit                     ║"
	"╚══════════════════════════════╝"
}

#####################################################
#	MENU_OPTIONS
#####################################################

# call option SubMenu1
function Invoke-SubMenu1 () {

	Show-SubMenu1
	$optionMenu1 = Read-Host "Choose an option_1"
	
	switch ($optionMenu1) {
		1 {
			Clear-Host
			Write-Host "Set Options"
			Write-Host "Do you want to change the state?"

			Invoke-Confirmation { Set_Default_Option }
			break
		}
		2 {
			Clear-Host
			Write-Host "Set Services"
			Write-Host "Do you want to change the state?"

			Invoke-Confirmation { Set_Service_Startup }
			break
		}
		3 {
			Clear-Host
			Write-Host "Set ScheduledTasks"
			Write-Host "Do you want to change the state?"

			Invoke-Confirmation { Set_Scheduled_Task }
			break
		}
		4 {
			Clear-Host
			Write-Host "Set OptionalFeatures"
			Write-Host "Do you want to change the state?"

			Invoke-Confirmation { Set_Optional_Feature }
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
				Write-Warning "(Valor invalido)->Unknown value!"
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

			Invoke-Confirmation { Set_Privacy_Security }
			break
		}
		2 {
			Clear-Host
			Write-Host "Set Windows Update Behavior"
			Write-Host "Do you want enable Manual Update, disable Preliminary Updates & Product Updates?"

			Invoke-Confirmation { Set_Update_Behavior }
			break
		}
		3 {
			Clear-Host
			Write-Host "Set Performance Mode"
			Write-Host "Do you want enable the TRIM, MemoryCompression, Minimum VisualEffects. Change the CPU usage for Windows Defender?"

			Invoke-Confirmation { Set_Performance_Mode }
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
				Write-Warning "(Valor invalido)->Unknown value!"
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
			Write-Host "Remove AppCapabilityPackages"
			Write-Host "Do you want to remove App from the local host?"

			Invoke-Confirmation { Remove_Capability_App }
			break
		}
		2 {
			Clear-Host
			Write-Host "Remove AppxUserPackages"
			Write-Host "Do you want to remove Appx from the current user account?"

			Invoke-Confirmation { Remove_User_Appx }
			break
		}
		3 {
			Clear-Host
			Write-Host "Remove AppxProvisionedPackages"
			Write-Host "Do you want to remove Appx from Windows image?"

			Invoke-Confirmation { Remove_Provisioned_Appx }
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
				Write-Warning "(Valor invalido)->Unknown value!"
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

			Invoke-Confirmation { Install_Apps }
			break
		}
		2 {
			Clear-Host
			Write-Host "Download Tools"
			Write-Host "Do you want to download Tools?"

			# Invoke-Confirmation { Download_Tools }
			"`nFuncion [Download_Tools] en mantenimiento... :3`n"
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
				Write-Warning "(Valor invalido)->Unknown value!"
				break
			} while ( $optionMenu4 -lt 1 -or $optionMenu4 -gt 3 )
			Invoke-SubMenu4
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-SubMenu4
}

# call option SubMenu5
function Invoke-SubMenu5 () {

	Show-SubMenu5
	$optionMenu5 = Read-Host "Choose an option_5"

	switch ($optionMenu5) {
		1 {
			Clear-Host
			Write-Host "Customize background"
			Write-Host "Do you want to customize background?"

			Invoke-Confirmation { Custom_Background_Picture }
			break
		}
		2 {
			Clear-Host
			Write-Host "Customize pwsh"
			Write-Host "Do you want to customize pwsh?"

			Invoke-Confirmation { Custom_Shell_Pwsh }
			break
		}
		3 {
			Clear-Host
			Write-Host "Customize powershell"
			Write-Host "Do you want to customize powershell?"

			Invoke-Confirmation { Custom_Shell_Powershell }
			break
		}
		4 {
			Clear-Host
			Write-Host "Customize cmd"
			Write-Host "Do you want to customize cmd?"

			Invoke-Confirmation { Custom_Shell_Cmd }
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
				Write-Warning "(Valor invalido)->Unknown value!"
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
			& { $null = Test-ModuleDism } 6> $null
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
			& { $null = Test-ModuleDism } 6> $null
			# Test-WinVersion -Operation { Test-ModuleAppx } -OSNumber 10;
			Invoke-SubMenu3
			Break
		}
		4 {
			Clear-Host
			Invoke-SubMenu4
			break
		}
		<#
		0 {
			Clear-Host
			Write-Host "Customize Power Plan"
			Write-Host "Do you want to customize your Power Plan?"

			# Invoke-Confirmation { Set_Power_Plan }
			"`nFuncion [Set_Power_Plan] en desarrollo... :3`n"
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
				Write-Warning "(Valor invalido)->Unknown value!"
				break
			} while ( $optionMenu -lt 1 -or $optionMenu -gt 6 )
			Invoke-MainMenu
		}
	}
	Write-Host "Press any key to continue..."; Read-Host
	Clear-Host
	Invoke-MainMenu
}

#####################################################
#	MAIN_FUNCTION
#####################################################

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
		return "-Command `"irm $WPRepository | iex`""
	}
}

# Test Rol Admin
function Test-CurrentRol {
	$userCurrent = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	$roleCurrent = ([Security.Principal.WindowsBuiltInRole] "Administrator")
	
	$adminCondition = $userCurrent.IsInRole($roleCurrent)
	if ( -not $adminCondition ) {

		Write-Host "Checking if Rol is Administrator..."
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

		$wingetCondition = winget upgrade --include-unknown --accept-source-agreements --accept-package-agreements
	} 
	catch {

		Write-Error "ERROR: $_"
		Write-Host "Checking if PM Winget is Installed..."
		$packageFile = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
		$packageUrl = "https://github.com/microsoft/winget-cli/releases/download/v1.8.1911/$packageFile"
		
		if( $null -eq (Get-AppxPackage | Where-Object { $_.Name -like "*Microsoft.VCLibs.140.00*" }) ) {

			Write-Host " -Downloading dependencies VCLibs" -ForegroundColor Yellow
			Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "Microsoft.VCLibs.x64.14.00.Desktop.appx"
			Add-AppxPackage -Path "Microsoft.VCLibs.x64.14.00.Desktop.appx"
		}
		
		if( $null -eq (Get-AppxPackage | Where-Object { $_.Name -like "*Microsoft.UI.Xaml.2.8*" }) ) {

			Write-Host " -Downloading dependencies UI.Xaml" -ForegroundColor Yellow
			Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -OutFile "Microsoft.UI.Xaml.2.8.x64.appx"
			Add-AppxPackage -Path "Microsoft.UI.Xaml.2.8.x64.appx"
		}

		if ( -not $wingetCondition ) {

			Write-Host " -Installing the package manager Winget" -ForegroundColor Yellow
			Invoke-WebRequest -Uri $packageUrl -OutFile "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
			Add-AppxPackage -Path "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
		}
	}
}

# Test Winget
function Test-WingetOption {
	
	Write-Host " -Updating the package AppInstaller" -ForegroundColor Yellow
	# winget upgrade "9NBLGGH4NNS1"
	# winget upgrade "Microsoft.AppInstaller"
}

# Test Choco
function Test-ChocoVersion {
	try {

		$chocoCondition = choco --version
	} 
	catch {

		Write-Error "ERROR: $_"
		Write-Host "Checking if PM Chocolatey is Installed..."

		if ( -not $chocoCondition ) {

			Write-Host " -Installing the package manager Chocolatey" -ForegroundColor Yellow
			Set-ExecutionPolicy Bypass -Scope Process -Force; 
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
			Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
		}
	}
}

# Test Choco Feature
function Test-ChocoFeature {
	$featureList = choco feature list
	$featureCurrent = "\[x\] allowGlobalConfirmation"
	
	$featureCondition = $featureList -match $featureCurrent
	if ( -not $featureCondition ) {
		
		Write-Host "Checking if allowGlobalConfirmation is Enabled..."
		Write-Host " -Enabling feature allowGlobalConfirmation" -ForegroundColor Yellow
		choco feature enable -n allowGlobalConfirmation
	}
}

# Test PowerShell
function Test-PwshVersion {
	try {

		$pwshCondition = pwsh --version
	} 
	catch {
		
		Write-Error "ERROR: $_"
		Write-Host "Checking if Shell pwsh is Installed..."
		$pwshPackage = "Microsoft.PowerShell"

		if ( -not $pwshCondition ) {

			Write-Host " -Installing the shell PowerShell Core" -ForegroundColor Yellow
			InstallApp $pwshPackage winget
		}
	}
}

Clear-Host
$Host.UI.RawUI.WindowTitle = "Dead Script [ x__x ]"

# Checking if Winget is installed
Test-WingetVersion

# Checking if All Sources were Accepted
Test-WingetOption

# Checking if Chocolatey is installed
Test-ChocoVersion

# Checking if allowGlobalConfirmation is Enabled
Test-ChocoFeature

# Checking if Shell pwsh is installed
Test-PwshVersion

# Checking if Rol is Administrator
Test-CurrentRol

# Establecer la página de códigos a UTF-8
chcp 65001 > $null

# Invoke the Main Menu the Script.
Invoke-MainMenu

# Sleep for 2 seconds
Start-Sleep -Milliseconds 3000

# Policy Execution Restart
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "CurrentUser" -Force
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "Process" -Force
