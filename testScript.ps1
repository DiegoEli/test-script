
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
		$null = New-Item -Path $itemPath -Name $itemName -ItemType $itemType -Force
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

Add-Type -AssemblyName PresentationFramework

function GenerateWinGUI ($varTitle, $varAction) {
	
	# XAML básico sin CheckBoxes
	$XAML = @"
	<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
			Title="Dead Script 💀" 
			Height="430" Width="390" Background="#1A1A1A" Foreground="White" 
			FontFamily="Cascadia Mono" FontSize="12" FontWeight="Bold"
			WindowStartupLocation="CenterScreen">
		<StackPanel>
			<!-- Titulo que desribira que se hace -->
			<TextBlock Text="$varTitle" Margin="10"/>
			
			<!-- Marco (Border) con ScrollViewer para los CheckBox -->
			<Border BorderBrush="Gray" BorderThickness="1" Margin="10" Padding="10" CornerRadius="7">
				<ScrollViewer VerticalScrollBarVisibility="Auto" Height="260">
					<StackPanel Name="ListContainer"></StackPanel>
				</ScrollViewer>
			</Border>
			
			<!-- Botón de Selección -->
			<Button Content="$varAction" Height="30" Width="100" Background="LightGray" Foreground="Black" 
					Name="ActionButton" BorderBrush="Transparent" HorizontalAlignment="Center" Margin="10"/>
		</StackPanel>
	</Window>
"@
	
	# Cargar la interfaz
	$reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
	$window = [Windows.Markup.XamlReader]::Load($reader)
	
	return $window
}

function GenerateWinGUITriple ($varTitle, $varAction) {
	
	# XAML básico sin CheckBoxes
	$XAML = @"
	<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
			Title="Dead Script 💀" 
			Height="430" Width="910" Background="#1A1A1A" Foreground="White" 
			FontFamily="Cascadia Mono" FontSize="12" FontWeight="Bold"
			WindowStartupLocation="CenterScreen">
		<StackPanel>
			<!-- Titulo que describe qué se hace -->
			<TextBlock Text="$varTitle" Margin="10" TextWrapping="Wrap"/>
		
			<!-- Panel principal con dos columnas -->
			<Grid Margin="5">
				<Grid.ColumnDefinitions>
					<ColumnDefinition Width="*" />
					<ColumnDefinition Width="*" />
					<ColumnDefinition Width="*" />
				</Grid.ColumnDefinitions>
			
				<!-- Panel de Lista 1 -->
				<Border Grid.Column="0" BorderBrush="Gray" BorderThickness="1" Margin="5" Padding="10" CornerRadius="7">
					<ScrollViewer VerticalScrollBarVisibility="Auto" Height="260">
						<StackPanel Name="ListContainer1"></StackPanel>
					</ScrollViewer>
				</Border>
			
				<!-- Panel de Lista 2 -->
				<Border Grid.Column="1" BorderBrush="Gray" BorderThickness="1" Margin="5" Padding="10" CornerRadius="7">
					<ScrollViewer VerticalScrollBarVisibility="Auto" Height="260">
						<StackPanel Name="ListContainer2"></StackPanel>
					</ScrollViewer>
				</Border>

				<!-- Panel de Lista 3 -->
				<Border Grid.Column="3" BorderBrush="Gray" BorderThickness="1" Margin="5" Padding="10" CornerRadius="7">
					<ScrollViewer VerticalScrollBarVisibility="Auto" Height="260">
						<StackPanel Name="ListContainer3"></StackPanel>
					</ScrollViewer>
				</Border>
			</Grid>
		
			<!-- Botón de Selección -->
			<Button Content="$varAction" Height="30" Width="100" Background="LightGray" Foreground="Black" 
					Name="ActionButton" BorderBrush="Transparent" HorizontalAlignment="Center" Margin="10"/>
		</StackPanel>
	</Window>
"@
	
	# Cargar la interfaz
	$reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
	$window = [Windows.Markup.XamlReader]::Load($reader)
	
	return $window
}

function GenerateWinGUIShell ($varTitle, $varAction) {
	
	$XAML = @"
	<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
			Title="Dead Script 💀" 
			Height="430" Width="810" Background="#1A1A1A" Foreground="White" 
			FontFamily="Cascadia Mono" FontSize="12" FontWeight="Bold" 
			WindowStartupLocation="CenterScreen">
		<StackPanel>
			<!-- Titulo que describe qué se hace -->
			<TextBlock Text="$varTitle" Margin="10" TextWrapping="Wrap"/>
		
			<!-- Panel principal con dos columnas -->
			<Grid Margin="5">
				<Grid.ColumnDefinitions>
					<ColumnDefinition Width="*" />
					<ColumnDefinition Width="*" />
					<ColumnDefinition Width="*" />
				</Grid.ColumnDefinitions>
			
				<!-- Panel de Lista 1 -->
				<Border Grid.Column="0" BorderBrush="Gray" BorderThickness="1" Margin="5" Padding="10" CornerRadius="7">
					<StackPanel Height="260">
						<TextBlock Name="TextBlock1" Margin="5,2,5,2" TextWrapping="Wrap"/>
						<CheckBox Name="CheckBox1" Margin="5,2,5,2" Foreground="White"/>
					</StackPanel>
				</Border>
			
				<!-- Panel de Lista 2 -->
				<Border Grid.Column="1" BorderBrush="Gray" BorderThickness="1" Margin="5" Padding="10" CornerRadius="7">
					<StackPanel Height="260">
						<TextBlock Name="TextBlock2" Margin="5,2,5,2" TextWrapping="Wrap"/>
						<CheckBox Name="CheckBox2" Margin="5,2,5,2" Foreground="White"/>
					</StackPanel>
				</Border>
				
				<!-- Panel de Lista 3 -->
				<Border Grid.Column="2" BorderBrush="Gray" BorderThickness="1" Margin="5" Padding="10" CornerRadius="7">
					<StackPanel Height="260">
						<TextBlock Name="TextBlock3" Margin="5,2,5,2" TextWrapping="Wrap"/>
						<CheckBox Name="CheckBox3" Margin="5,2,5,2" Foreground="White"/>
					</StackPanel>
				</Border>
			</Grid>
		
			<!-- Botón de Selección -->
			<Button Content="$varAction" Height="30" Width="100" Background="LightGray" Foreground="Black" 
					Name="ActionButton" BorderBrush="Transparent" HorizontalAlignment="Center" Margin="10"/>
		</StackPanel>
	</Window>
"@

    # Cargar la interfaz
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    return $window
}

function GenerateCheckBox ($currentList, $window, $listContainerName) {
	
	# Generar CheckBoxes dinámicamente y registrarlos en el objeto $window
	foreach ($item in $currentList) {
		$checkBox = New-Object System.Windows.Controls.CheckBox
		$checkBox.Content = $item.ShowInGUI
		$checkBox.Name = $item.IsXamlId
		$checkBox.Foreground = 'White'
		$checkBox.FontWeight = 'Regular'
		$window.FindName($listContainerName).Children.Add($checkBox)
		$window.RegisterName($item.IsXamlId, $checkBox)  # Registrar el CheckBox
	}
	
	return $checkBox
}

function GenerateTextBlock ($currentText, $checkBoxText, $window, $textBlockName, $checkBoxName) {
	
	$window.FindName($textBlockName).Text = $currentText
	$window.FindName($checkBoxName).Content = $checkBoxText
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

	#"Hide Option Hibernate"
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

function Opt_WiFiSense {
	$wifiPath = ''
	$property = ''
	$value = 00
	
	# Option change value
	Set-OptionValue $wifiPath $property $value
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

$optionList = @(
	@{ ShowInGUI = "Enable Auto Logon"; IsXamlId = "AutoLogon"; IsOperation = "Opt_AutoLogon" }
	@{ ShowInGUI = "Disable Fast Startup"; IsXamlId = "FastStartup"; IsOperation = "Opt_FastStartup" }
	@{ ShowInGUI = "Enable Verbose Logon Messages"; IsXamlId = "VerboseLogon"; IsOperation = "Opt_VerboseLogon" }
	@{ ShowInGUI = "Enable Show Version in Desktop"; IsXamlId = "ShowBuildVersion"; IsOperation = "Opt_ShowBuildVersion" }
	@{ ShowInGUI = "Disable Hibernate Mode (Only Desktop PC)"; IsXamlId = "HibernateMode"; IsOperation = "Opt_HibernateMode" }
	@{ ShowInGUI = "Disable Wi-Fi Sense (Only Desktop PC)"; IsXamlId = "WiFi_Sense"; IsOperation = "Opt_WiFiSense" }
	@{ ShowInGUI = "Disable Windows Startup Sound"; IsXamlId = "StartupSound"; IsOperation = "Opt_StartupSound" }
	@{ ShowInGUI = "Disable Adjust Volume of Sounds"; IsXamlId = "CommunicationsActivity"; IsOperation = "Opt_CommunicationsActivity" }
	@{ ShowInGUI = "Disable Pointer Precision"; IsXamlId = "MousePrecision"; IsOperation = "Opt_MousePrecision" }
	@{ ShowInGUI = "Disable Storage Sense"; IsXamlId = "StorageSense"; IsOperation = "Opt_StorageSense" }
	# @{ ShowInGUI = "Disable Device Encryption"; IsXamlId = "DeviceEncryption"; IsOperation = "Opt_DeviceEncryption" }
	@{ ShowInGUI = "Disable Suggest Snap"; IsXamlId = "SnapSuggest"; IsOperation = "Opt_SnapSuggest" }
	@{ ShowInGUI = "Enable Show File Extensions"; IsXamlId = "ShowFileExtensions"; IsOperation = "Opt_ShowFileExtensions" }
	@{ ShowInGUI = "Enable Show Hidden System Files"; IsXamlId = "ShowHiddenFiles"; IsOperation = "Opt_ShowHiddenFiles" }
	@{ ShowInGUI = "Disable Show Sync Provider"; IsXamlId = "ShowSyncProvider"; IsOperation = "Opt_ShowSyncProvider" }
	@{ ShowInGUI = "Enable End Task in Taskbar"; IsXamlId = "ShowEndTask"; IsOperation = "Opt_ShowEndTask" }
	# @{ ShowInGUI = "Enable Sudo Command"; IsXamlId = "SudoCommand"; IsOperation = "Opt_SudoCommand" }
	@{ ShowInGUI = "Enable Dark Mode"; IsXamlId = "DarkMode"; IsOperation = "Opt_DarkMode" }
	@{ ShowInGUI = "Enable Hide Item Search"; IsXamlId = "ShowItemSearch"; IsOperation = "Opt_ShowItemSearch" }
	@{ ShowInGUI = "Disable Show Item TaskView"; IsXamlId = "ShowItemTaskView"; IsOperation = "Opt_ShowItemTaskView" }
	@{ ShowInGUI = "Disable Hide the Taskbar"; IsXamlId = "HideTaskbar"; IsOperation = "Opt_HideTaskbar" }
	@{ ShowInGUI = "Enable Show the Desktop"; IsXamlId = "ShowDesktop"; IsOperation = "Opt_ShowDesktop" }
	@{ ShowInGUI = "Disable Show Language Bar"; IsXamlId = "ShowLanguageBar"; IsOperation = "Opt_ShowLanguageBar" }
	@{ ShowInGUI = "Enable Show Seconds in Clock"; IsXamlId = "ShowSeconds"; IsOperation = "Opt_ShowSeconds" }
	@{ ShowInGUI = "Disable Game Bar"; IsXamlId = "GameBar"; IsOperation = "Opt_GameBar" }
	@{ ShowInGUI = "Disable Game Mode"; IsXamlId = "GameMode"; IsOperation = "Opt_GameMode" }
	@{ ShowInGUI = "Remove Gallery Icon in Explorer"; IsXamlId = "GalleryIcon"; IsOperation = "Remove_GalleryIcon" }
	@{ ShowInGUI = "Remove System Icons in Desktop"; IsXamlId = "DesktopIcons"; IsOperation = "Remove_DesktopIcons" }
)

function Set_Default_Option () {

	$window = GenerateWinGUI "SELECCIONE LAS PREFERENCIAS" "Aplicar"
	$checkBox = GenerateCheckBox $optionList $window "ListContainer"
	
	$window.FindName("ActionButton").Add_Click({
		
		$ListToChanged = @()
		foreach ($listKey in $optionList) {
			$checkBox = $window.FindName($listKey.IsXamlId)
			if ($checkBox -and $checkBox.IsChecked) {
				$ListToChanged += $listKey.IsOperation
			}
		}
		
		Write-Host "==  SELECTED PREFERENCE  =="
		if ( $ListToChanged.Count -gt 0 ) {
			foreach ($Operation in $ListToChanged) {
				& $Operation
			}
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
		$window.Close()
	})
	
	$window.ShowDialog()
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

$privacyList = @(
	@{ ShowInGUI = "Disable Windows Spotlight"; IsXamlId = "Spotlight"; IsOperation = "Disable_Spotlight" }
	@{ ShowInGUI = "Disable Welcome Experience"; IsXamlId = "AdditionalSettings"; IsOperation = "Disable_AdditionalSettings" }
	@{ ShowInGUI = "Disable Get Facts, Tips, Trick"; IsXamlId = "GetTipsTricks"; IsOperation = "Disable_GetTipsTricks" }
	@{ ShowInGUI = "Disable Windows Start Info"; IsXamlId = "WinStartInfo"; IsOperation = "Disable_WinStartInfo" }
	@{ ShowInGUI = "Disable Personalize Ads"; IsXamlId = "PersonalizeAds"; IsOperation = "Disable_PersonalizeAds" }
	@{ ShowInGUI = "Disable Typing Personalization"; IsXamlId = "TypingPersonalization"; IsOperation = "Disable_TypingPersonalization" }
	@{ ShowInGUI = "Disable Diagnostic Data"; IsXamlId = "DiagnosticData"; IsOperation = "Disable_DiagnosticData" }
	@{ ShowInGUI = "Disable Activity History"; IsXamlId = "ActivityHistory"; IsOperation = "Disable_ActivityHistory" }
	@{ ShowInGUI = "Disable Cortana Results"; IsXamlId = "CortanaResults"; IsOperation = "Disable_CortanaResults" }
	@{ ShowInGUI = "Disable Web Results"; IsXamlId = "WebResults"; IsOperation = "Disable_WebResults" }
	@{ ShowInGUI = "Disable Local Results"; IsXamlId = "LocalResults"; IsOperation = "Disable_LocalResults" }
	@{ ShowInGUI = "Disable Location Tracking"; IsXamlId = "LocationTracking"; IsOperation = "Disable_LocationTracking" }
)

# function Set_Privacy_Security () {

# 	$window = GenerateWinGUI "SELECCIONE LOS AJUSTES DE PRIVACIDAD" "Aplicar"
# 	$checkBox = GenerateCheckBox $privacyList $window "ListContainer"

# 	$window.FindName("ActionButton").Add_Click({
		
# 		$ListToChanged = @()
# 		foreach ($listKey in $privacyList) {
# 			$checkBox = $window.FindName($listKey.IsXamlId)
# 			if ($checkBox -and $checkBox.IsChecked) {
# 				$ListToChanged += $listKey.IsOperation
# 			}
# 		}
		
# 		Write-Host "==  SELECTED PRIVACY TWEAKS  =="
# 		if ( $ListToChanged.Count -gt 0 ) {
# 			foreach ($Operation in $ListToChanged) {
# 				& $Operation
# 			}
# 		}
# 		Write-Host "=========================="
# 		Write-Host "  Operation are Finished  "
# 		Write-Host "=========================="
# 		$window.Close()
# 	})

# 	# Mostrar la interfaz
# 	$window.ShowDialog()
# }

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

$updateList = @(
	@{ ShowInGUI = "Disable Windows AutoUpdates"; IsXamlId = "WinAutoUpdates"; IsOperation = "Set_WinAutoUpdates" }
	@{ ShowInGUI = "Disable Preliminary Updates"; IsXamlId = "PreliminaryUpdates"; IsOperation = "Set_PreliminaryUpdates" }
	@{ ShowInGUI = "Enable Delay Security Updates"; IsXamlId = "DelaySecurityUpdates"; IsOperation = "Set_DelaySecurityUpdates" }
	@{ ShowInGUI = "Disable Get the latest Updates"; IsXamlId = "GetLatestUpdates"; IsOperation = "Set_GetLatestUpdates" }
	@{ ShowInGUI = "Disable Updates for other products"; IsXamlId = "UpdateOtherProduct"; IsOperation = "Set_UpdateOtherProduct" }
	@{ ShowInGUI = "Enable Active Hours of 06:00-23:00"; IsXamlId = "ActiveHours"; IsOperation = "Set_ActiveHours" }
	@{ ShowInGUI = "Disable Downloads from other PCs"; IsXamlId = "DownloadsOtherPCs"; IsOperation = "Set_DownloadsOtherPCs" }
	@{ ShowInGUI = "Disable Store AutoUpdates"; IsXamlId = "StoreAutoUpdates"; IsOperation = "Set_StoreAutoUpdates" }
	@{ ShowInGUI = "Limit reservable bandwidth"; IsXamlId = "LimitBandwidthUpdates"; IsOperation = "Set_LimitBandwidthUpdates" }
)

# function Set_Update_Behavior () {

# 	$window = GenerateWinGUI "SELECCIONE EL COMPORTAMIENTO DE LAS UPDATES" "Aplicar"
# 	$checkBox = GenerateCheckBox $updateList $window "ListContainer"

# 	$window.FindName("ActionButton").Add_Click({

# 		$ListToChanged = @()
# 		foreach ($listKey in $updateList) {
# 			$checkBox = $window.FindName($listKey.IsXamlId)
# 			if ($checkBox -and $checkBox.IsChecked) {
# 				$ListToChanged += $listKey.IsOperation
# 			}
# 		}

# 		Write-Host "==  SELECTED UPDATE BEHAVIOR  =="
# 		if ( $ListToChanged.Count -gt 0 ) {
# 			foreach ($Operation in $ListToChanged) {
# 				& $Operation
# 			}
# 		}
# 		Write-Host "=========================="
# 		Write-Host "  Operation are Finished  "
# 		Write-Host "=========================="
# 		$window.Close()
# 	})

# 	$window.ShowDialog()
# }

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

$performanceList = @(
	@{ ShowInGUI = "Reduce Scan CPU Load"; IsXamlId = "ScanCpuLoad"; IsOperation = "Config_ScanCpuLoad" }
	@{ ShowInGUI = "Disable Auto Sample"; IsXamlId = "AutoSample"; IsOperation = "Config_AutoSample" }
	@{ ShowInGUI = "Enable Memory Compression"; IsXamlId = "MemoryCompression"; IsOperation = "Config_MemoryCompression" }
	@{ ShowInGUI = "Enable TRIM SSD"; IsXamlId = "TrimSSD"; IsOperation = "Config_TrimSSD" }
	@{ ShowInGUI = "Disable Background Apps"; IsXamlId = "BackgroundApp"; IsOperation = "Disable_BackgroundApp" }
	@{ ShowInGUI = "Disable Transparency Effects"; IsXamlId = "TransparencyEffects"; IsOperation = "Disable_TransparencyEffects" }
	@{ ShowInGUI = "Apply Minimal Visual Effects"; IsXamlId = "CustomAppearance"; IsOperation = "Set_CustomAppearance" }
	@{ ShowInGUI = "Group Svchost Processes"; IsXamlId = "GroupProcesses"; IsOperation = "Set_GroupProcesses" }
)

function Set_PrivacySecu_UpdateBeha_PerformanceMode () {

	$window = GenerateWinGUITriple "SELECCIONE LOS AJUSTES DE PRIVACIDAD, EL COMPORTAMIENTO DE LAS ACTUALIZACIONES Y LOS AJUSTES DE RENDIMIENTO" "Aplicar"
	$checkBox1 = GenerateCheckBox $privacyList $window "ListContainer1"
	$checkBox2 = GenerateCheckBox $updateList $window "ListContainer2"
	$checkBox3 = GenerateCheckBox $performanceList $window "ListContainer3"

	$window.FindName("ActionButton").Add_Click({

		$ListToChanged1 = @()
		foreach ($listKey in $privacyList) {
			$checkBox1 = $window.FindName($listKey.IsXamlId)
			if ($checkBox1 -and $checkBox1.IsChecked) {
				$ListToChanged1 += $listKey.IsOperation
			}
		}
		$ListToChanged2 = @()
		foreach ($listKey in $updateList) {
			$checkBox2 = $window.FindName($listKey.IsXamlId)
			if ($checkBox2 -and $checkBox2.IsChecked) {
				$ListToChanged2 += $listKey.IsOperation
			}
		}
		$ListToChanged3 = @()
		foreach ($listKey in $performanceList) {
			$checkBox3 = $window.FindName($listKey.IsXamlId)
			if ($checkBox3 -and $checkBox3.IsChecked) {
				$ListToChanged3 += $listKey.IsOperation
			}
		}

		Write-Host "==  SELECTED OPERATIONS  =="
		if ( $ListToChanged1.Count -gt 0 ) {
			foreach ($Operation in $ListToChanged1) {
				& $Operation
			}
		}
		if ( $ListToChanged2.Count -gt 0 ) {
			foreach ($Operation in $ListToChanged2) {
				& $Operation
			}
		}
		if ( $ListToChanged3.Count -gt 0 ) {
			foreach ($Operation in $ListToChanged3) {
				& $Operation
			}
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
		$window.Close()
	})

	$window.ShowDialog()
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
	
	Write-Host "==  SET SERVICES  =="
	foreach ($serviceId in $disableList) {
		ConfigService $serviceId Disabled
	}
	
	foreach ($serviceId in $manualList) {
		ConfigService $serviceId Manual
	}
	Write-Host "=========================="
	Write-Host "  Operation are Finished  "
	Write-Host "=========================="
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
	
	Write-Host "==  SET SCHEDULED TASKS  =="
	foreach ($task in $disableTList) {
		ConfigTask $task.Path $task.Name Disabled
	}
	Write-Host "=========================="
	Write-Host "  Operation are Finished  "
	Write-Host "=========================="
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

$capabilityList = @(
	@{ ShowInGUI = "Analog Holographic"; IsXamlId = "AnalogHolographic"; IsOperation = "Analog.Holographic.Desktop" }
	@{ ShowInGUI = "Steps Recorder"; IsXamlId = "StepsRecorder"; IsOperation = "App.StepsRecorder" }
	@{ ShowInGUI = "Quick Assist"; IsXamlId = "QuickAssist"; IsOperation = "App.Support.QuickAssist" }
	@{ ShowInGUI = "Internet Explorer"; IsXamlId = "InternetExplorer"; IsOperation = "Browser.InternetExplorer" }
	@{ ShowInGUI = "Hello Face"; IsXamlId = "HelloFace"; IsOperation = "Hello.Face.20134" }
	@{ ShowInGUI = "Math Recognizer"; IsXamlId = "MathRecognizer"; IsOperation = "MathRecognizer" }
	@{ ShowInGUI = "Windows Media Player"; IsXamlId = "WindowsMediaPlayer"; IsOperation = "Media.WindowsMediaPlayer" }
	@{ ShowInGUI = "Wallpapers Extended"; IsXamlId = "WallpapersExtended"; IsOperation = "Microsoft.Wallpapers.Extended" }
	@{ ShowInGUI = "MSPaint (OLD)"; IsXamlId = "WindowsMSPaint"; IsOperation = "Microsoft.Windows.MSPaint" }
	@{ ShowInGUI = "Notepad (OLD)"; IsXamlId = "WindowsNotepad"; IsOperation = "Microsoft.Windows.Notepad.System" }
	@{ ShowInGUI = "PowerShell ISE"; IsXamlId = "PowerShellISE"; IsOperation = "Microsoft.Windows.PowerShell.ISE" }
	@{ ShowInGUI = "WordPad"; IsXamlId = "WindowsWordPad"; IsOperation = "Microsoft.Windows.WordPad" }
	@{ ShowInGUI = "Print Fax"; IsXamlId = "PrintFax"; IsOperation = "Print.Fax.Scan" }
	# @{ ShowInGUI = "WMIC Command"; IsXamlId = "WMIC"; IsOperation = "WMIC" }
	@{ ShowInGUI = "XPS Viewer"; IsXamlId = "XPSViewer"; IsOperation = "XPS.Viewer" }
)

# function Remove_Capability_App () {

# 	$window = GenerateWinGUI "SELECCIONE LAS CAPACIDADES DE WINDOWS" "Remover"
# 	$checkBox = GenerateCheckBox $capabilityList $window "ListContainer"

# 	$window.FindName("ActionButton").Add_Click({

# 		$ListToRemoveC = @()
# 		foreach ($listKey in $capabilityList) {
# 			$checkBox = $window.FindName($listKey.IsXamlId)
# 			if ($checkBox -and $checkBox.IsChecked) {
# 				$ListToRemoveC += $listKey.IsOperation
# 			}
# 		}

# 		Write-Host "==  SELECTED CAPABILITY  =="
# 		if ( $ListToRemoveC.Count -gt 0 ) {
# 			foreach ($appcId in $ListToRemoveC) {
# 				RemoveCapabilityApp $appcId
# 			}
# 		}
# 		Write-Host "=========================="
# 		Write-Host "  Operation are Finished  "
# 		Write-Host "=========================="
# 		$window.Close()
# 	})

# 	$window.ShowDialog()
# }

# Modification #: Configure Remove AppxPackage in Windows
# Get-AppxPackage | Where-Object { $_.NonRemovable -like "False" } | Sort-Object Name | Format-Table -Property Name, PackageFullName, NonRemovable
function RemovePackageAppx ($appxName) {
	# $appx = Get-AppxPackage | Where-Object { ($_.NonRemovable -like "False") -and ($_.PackageFullName -like "*$appxName*") }
	$appx = Get-AppxPackage -Name "*$appxName*"

	if ($appx) {
		
		Write-Host "Package [$appxName] found, Removing..." -NoNewline
		Remove-AppxPackage -Package "$($appx.PackageFullName)"
		
		$appx | Format-List -Property Name, Version, Architecture, ResourceId, PackageFullName, Status
	} 
	else {
		Write-Host "ERROR: Removing Package [$appxName], Appx not found."
	}
}

$packageList = @(
	@{ ShowInGUI = "Microsoft Clipchamp"; IsXamlId = "MSClipchamp"; IsOperation = "Clipchamp.Clipchamp" }
	@{ ShowInGUI = "Cortana"; IsXamlId = "MSCortana"; IsOperation = "Microsoft.549981C3F5F10" }
	@{ ShowInGUI = "AV1 Video Extension"; IsXamlId = "MSAV1VideoExtension"; IsOperation = "Microsoft.AV1VideoExtension" }
	@{ ShowInGUI = "Microsoft News"; IsXamlId = "MSBingNews"; IsOperation = "Microsoft.BingNews" }
	@{ ShowInGUI = "MSN Weather"; IsXamlId = "MSBingWeather"; IsOperation = "Microsoft.BingWeather" }
	# @{ ShowInGUI = "Copilot"; IsXamlId = "MSCopilot"; IsOperation = "Microsoft.Copilot" }
	@{ ShowInGUI = "Xbox App"; IsXamlId = "MSGamingApp"; IsOperation = "Microsoft.GamingApp" }
	@{ ShowInGUI = "Get Help"; IsXamlId = "MSGetHelp"; IsOperation = "Microsoft.GetHelp" }
	@{ ShowInGUI = "Get Started"; IsXamlId = "MSGetstarted"; IsOperation = "Microsoft.Getstarted" }
	@{ ShowInGUI = "HEIF Image Extension"; IsXamlId = "MSHEIFImageExtension"; IsOperation = "Microsoft.HEIFImageExtension" }
	@{ ShowInGUI = "HEVC Video Extension"; IsXamlId = "MSHEVCVideoExtension"; IsOperation = "Microsoft.HEVCVideoExtension" }
	@{ ShowInGUI = "Paint 3D"; IsXamlId = "MSMicrosoft3DViewer"; IsOperation = "Microsoft.Microsoft3DViewer" }
	# @{ ShowInGUI = "Microsoft Edge"; IsXamlId = "MSEdge"; IsOperation = "Microsoft.MicrosoftEdge.Stable" }
	# @{ ShowInGUI = "Microsoft Edge Tools"; IsXamlId = "MSEdgeDevTools"; IsOperation = "Microsoft.MicrosoftEdgeDevToolsClient" }
	@{ ShowInGUI = "Microsoft 365 (PWA)"; IsXamlId = "MSOfficeHub"; IsOperation = "Microsoft.MicrosoftOfficeHub" }
	@{ ShowInGUI = "Solitaire Collection"; IsXamlId = "MSSolitaireCollection"; IsOperation = "Microsoft.MicrosoftSolitaireCollection" }
	@{ ShowInGUI = "Microsoft Sticky Notes"; IsXamlId = "MSStickyNotes"; IsOperation = "Microsoft.MicrosoftStickyNotes" }
	@{ ShowInGUI = "Mixed Reality Portal"; IsXamlId = "MSMixedReality"; IsOperation = "Microsoft.MixedReality.Portal" }
	@{ ShowInGUI = "Paint (OLD)"; IsXamlId = "MSPaint"; IsOperation = "Microsoft.MSPaint" }
	@{ ShowInGUI = "OneNote"; IsXamlId = "MSOneNote"; IsOperation = "Microsoft.Office.OneNote" }
	@{ ShowInGUI = "Outlook for Windows"; IsXamlId = "MSOutlookForWindows"; IsOperation = "Microsoft.OutlookForWindows" }
	@{ ShowInGUI = "Microsoft People"; IsXamlId = "MSPeople"; IsOperation = "Microsoft.People" }
	@{ ShowInGUI = "Power Automate"; IsXamlId = "MSPowerAutomate"; IsOperation = "Microsoft.PowerAutomateDesktop" }
	@{ ShowInGUI = "Raw Image Extension"; IsXamlId = "MSRawImageExtension"; IsOperation = "Microsoft.RawImageExtension" }
	# @{ ShowInGUI = "Store Purchase App"; IsXamlId = "MSStorePurchaseApp"; IsOperation = "Microsoft.StorePurchaseApp" }
	@{ ShowInGUI = "Skype"; IsXamlId = "MSSkypeApp"; IsOperation = "Microsoft.SkypeApp" }
	@{ ShowInGUI = "Microsoft To Do"; IsXamlId = "MSTodos"; IsOperation = "Microsoft.Todos" }
	@{ ShowInGUI = "VP9 Video Extension"; IsXamlId = "MSVP9VideoExtensions"; IsOperation = "Microsoft.VP9VideoExtensions" }
	@{ ShowInGUI = "Microsoft Wallet"; IsXamlId = "MSWallet"; IsOperation = "Microsoft.Wallet" }
	@{ ShowInGUI = "Web Media Extension"; IsXamlId = "MSWebMediaExtensions"; IsOperation = "Microsoft.WebMediaExtensions" }
	@{ ShowInGUI = "Webp Image Extension"; IsXamlId = "MSWebpImageExtension"; IsOperation = "Microsoft.WebpImageExtension" }
	@{ ShowInGUI = "Dev Home"; IsXamlId = "MSDevHome"; IsOperation = "Microsoft.Windows.DevHome" }
	@{ ShowInGUI = "Microsoft Photos"; IsXamlId = "MSPhotos"; IsOperation = "Microsoft.Windows.Photos" }
	@{ ShowInGUI = "Windows Camera"; IsXamlId = "MSCamera"; IsOperation = "Microsoft.WindowsCamera" }
	@{ ShowInGUI = "Mail and Calendar"; IsXamlId = "MScommunicationsapps"; IsOperation = "microsoft.windowscommunicationsapps" }
	@{ ShowInGUI = "Feedback Hub"; IsXamlId = "MSFeedbackHub"; IsOperation = "Microsoft.WindowsFeedbackHub" }
	@{ ShowInGUI = "Windows Maps"; IsXamlId = "MSMaps"; IsOperation = "Microsoft.WindowsMaps" }
	@{ ShowInGUI = "Windows Sound Recorder"; IsXamlId = "MSSoundRecorder"; IsOperation = "Microsoft.WindowsSoundRecorder" }
	@{ ShowInGUI = "Xbox TCUI"; IsXamlId = "MSXboxTCUI"; IsOperation = "Microsoft.Xbox.TCUI" }
	@{ ShowInGUI = "Xbox App (OLD)"; IsXamlId = "MSXboxApp"; IsOperation = "Microsoft.XboxApp" }
	@{ ShowInGUI = "Xbox Game Overlay"; IsXamlId = "MSXboxGameOverlay"; IsOperation = "Microsoft.XboxGameOverlay" }
	# @{ ShowInGUI = "Game Bar"; IsXamlId = "MSXboxGamingOverlay"; IsOperation = "Microsoft.XboxGamingOverlay" }
	@{ ShowInGUI = "Xbox Provider"; IsXamlId = "MSXboxIdentityProvider"; IsOperation = "Microsoft.XboxIdentityProvider" }
	@{ ShowInGUI = "Xbox Text Overlay"; IsXamlId = "MSXboxSpeechToTextOverlay"; IsOperation = "Microsoft.XboxSpeechToTextOverlay" }
	# @{ ShowInGUI = "Phone Link"; IsXamlId = "MSYourPhone"; IsOperation = "Microsoft.YourPhone" }
	@{ ShowInGUI = "Windows Media Player"; IsXamlId = "MSZuneMusic"; IsOperation = "Microsoft.ZuneMusic" }
	@{ ShowInGUI = "Movies & TV"; IsXamlId = "MSZuneVideo"; IsOperation = "Microsoft.ZuneVideo" }
	@{ ShowInGUI = "Microsoft Family Safety"; IsXamlId = "MSFamily"; IsOperation = "MicrosoftCorporationII.MicrosoftFamily" }
	@{ ShowInGUI = "Quick Assist"; IsXamlId = "MSQuickAssist"; IsOperation = "MicrosoftCorporationII.QuickAssist" }
	@{ ShowInGUI = "Windows App Runtime Main"; IsXamlId = "MSWinAppRuntime_Main"; IsOperation = "MicrosoftCorporationII.WinAppRuntime.Main.1.5" }
	@{ ShowInGUI = "Windows App Runtime Singleton"; IsXamlId = "MSWinAppRuntime_Singleton"; IsOperation = "MicrosoftCorporationII.WinAppRuntime.Singleton" }
	@{ ShowInGUI = "Widgets"; IsXamlId = "MSWebExperience"; IsOperation = "MicrosoftWindows.Client.WebExperience" }
	# @{ ShowInGUI = "Cross Device Host"; IsXamlId = "MSCrossDevice"; IsOperation = "MicrosoftWindows.CrossDevice" }
	@{ ShowInGUI = "Widgets Platform"; IsXamlId = "MSWidgetsPlatform"; IsOperation = "Microsoft.WidgetsPlatformRuntime" }
	@{ ShowInGUI = "Microsoft Teams"; IsXamlId = "MSWTeams"; IsOperation = "MSTeams" }
	@{ ShowInGUI = "Spotify Music"; IsXamlId = "MSSpotifyMusic"; IsOperation = "SpotifyAB.SpotifyMusic" }
	# @{ ShowInGUI = "linkedin"; IsXamlId = "MSlinkedin"; IsOperation = "linkedin_searchId" }
	# @{ ShowInGUI = "Camo Studio"; IsXamlId = "MSCamoStudio"; IsOperation = "CamoStudio_searchId" }
)

# function Remove_User_Appx () {

# 	$window = GenerateWinGUI "SELECCIONE LOS PAQUETES DE WINDOWS" "Remover"
# 	$checkBox = GenerateCheckBox $packageList $window "ListContainer"

# 	$window.FindName("ActionButton").Add_Click({

# 		$ListToRemoveU = @()
# 		foreach ($listKey in $packageList) {
# 			$checkBox = $window.FindName($listKey.IsXamlId)
# 			if ($checkBox -and $checkBox.IsChecked) {
# 				$ListToRemoveU += $listKey.IsOperation
# 			}
# 		}

# 		Write-Host "==  SELECTED PACKAGE  =="
# 		if ( $ListToRemoveU.Count -gt 0 ) {
# 			foreach ($appxId in $ListToRemoveU) {
# 				RemovePackageAppx $appxId
# 			}
# 		}
# 		Write-Host "=========================="
# 		Write-Host "  Operation are Finished  "
# 		Write-Host "=========================="
# 		$window.Close()
# 	})

# 	$window.ShowDialog()
# }

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

$provisionedList = @(
	@{ ShowInGUI = "Microsoft Clipchamp"; IsXamlId = "PMSClipchamp"; IsOperation = "Clipchamp.Clipchamp" }
	@{ ShowInGUI = "Cortana"; IsXamlId = "PMSCortana"; IsOperation = "Microsoft.549981C3F5F10" }
	@{ ShowInGUI = "Microsoft News"; IsXamlId = "PMSBingNews"; IsOperation = "Microsoft.BingNews" }
	@{ ShowInGUI = "Bing Search (Edge)"; IsXamlId = "PMSBingSearch"; IsOperation = "Microsoft.BingSearch" }
	@{ ShowInGUI = "MSN Weather"; IsXamlId = "PMSBingWeather"; IsOperation = "Microsoft.BingWeather" }
	# @{ ShowInGUI = "Copilot"; IsXamlId = "PMSCopilot"; IsOperation = "Microsoft.Copilot" }
	@{ ShowInGUI = "Xbox App"; IsXamlId = "PMSGamingApp"; IsOperation = "Microsoft.GamingApp" }
	@{ ShowInGUI = "Get Help"; IsXamlId = "PMSGetHelp"; IsOperation = "Microsoft.GetHelp" }
	@{ ShowInGUI = "Get Started"; IsXamlId = "PMSGetstarted"; IsOperation = "Microsoft.Getstarted" }
	@{ ShowInGUI = "HEIF Image Extension"; IsXamlId = "PMSHEIFImageExtension"; IsOperation = "Microsoft.HEIFImageExtension" }
	@{ ShowInGUI = "HEVC Video Extension"; IsXamlId = "PMSHEVCVideoExtension"; IsOperation = "Microsoft.HEVCVideoExtension" }
	@{ ShowInGUI = "Paint 3D"; IsXamlId = "PMSMicrosoft3DViewer"; IsOperation = "Microsoft.Microsoft3DViewer" }
	# @{ ShowInGUI = "Microsoft Edge"; IsXamlId = "PMSEdge"; IsOperation = "Microsoft.MicrosoftEdge.Stable" }
	# @{ ShowInGUI = "Microsoft Edge Tools"; IsXamlId = "PMSEdgeDevTools"; IsOperation = "Microsoft.MicrosoftEdgeDevToolsClient" }
	@{ ShowInGUI = "Microsoft 365 (PWA)"; IsXamlId = "PMSOfficeHub"; IsOperation = "Microsoft.MicrosoftOfficeHub" }
	@{ ShowInGUI = "Solitaire Collection"; IsXamlId = "PMSSolitaireCollection"; IsOperation = "Microsoft.MicrosoftSolitaireCollection" }
	@{ ShowInGUI = "Microsoft Sticky Notes"; IsXamlId = "PMSStickyNotes"; IsOperation = "Microsoft.MicrosoftStickyNotes" }
	@{ ShowInGUI = "Mixed Reality Portal"; IsXamlId = "PMSMixedReality"; IsOperation = "Microsoft.MixedReality.Portal" }
	@{ ShowInGUI = "Paint (OLD)"; IsXamlId = "PMSPaint"; IsOperation = "Microsoft.MSPaint" }
	@{ ShowInGUI = "OneNote"; IsXamlId = "PMSOneNote"; IsOperation = "Microsoft.Office.OneNote" }
	@{ ShowInGUI = "Outlook for Windows"; IsXamlId = "PMSOutlookForWindows"; IsOperation = "Microsoft.OutlookForWindows" }
	@{ ShowInGUI = "Microsoft People"; IsXamlId = "PMSPeople"; IsOperation = "Microsoft.People" }
	@{ ShowInGUI = "Power Automate"; IsXamlId = "PMSPowerAutomate"; IsOperation = "Microsoft.PowerAutomateDesktop" }
	@{ ShowInGUI = "Raw Image Extension"; IsXamlId = "PMSRawImageExtension"; IsOperation = "Microsoft.RawImageExtension" }
	# @{ ShowInGUI = "Store Purchase App"; IsXamlId = "PMSStorePurchaseApp"; IsOperation = "Microsoft.StorePurchaseApp" }
	@{ ShowInGUI = "Skype"; IsXamlId = "PMSSkypeApp"; IsOperation = "Microsoft.SkypeApp" }
	@{ ShowInGUI = "Microsoft To Do"; IsXamlId = "PMSTodos"; IsOperation = "Microsoft.Todos" }
	@{ ShowInGUI = "VP9 Video Extension"; IsXamlId = "PMSVP9VideoExtensions"; IsOperation = "Microsoft.VP9VideoExtensions" }
	@{ ShowInGUI = "Microsoft Wallet"; IsXamlId = "PMSWallet"; IsOperation = "Microsoft.Wallet" }
	@{ ShowInGUI = "Web Media Extension"; IsXamlId = "PMSWebMediaExtensions"; IsOperation = "Microsoft.WebMediaExtensions" }
	@{ ShowInGUI = "Webp Image Extension"; IsXamlId = "PMSWebpImageExtension"; IsOperation = "Microsoft.WebpImageExtension" }
	@{ ShowInGUI = "Dev Home"; IsXamlId = "PMSDevHome"; IsOperation = "Microsoft.Windows.DevHome" }
	@{ ShowInGUI = "Microsoft Photos"; IsXamlId = "PMSPhotos"; IsOperation = "Microsoft.Windows.Photos" }
	@{ ShowInGUI = "Mail and Calendar"; IsXamlId = "PMScommunicationsapps"; IsOperation = "microsoft.windowscommunicationsapps" }
	@{ ShowInGUI = "Feedback Hub"; IsXamlId = "PMSFeedbackHub"; IsOperation = "Microsoft.WindowsFeedbackHub" }
	@{ ShowInGUI = "Windows Maps"; IsXamlId = "PMSMaps"; IsOperation = "Microsoft.WindowsMaps" }
	@{ ShowInGUI = "Xbox TCUI"; IsXamlId = "PMSXboxTCUI"; IsOperation = "Microsoft.Xbox.TCUI" }
	@{ ShowInGUI = "Xbox App (OLD)"; IsXamlId = "PMSXboxApp"; IsOperation = "Microsoft.XboxApp" }
	@{ ShowInGUI = "Xbox Game Overlay"; IsXamlId = "PMSXboxGameOverlay"; IsOperation = "Microsoft.XboxGameOverlay" }
	# @{ ShowInGUI = "Game Bar"; IsXamlId = "PMSXboxGamingOverlay"; IsOperation = "Microsoft.XboxGamingOverlay" }
	@{ ShowInGUI = "Xbox Provider"; IsXamlId = "PMSXboxIdentityProvider"; IsOperation = "Microsoft.XboxIdentityProvider" }
	@{ ShowInGUI = "Xbox Text Overlay"; IsXamlId = "PMSXboxSpeechToTextOverlay"; IsOperation = "Microsoft.XboxSpeechToTextOverlay" }
	# @{ ShowInGUI = "Phone Link"; IsXamlId = "PMSYourPhone"; IsOperation = "Microsoft.YourPhone" }
	@{ ShowInGUI = "Windows Media Player"; IsXamlId = "PMSZuneMusic"; IsOperation = "Microsoft.ZuneMusic" }
	@{ ShowInGUI = "Movies & TV"; IsXamlId = "PMSZuneVideo"; IsOperation = "Microsoft.ZuneVideo" }
	@{ ShowInGUI = "Microsoft Family Safety"; IsXamlId = "PMSFamily"; IsOperation = "MicrosoftCorporationII.MicrosoftFamily" }
	@{ ShowInGUI = "Quick Assist"; IsXamlId = "PMSQuickAssist"; IsOperation = "MicrosoftCorporationII.QuickAssist" }
	@{ ShowInGUI = "Widgets"; IsXamlId = "PMSWebExperience"; IsOperation = "MicrosoftWindows.Client.WebExperience" }
	# @{ ShowInGUI = "Cross Device Host"; IsXamlId = "PMSCrossDevice"; IsOperation = "MicrosoftWindows.CrossDevice" }
	@{ ShowInGUI = "Widgets Platform"; IsXamlId = "PMSWidgetsPlatform"; IsOperation = "Microsoft.WidgetsPlatformRuntime" }
	@{ ShowInGUI = "Microsoft Teams"; IsXamlId = "PMSWTeams"; IsOperation = "MSTeams" }
)

function Remove_Capability_Package_Provisioned () {

	$window = GenerateWinGUITriple "SELECCIONE LAS CAPACIDADES DE WINDOWS, LOS PAQUETES DE WINDOWS Y LOS PROVISIONADOS DE WINDOWS" "Remover"
	$checkBox1 = GenerateCheckBox $capabilityList $window "ListContainer1"
	$checkBox2 = GenerateCheckBox $packageList $window "ListContainer2"
	$checkBox3 = GenerateCheckBox $provisionedList $window "ListContainer3"

	$window.FindName("ActionButton").Add_Click({

		$ListToRemoveC = @()
		foreach ($listKey in $capabilityList) {
			$checkBox1 = $window.FindName($listKey.IsXamlId)
			if ($checkBox1 -and $checkBox1.IsChecked) {
				$ListToRemoveC += $listKey.IsOperation
			}
		}
		$ListToRemoveU = @()
		foreach ($listKey in $packageList) {
			$checkBox2 = $window.FindName($listKey.IsXamlId)
			if ($checkBox2 -and $checkBox2.IsChecked) {
				$ListToRemoveU += $listKey.IsOperation
			}
		}
		$ListToRemoveP = @()
		foreach ($listKey in $provisionedList) {
			$checkBox3 = $window.FindName($listKey.IsXamlId)
			if ($checkBox3 -and $checkBox3.IsChecked) {
				$ListToRemoveP += $listKey.IsOperation
			}
		}
		
		Write-Host "==  SELECTED OPERATIONS  =="
		if ( $ListToRemoveC.Count -gt 0 ) {
			foreach ($appcId in $ListToRemoveC) {
				RemoveCapabilityApp $appcId
			}
		}
		if ( $ListToRemoveU.Count -gt 0 ) {
			foreach ($appxId in $ListToRemoveU) {
				RemovePackageAppx $appxId
			}
		}
		if ( $ListToRemoveP.Count -gt 0 ) {
			foreach ($appxId in $ListToRemoveP) {
				RemoveProvisionedAppx $appxId
			}
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
		$window.Close()
	})

	$window.ShowDialog()
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

$disableFList = @(
	@{ ShowInGUI = "Disable Internet Explorer 11"; IsXamlId = "Internet_Explorer"; IsOperation = "Internet-Explorer-Optional-amd64" }
	@{ ShowInGUI = "Disable Media Features"; IsXamlId = "MediaPlay"; IsOperation = "MediaPlayback" }
	@{ ShowInGUI = "Disable Windows Media Player"; IsXamlId = "MediaPlayer"; IsOperation = "WindowsMediaPlayer" }
)

$enableFList = @(
	@{ ShowInGUI = "Enable .NET Framework 3.5"; IsXamlId = "NetFramework"; IsOperation = "NetFx3" }
	@{ ShowInGUI = "Enable Windows Sandbox"; IsXamlId = "ClientVM"; IsOperation = "Containers-DisposableClientVM" }
)

function Set_Optional_Feature () {

	$window = GenerateWinGUI "SELECCIONE LAS CARACTERISTICAS OPCIONALES" "Aplicar"
	$checkBox1 = GenerateCheckBox $disableFList $window "ListContainer"
	$checkBox2 = GenerateCheckBox $enableFList $window "ListContainer"

	$window.FindName("ActionButton").Add_Click({

		$ListToDisable = @()
		foreach ($listKey in $disableFList) {
			$checkBox1 = $window.FindName($listKey.IsXamlId)
			if ($checkBox1 -and $checkBox1.IsChecked) {
				$ListToDisable += $listKey.IsOperation
			}
		}
		$ListToEnable = @()
		foreach ($currentItemName in $collection) {
			$checkBox2 = $window.FindName($listKey.IsXamlId)
			if ($checkBox2 -and $checkBox2.IsChecked) {
				$ListToEnable += $listKey.IsOperation
			}
		}

		Write-Host "==  SELECTED FEATURE  =="
		if ( $ListToDisable.Count -gt 0 ) {
			foreach ($featureId in $ListToDisable) {
				ConfigFeature $featureId Disabled
			}
		}
		if ( $ListToEnable.Count -gt 0 ) {
			foreach ($featureId in $ListToEnable) {
				ConfigFeature $featureId Enabled
			}
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
		$window.Close()
	})

	$window.ShowDialog()

	<#
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

	Write-Host "==  SELECTED FEATURE  =="
	Write-Host "Setting Feature: $ListToDisable $ListToEnable"
	foreach ($featureId in $ListToDisable) {
		ConfigFeature $featureId Disabled
	}

	foreach ($featureId in $ListToEnable) {
		ConfigFeature $featureId Enabled
	}
	Write-Host "=========================="
	Write-Host "  Operation are Finished  "
	Write-Host "=========================="
	#>
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
		Write-Host "App [$appId] found, existing Package."
		Write-Host "$appId already installed."
	}
}

$wingetList = @(
	@{ ShowInGUI = "Visual C++ 2015-2022 Redist (x86)"; IsXamlId = "MSVisuCplusRedis2015_x86"; IsOperation = "Microsoft.VCRedist.2015+.x86" }
	@{ ShowInGUI = "Visual C++ 2015-2022 Redist (x64)"; IsXamlId = "MSVisuCplusRedis2015_x64"; IsOperation = "Microsoft.VCRedist.2015+.x64" }
	@{ ShowInGUI = "Bitwarden"; IsXamlId = "BitwardenId"; IsOperation = "Bitwarden.Bitwarden" }
	@{ ShowInGUI = "Mozilla Firefox"; IsXamlId = "FirefoxBrow"; IsOperation = "Mozilla.Firefox" }
	@{ ShowInGUI = "Vivaldi Browser"; IsXamlId = "VivaldiBrow"; IsOperation = "Vivaldi.Vivaldi" }
	@{ ShowInGUI = "OperaGX Browser"; IsXamlId = "OperaGXBrow"; IsOperation = "Opera.OperaGX" }
	# @{ ShowInGUI = "Microsoft Edge"; IsXamlId = "MSEdgeBrow"; IsOperation = "Microsoft.Edge" }
	@{ ShowInGUI = "ZoomIt"; IsXamlId = "MSZoomIt"; IsOperation = "Microsoft.Sysinternals.ZoomIt" }
	@{ ShowInGUI = "Energy Star X"; IsXamlId = "StoreEnergyStarX"; IsOperation = "9NF7JTB3B17P" }
	@{ ShowInGUI = "Microsoft PC Manager"; IsXamlId = "StorePCManager"; IsOperation = "9PM860492SZD" }
	@{ ShowInGUI = "AutoHotkey"; IsXamlId = "AutoHotkeyId"; IsOperation = "AutoHotkey.AutoHotkey" }
	@{ ShowInGUI = "Everything (x64)"; IsXamlId = "Everything"; IsOperation = "voidtools.Everything" }
	@{ ShowInGUI = "QuickLook"; IsXamlId = "QuickLookId"; IsOperation = "QL-Win.QuickLook" }
	@{ ShowInGUI = "Lightshot"; IsXamlId = "LightshotId"; IsOperation = "Skillbrains.Lightshot" }
	@{ ShowInGUI = "ChatGPT"; IsXamlId = "ChatGPTId"; IsOperation = "9NT1R1C2HH7J" }
	@{ ShowInGUI = "Quick Share Google"; IsXamlId = "QuickShare"; IsOperation = "Google.QuickShare" }
	@{ ShowInGUI = "PowerToys (Preview)"; IsXamlId = "PowerToys"; IsOperation = "Microsoft.PowerToys" }
	@{ ShowInGUI = "7-Zip"; IsXamlId = "SevenZip"; IsOperation = "7zip.7zip" }
	@{ ShowInGUI = "WinRAR"; IsXamlId = "WinRARId"; IsOperation = "RARLab.WinRAR" }
	@{ ShowInGUI = "Google Drive"; IsXamlId = "GoogleDrive"; IsOperation = "Google.GoogleDrive" }
	@{ ShowInGUI = "TeraBox Desktop"; IsXamlId = "TeraBox"; IsOperation = "Baidu.TeraBox" }
	@{ ShowInGUI = "Notepad++"; IsXamlId = "Notepadplusplus"; IsOperation = "Notepad++.Notepad++" }
	@{ ShowInGUI = "GIMP"; IsXamlId = "GimpId"; IsOperation = "GIMP.GIMP" }
	@{ ShowInGUI = "Audacity"; IsXamlId = "AudacityId"; IsOperation = "Audacity.Audacity" }
	@{ ShowInGUI = "IrfanView (x64)"; IsXamlId = "IrfanView"; IsOperation = "IrfanSkiljan.IrfanView" }
	@{ ShowInGUI = "VLC Media Player"; IsXamlId = "VLCMediaPlayer"; IsOperation = "VideoLAN.VLC" }
	@{ ShowInGUI = "SumatraPDF"; IsXamlId = "SumatraPDFId"; IsOperation = "SumatraPDF.SumatraPDF" }
	@{ ShowInGUI = "Microsoft 365 Apps"; IsXamlId = "MSOffice"; IsOperation = "Microsoft.Office" }
	@{ ShowInGUI = "OnlyOffice"; IsXamlId = "OnlyOfficeId"; IsOperation = "ONLYOFFICE.DesktopEditors" }
	@{ ShowInGUI = "LibreOffice LTS"; IsXamlId = "LibreOffice"; IsOperation = "TheDocumentFoundation.LibreOffice.LTS" }
	@{ ShowInGUI = "Steam Launcher"; IsXamlId = "SteamLauncher"; IsOperation = "Valve.Steam" }
	@{ ShowInGUI = "Epic Games Launcher"; IsXamlId = "EpicLauncher"; IsOperation = "EpicGames.EpicGamesLauncher" }
	@{ ShowInGUI = "Ubisoft Connect"; IsXamlId = "UbisoftConnet"; IsOperation = "Ubisoft.Connect" }
	@{ ShowInGUI = "BlueStacks"; IsXamlId = "BlueStacksId"; IsOperation = "BlueStack.BlueStacks" }
	@{ ShowInGUI = "qBittorrent"; IsXamlId = "qBittorrentId"; IsOperation = "qBittorrent.qBittorrent" }
	@{ ShowInGUI = "WhatsApp Desktop"; IsXamlId = "WhatsApp"; IsOperation = "9NKSQGP7F2NH" }
	@{ ShowInGUI = "Telegram Desktop"; IsXamlId = "Telegram"; IsOperation = "Telegram.TelegramDesktop" }
	@{ ShowInGUI = "Mozilla Thunderbird"; IsXamlId = "Thunderbird"; IsOperation = "Mozilla.Thunderbird" }
	@{ ShowInGUI = "scrcpy"; IsXamlId = "scrcpyId"; IsOperation = "Genymobile.scrcpy" }
	@{ ShowInGUI = "Discord"; IsXamlId = "DiscordId"; IsOperation = "Discord.Discord" }
	@{ ShowInGUI = "Zoom Workplace"; IsXamlId = "ZoomId"; IsOperation = "Zoom.Zoom" }
	@{ ShowInGUI = "Microsoft Teams (New)"; IsXamlId = "MSTeams"; IsOperation = "Microsoft.Teams" }
	@{ ShowInGUI = "Slack"; IsXamlId = "SlackId"; IsOperation = "SlackTechnologies.Slack" }
	@{ ShowInGUI = "OBS Studio"; IsXamlId = "OBSStudio"; IsOperation = "OBSProject.OBSStudio" }
	# @{ ShowInGUI = "MiniTool Partition Wizard"; IsXamlId = "PartitionWizard"; IsOperation = "MiniTool.PartitionWizard.Free" }
	@{ ShowInGUI = "PuTTY"; IsXamlId = "PuTTYId"; IsOperation = "PuTTY.PuTTY" }
	@{ ShowInGUI = "WinSCP"; IsXamlId = "WinSCPId"; IsOperation = "WinSCP.WinSCP" }
	@{ ShowInGUI = "TeamViewer"; IsXamlId = "TeamViewerId"; IsOperation = "TeamViewer.TeamViewer" }
	@{ ShowInGUI = "Oracle VM VirtualBox"; IsXamlId = "VirtualBox"; IsOperation = "Oracle.VirtualBox" }
	# @{ ShowInGUI = "VMware Workstation Pro"; IsXamlId = "VMware"; IsOperation = "VMware.IDDDDDDD" }
	@{ ShowInGUI = "FxSound"; IsXamlId = "FxSoundId"; IsOperation = "FxSoundLLC.FxSound" }
	@{ ShowInGUI = "Fan Control"; IsXamlId = "FanControl"; IsOperation = "Rem0o.FanControl" }
	@{ ShowInGUI = "MSI Afterburner"; IsXamlId = "Afterburner"; IsOperation = "Guru3D.Afterburner" }
	@{ ShowInGUI = "TechPowerUp GPU-Z"; IsXamlId = "GPU_Z"; IsOperation = "TechPowerUp.GPU-Z" }
	@{ ShowInGUI = "WinDirStat"; IsXamlId = "WinDirStatId"; IsOperation = "WinDirStat.WinDirStat" }
	@{ ShowInGUI = "Recuva"; IsXamlId = "RecuvaId"; IsOperation = "Piriform.Recuva" }
	@{ ShowInGUI = "BleachBit"; IsXamlId = "BleachBitId"; IsOperation = "BleachBit.BleachBit" }
	# @{ ShowInGUI = "NVCleanstall"; IsXamlId = "NVCleanstallId"; IsOperation = "TechPowerUp.NVCleanstall" }
	@{ ShowInGUI = "starship"; IsXamlId = "StarshipId"; IsOperation = "Starship.Starship" }
	@{ ShowInGUI = "Neovim"; IsXamlId = "NeovimId"; IsOperation = "Neovim.Neovim" }
	@{ ShowInGUI = "Visual Studio Code"; IsXamlId = "VSCode"; IsOperation = "Microsoft.VisualStudioCode" }
	@{ ShowInGUI = "Git"; IsXamlId = "GitId"; IsOperation = "Git.Git" }
	@{ ShowInGUI = "Java SDK"; IsXamlId = "JavaSDK"; IsOperation = "Oracle.JDK.22" }
	@{ ShowInGUI = "Python 3.12"; IsXamlId = "Python"; IsOperation = "Python.Python.3.12" }
	@{ ShowInGUI = "Rust (MSVC)"; IsXamlId = "Rustlang"; IsOperation = "Rustlang.Rust.MSVC" }
	# @{ ShowInGUI = "Rustup: toolchain"; IsXamlId = "Rustlang"; IsOperation = "Rustlang.Rustup" }
	@{ ShowInGUI = "Node.js LTS"; IsXamlId = "NodeJS"; IsOperation = "OpenJS.NodeJS.LTS" }
	@{ ShowInGUI = "GitHub Desktop"; IsXamlId = "GitHubId"; IsOperation = "GitHub.GitHubDesktop" }
	@{ ShowInGUI = "Visual Studio Community"; IsXamlId = "VSCommunity"; IsOperation = "Microsoft.VisualStudio.2022.Community" }
	@{ ShowInGUI = "Apache NetBeans IDE"; IsXamlId = "NetBeans"; IsOperation = "Apache.NetBeans" }
	@{ ShowInGUI = "Android Studio"; IsXamlId = "AndroidStudio"; IsOperation = "Google.AndroidStudio" }
	@{ ShowInGUI = "MySQL"; IsXamlId = "MySQLId"; IsOperation = "Oracle.MySQL" }
	# @{ ShowInGUI = "PostgreSQL 16"; IsXamlId = "PostgreSQL"; IsOperation = "PostgreSQL.PostgreSQL.16" }
	# @{ ShowInGUI = "SQLServer Express"; IsXamlId = "SQLServer"; IsOperation = "Microsoft.SQLServer.2022.Express" }
	@{ ShowInGUI = "SQLServer Management Studio"; IsXamlId = "SQLServerMS"; IsOperation = "Microsoft.SQLServerManagementStudio" }
	@{ ShowInGUI = "Docker Desktop"; IsXamlId = "Docker"; IsOperation = "Docker.DockerDesktop" }
	# @{ ShowInGUI = "Windows Terminal"; IsXamlId = "WindowsTerminal"; IsOperation = "Microsoft.WindowsTerminal" }
)

$chocoList = @(
	@{ ShowInGUI = "AIMP Music Player"; IsXamlId = "AimpId"; IsOperation = "aimp" }
	@{ ShowInGUI = "Keypirinha Launcher"; IsXamlId = "KeypirinhaId"; IsOperation = "keypirinha" }
	@{ ShowInGUI = "FileZilla Client"; IsXamlId = "FilezillaId"; IsOperation = "filezilla" }
	@{ ShowInGUI = "Fing Desktop"; IsXamlId = "FingId"; IsOperation = "fing" }
)

function Install_Apps () {

	$window = GenerateWinGUI "SELECCIONE LAS APLICACIONES" "Instalar"
	$checkBox1 = GenerateCheckBox $wingetList $window "ListContainer"
	$checkBox2 = GenerateCheckBox $chocoList $window "ListContainer"

	$window.FindName("ActionButton").Add_Click({
		
		$ListToInstallW = @()
		foreach ($listKey in $wingetList) {
			$checkBox1 = $window.FindName($listKey.IsXamlId)
			if ($checkBox1 -and $checkBox1.IsChecked) {
				$ListToInstallW += $listKey.IsOperation
			}
		}
	
		$ListToInstallC = @()
		foreach ($listKey in $chocoList) {
			$checkBox2 = $window.FindName($listKey.IsXamlId)
			if ($checkBox2 -and $checkBox2.IsChecked) {
				$ListToInstallC += $listKey.IsOperation
			}
		}
		
		Write-Host "==  SELECTED APP  =="
		if ( $ListToInstallW.Count -gt 0 ) {
			foreach ($appId in $ListToInstallW) {
				InstallApp $appId winget
			}
		}

		if ( $ListToInstallC.Count -gt 0 ) {
			foreach ($appId in $ListToInstallC) {
				InstallApp $appId choco
			}
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
		$window.Close()
	})

	$window.ShowDialog()
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

<#
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
#>

function Download_Tools () {
	
	<#
	Write-Host "Url Search Tools`n------------------"
	$ListToDownload = @()
	foreach ($toolData in $toolList) {

		$messageS = "Download App $($toolData.Name)"
		$selectedApp = Add-ItemSelection $messageS $toolData
		if ($selectedApp) {
			$ListToDownload += $selectedApp
		}
	}
	
	Write-Host "==  SELECTED TOOL  =="
	Write-Host "Download Tool: $ListToDownload`n"
	foreach ($toolId in $ListToDownload) {
		DownloadApp $toolId.TUrl $toolId.File
	}
	Write-Host "=========================="
	Write-Host "  Operation are Finished  "
	Write-Host "=========================="
	#>
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
	Write-Host "##  PROMPT OH-MY-POSH"
	InstallApp "JanDeDobbeleer.OhMyPosh" winget
	
	# Iniciar Oh-My-Posh en la terminal
	$initPrompt = 'oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\' + $themeName + '.omp.json"'
	$activatePrompt = Invoke-Expression $initPrompt
	Write-Host "Initializing the following prompt: $initPrompt"
	
	# Activar Oh-My-Posh en la terminal
	Write-Host "Activating the following config of prompt: $activatePrompt`n"
	
	return $activatePrompt
}

function Install_ModuleT {
	
	# MyTheme 7.2: Module Terminal-Icons
	Write-Host "##  PS MODULE TERMINAL-ICONS"
	InstallModule "Terminal-Icons"
	$iconsComand = ActivateModule "Terminal-Icons"
	Write-Host ""
	
	# MyTheme 7.2: Module z
	Write-Host "##  PS MODULE Z"
	InstallModule "z"
	Write-Host ""

	return $iconsComand
}

function Enable_ListViewT {
	
	$modeName = 'ListView'
	$option = Get-PSReadLineOption | Where-Object { $_.PredictionViewStyle -notlike "$modeName" }

	Write-Host "##  PS OPTION PREDICTION-STYLE"
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

		Write-Host "String [$valueToAdd] not found, Adding..." -ForegroundColor Yellow
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
	Write-Host "---------------------------"
	Write-Host "==  SET BACKGROUND TYPE  =="
	Write-Host "---------------------------"
	Set_BackgroundType

	Write-Host "`n----------------------------"
	Write-Host "==  SET BACKGROUND IMAGE  =="
	Write-Host "----------------------------"
	$filePath = "$env:USERPROFILE\Pictures\wallpaperbetter-3840-2160-3.jpg"
	$webPath = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/wallpaperbetter-3840-2160-3.jpg"
	
	Write-Host "Test [Image] for Background."
	Test_ImagePath $filePath $webPath

	# Show File
	Get-ChildItem $filePath | Format-Table

	# Change current picture
	Set_BackgroundImage "HKCU:\Control Panel\Desktop" "WallPaper" $filePath
	
	# Change to a Fill
	Write-Host "`n--------------------"
	Write-Host "==  SET FIT TYPE  =="
	Write-Host "--------------------"
	Set_FitType
	
	Write-Host "`n-----------------------------"
	Write-Host "==  TEST BACKGROUND OTHER  =="
	Write-Host "-----------------------------"
	$filePath1 = "$env:USERPROFILE\Pictures\cropped-3840-2160-310526.jpg"
	$webPath1 = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/cropped-3840-2160-310526.jpg"

	Write-Host "Test [Image] for Lock Screen."
	Test_ImagePath $filePath1 $webPath1

	# Show File
	Get-ChildItem $filePath1 | Format-Table

	$filePath2 = "$env:USERPROFILE\Pictures\dark-minimal-mountains.png"
	$webPath2 = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/dark-minimal-mountains.png"

	Write-Host "Test [Image] for Browser."
	Test_ImagePath $filePath2 $webPath2

	# Show File
	Get-ChildItem $filePath2 | Format-Table

	Write-Host "=========================="
	Write-Host "  Operation are Finished  "
	Write-Host "=========================="
}

function Custom_Shell_Pwsh () {

	Write-Host "--------------------------"
	Write-Host "==  PROFILE SHELL PWSH  =="
	Write-Host "--------------------------"

	$activatePrompt = Install_PromptT "kushal"
	$iconsComand = Install_ModuleT
	$predictionComand = Enable_ListViewT

	# Create File
	Write-Host "##  PROFILE SHELL"
	Write-Host "Creating the following file: `$PROFILE"
	$PROFILE_TEMP1 = "$env:USERPROFILE\Documents\PowerShell"
	Test-ItemPath $PROFILE_TEMP1 "Microsoft.PowerShell_profile.ps1" "File"
	$PROFILE_PATH_1 = "$PROFILE_TEMP1\Microsoft.PowerShell_profile.ps1"

	# Show File
	Get-ChildItem $PROFILE_PATH_1 | Format-Table

	# Add Content
	Write-Host "Adding content the following file: `$PROFILE"
	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test-FileContent $PROFILE_PATH_1 $stringReduce $activatePrompt
	Test-FileContent $PROFILE_PATH_1 $iconsComand $iconsComand
	Test-FileContent $PROFILE_PATH_1 $predictionComand $predictionComand

	# Show Content
	Write-Host "`n$(Get-Content -Path $PROFILE_PATH_1 -Raw)" -ForegroundColor Cyan -NoNewline
}

function Custom_Shell_Powershell () {
	
	Write-Host "--------------------------------"
	Write-Host "==  PROFILE SHELL POWERSHELL  =="
	Write-Host "--------------------------------"

	$activatePrompt = Install_PromptT "kali"

	# Create File
	Write-Host "##  PROFILE SHELL"
	Write-Host "Creating the following file: `$PROFILE"
	$PROFILE_TEMP2 = "$env:USERPROFILE\Documents\WindowsPowerShell"
	Test-ItemPath $PROFILE_TEMP2 "Microsoft.PowerShell_profile.ps1" "File"
	$PROFILE_PATH_2 = "$PROFILE_TEMP2\Microsoft.PowerShell_profile.ps1"

	# Show File
	Get-ChildItem $PROFILE_PATH_2 | Format-Table

	# Add Content
	Write-Host "Adding content the following file: `$PROFILE"
	$stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26)
	Test-FileContent $PROFILE_PATH_2 $stringReduce $activatePrompt

	# Show Content
	Write-Host "`n$(Get-Content -Path $PROFILE_PATH_2 -Raw)" -ForegroundColor Cyan -NoNewline
}

function Install_PromptC {
	param (
		[string]$themeName
	)

	# Instalar Clink en la terminal
	Write-Host "##  TOOL CLINK"
	InstallApp "chrisant996.Clink" winget          # (clink set clink.logo none)

	# Instalar Oh-My-Posh en la terminal
	Write-Host "##  PROMPT OH-MY-POSH"
	InstallApp "JanDeDobbeleer.OhMyPosh" winget

	# Iniciar Oh-My-Posh en la terminal
	$initPrompt = 'oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\' + $themeName + '.omp.json"'
	$null = Invoke-Expression $initPrompt
	Write-Host "Initializing the following prompt: $initPrompt"

	# Cargar Oh-My-Posh en la terminal
	$env:POSH_THEMES_PATH_TEMP = $env:POSH_THEMES_PATH -replace '\\', '/'
	$loadPrompt = "load(io.popen('oh-my-posh.exe --config=`"$env:POSH_THEMES_PATH_TEMP/$themeName.omp.json`" --init --shell cmd'):read(`"*a`"))()"
	Write-Host "Loading the following config of prompt : $loadPrompt`n"

	return $loadPrompt
}

function Custom_Shell_Cmd () {

	Write-Host "-------------------------"
	Write-Host "==  PROFILE SHELL CMD  =="
	Write-Host "-------------------------"

	$addComment = "-- oh-my-posh.lua"
	$loadPrompt = Install_PromptC "stelbent.minimal"

	# Create File
	Write-Host "##  CONFIG SHELL"
	Write-Host "Creating the following file: `$CONFIG"
	$CONFIG_TEMP3 = "$env:LOCALAPPDATA\clink"
	Test-ItemPath $CONFIG_TEMP3 "oh-my-posh.lua" "File"
	$CONFIG_PATH_3 = "$CONFIG_TEMP3\oh-my-posh.lua"

	# Show File
	Get-ChildItem $CONFIG_PATH_3 | Format-Table
	
	# Add Content
	Write-Host "Adding content the following file: `$CONFIG"
	Test-FileContent $CONFIG_PATH_3 $addComment $addComment
	Test-FileContent $CONFIG_PATH_3 $loadPrompt $loadPrompt

	# Show Content
	Write-Host "`n$(Get-Content -Path $CONFIG_PATH_3 -Raw)" -ForegroundColor Cyan -NoNewline
}

function Custom_Pwsh_Powershell_Cmd () {

	$varTextBlock1 = "SHELL PWSH" + 
	"`n- Se agrega un prompt personalizado de oh-my-posh con el tema 'kushal'." + 
	"`n- Se agrega el modulo 'Terminal-Icons' para mostrar iconos en los archivos o carpetas." + 
	"`n- Se agrega el modulo 'z' para moverse entre directorios mas rapido." + 
	"`n- Se habilita el modo 'ListView' para mostrar las sugerencias en forma de lista.`n"
	$varTextBlock2 = "SHELL POWERSHELL" + 
	"`n- Se agrega un prompt personalizado de oh-my-posh con el tema 'kali'.`n"
	$varTextBlock3 = "SHELL CMD" + 
	"`n- Se agrega el complemento 'Clink' para ampliar las funcionalidades de la Shell." + 
	"`n- Se agrega un prompt personalizado de oh-my-posh con el tema 'stelbent'.`n"

	$window = GenerateWinGUIShell "SELECCIONE LOS PERFILES QUE DESEA AÑADIR" "Aplicar"
	GenerateTextBlock $varTextBlock1 "Aplicar PERFIL" $window "TextBlock1" "CheckBox1"
	GenerateTextBlock $varTextBlock2 "Aplicar PERFIL" $window "TextBlock2" "CheckBox2"
	GenerateTextBlock $varTextBlock3 "Aplicar CONFIG" $window "TextBlock3" "CheckBox3"

	$window.FindName("ActionButton").Add_Click({
		
		Write-Host "==  SELECTED OPERATIONS  =="
		if ( $window.FindName("CheckBox1").IsChecked ) {
			Custom_Shell_Pwsh
		}
		if ( $window.FindName("CheckBox2").IsChecked ) {
			Custom_Shell_Powershell
		}
		if ( $window.FindName("CheckBox3").IsChecked ) {
			Write-Host "FUNCION EN MANTENIMIENTO => Custom_Shell_Cmd"
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
		$window.Close()
	})

	$window.ShowDialog()
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
	# "║ [1] Privacy & Security     ║"
	# "║ [2] WindowsUpdate Behavior ║"
	"║ [1] Performance Mode       ║"
	"║ [2] Go Back                ║"
	"╚════════════════════════════╝"
}

# drawing SubMenu3
function Show-SubMenu3 {
	Write-Host ""
	"╔════════════════════════════╗"
	"║         SUB-MENU-3         ║"
	"╠════════════════════════════╣"
	# "║ [1] Remove Capability      ║"
	# "║ [2] Remove Package         ║"
	"║ [1] Remove Provisioned     ║"
	"║ [2] Go Back                ║"
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
	# "║ [2] Customize pwsh         ║"
	# "║ [3] Customize powershell   ║"
	"║ [2] Customize Shell        ║"
	"║ [3] Go Back                ║"
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
		<#
		1 {
			Clear-Host
			Write-Host "Set Privacy"
			Write-Host "Do you want disable Web results, Cortana results, Diagnoctics data, Activity history?"

			Invoke-Confirmation { "FUNCION OBSOLETA" }
			break
		}
		2 {
			Clear-Host
			Write-Host "Set Windows Update Behavior"
			Write-Host "Do you want enable Manual Update, disable Preliminary Updates & Product Updates?"

			Invoke-Confirmation { "FUNCION OBSOLETA" }
			break
		}
		#>
		1 {
			Clear-Host
			Write-Host "Set Performance Mode"
			Write-Host "Do you want enable the TRIM, MemoryCompression, Minimum VisualEffects. Change the CPU usage for Windows Defender?"

			Invoke-Confirmation { Set_PrivacySecu_UpdateBeha_PerformanceMode }
			break
		}
		2 {
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
		<#
		1 {
			Clear-Host
			Write-Host "Remove AppCapabilityPackages"
			Write-Host "Do you want to remove App from the local host?"

			Invoke-Confirmation { "FUNCION OBSOLETA Remove_Capability_App" }
			break
		}
		2 {
			Clear-Host
			Write-Host "Remove AppxUserPackages"
			Write-Host "Do you want to remove Appx from the current user account?"

			Invoke-Confirmation { "FUNCION OBSOLETA Remove_User_Appx" }
			break
		}
		#>
		1 {
			Clear-Host
			Write-Host "Remove AppxProvisionedPackages"
			Write-Host "Do you want to remove Appx from Windows image?"

			Invoke-Confirmation { Remove_Capability_Package_Provisioned }
			break
		}
		2 {
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
		<#
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
		#>
		2 {
			Clear-Host
			Write-Host "Customize cmd"
			Write-Host "Do you want to customize cmd?"

			Invoke-Confirmation { Custom_Pwsh_Powershell_Cmd }
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

		$wingetCondition = winget upgrade --accept-source-agreements --accept-package-agreements
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
$Host.UI.RawUI.WindowTitle = "Dead Script 💀"

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

# Sleep for 3 seconds
Start-Sleep -Milliseconds 3000

# Policy Execution Restart
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "CurrentUser" -Force
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "Process" -Force
