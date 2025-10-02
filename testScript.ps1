
# Policy Execution Enable
# Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope "LocalMachine" -Force
# Set-ExecutionPolicy -ExecutionPolicy "Bypass" -Scope "LocalMachine" -Force

#####################################################
#	ABOUT_SCRIPT
#####################################################

# Show script info
$global:WPAuthor = "D_E_M_O_N"
$global:WPName = "WinCustom"
$global:WPVersion = "v0.19.10"
$WPRepository = "https://raw.githubusercontent.com/DiegoEli/test-script/refs/heads/testing/testScript.ps1"
# $WPRepository = "https://raw.githubusercontent.com/DiegoEli/WinCustom/refs/heads/main/WinCustom.ps1"

<#
.NOTES
	Author  : Diego Mendoza(JuanPerez)
	Github  : https://github.com/DiegoEli
	Name    : WinCust
	Version : v0.19.10

.PARAMETER [Aliases]
	irm = Invoke-RestMethod
	iex = Invoke-Expression

.EXAMPLE
	::Run the script from the repository remote.
	
	irm "https://raw.githubusercontent.com/DiegoEli/test-script/refs/heads/temp/testScript.ps1" | iex

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

		Write-Host "Item [$itemPath\$itemName] not found, Creating..." -ForegroundColor Yellow
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

		Write-Host "Property [$proPath\$proName] not found, Creating..." -ForegroundColor Yellow
		$null = New-ItemProperty -Path $proPath -Name $proName -PropertyType $proType -Value "0" -Force
	}
}

# Variable para usar colores de forma cruda
$_esc = [char]0x1B

# function Set Option Status
function Set-OptionValue {
	param (
		[string]$optPath,
		[string]$optProperty,
		[string]$optType,
		[string]$optValue
	)

	Test-PropertyPath $optPath $optProperty $optType

	$currentValue = (Get-ItemProperty -Path $optPath).$optProperty

	if ( $currentValue -ne $optValue ) {

		Write-Host "Setting value [$_esc[1;34m$optPath\$optProperty$_esc[0m], Changing..."
		Set-ItemProperty -Path $optPath -Name $optProperty -Value $optValue -Force
	} 
	else {
		Write-Host "Value [$_esc[1;34m$optPath\$optProperty$_esc[0m] remains Changed."
	}
}

Add-Type -AssemblyName PresentationFramework

function GenerateWinGUIMenu {
	$XAML = @"
	<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
			Title="WinCustom 💀" Height="490" Width="910"
			Background="#272727" Foreground="White"
			FontFamily="Segoe UI" FontSize="14" FontWeight="Bold"
			WindowStartupLocation="CenterScreen">
		<Grid>
			<Grid.ColumnDefinitions>
				<ColumnDefinition Width="280"/>
				<ColumnDefinition Width="*"/>
			</Grid.ColumnDefinitions>
		
			<!-- Menú lateral sin Padding -->
			<StackPanel Grid.Column="0" Background="#202020" Orientation="Vertical">
				<TextBlock Text="WinCustom by Diego" Margin="10" FontFamily="Segoe UI" FontSize="16" FontWeight="Bold"/>
				<Button Name="BtnChaPreference" Content="Cambiar Preferencias" Margin="10" Height="35" Background="#3A3A3D" Foreground="White"/>
				<Button Name="BtnEsseTweaks" Content="Ajsutes Esenciales" Margin="10" Height="35" Background="#3A3A3D" Foreground="White"/>
				<Button Name="BtnRemBloatware" Content="Remover Bloatware" Margin="10" Height="35" Background="#3A3A3D" Foreground="White"/>
				<Button Name="BtnAddAppTool" Content="Añadir Apps-Tools" Margin="10" Height="35" Background="#3A3A3D" Foreground="White"/>
				<Button Name="BtnCustoTerminal" Content="Personalizar Shell" Margin="10" Height="35" Background="#3A3A3D" Foreground="White"/>
			</StackPanel>
		
			<!-- Contenido principal -->
			<Grid Grid.Column="1" Name="MainContent" Margin="10">
			</Grid>
		</Grid>
	</Window>
"@
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
    $window = [Windows.Markup.XamlReader]::Load($reader)
    return $window
}

function GenerateWinGUIMod ($varTitle, $varAction) {
	
	$XAML = @"
	<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
		<!-- Definición de Filas -->
		<Grid.RowDefinitions>
			<RowDefinition Height="Auto"/>
			<RowDefinition Height="*"/>
			<RowDefinition Height="Auto"/>
		</Grid.RowDefinitions>
			
		<!-- Definición de Columnas -->
		<Grid.ColumnDefinitions>
			<ColumnDefinition Width="*"/>
			<ColumnDefinition Width="*"/>
			<ColumnDefinition Width="*"/>
		</Grid.ColumnDefinitions>

		<!-- Titulo que desribira que se hace -->
		<TextBlock Grid.Row="0" Grid.ColumnSpan="3" Text="$varTitle" Margin="10" TextWrapping="Wrap"/>

		<!-- Marco (Border) con ScrollViewer para los CheckBox -->
		<Border Grid.Row="1" Grid.Column="0" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
				<StackPanel Name="ListContainer1">
					<TextBlock Name="TextBlock1" Margin="5,2,5,2" TextWrapping="Wrap"/>
				</StackPanel>
			</ScrollViewer>
		</Border>

		<!-- Panel de Lista 1 -->
		<Border Grid.Row="1" Grid.Column="1" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto">
				<StackPanel>
					<TextBlock Name="TextBlock2" Margin="5,2,5,2" TextWrapping="Wrap"/>
					<CheckBox Name="CheckBox2" Margin="5,2,5,2" Foreground="White"/>

					<TextBlock Name="TextBlock3" Margin="5,2,5,2" TextWrapping="Wrap"/>
					<CheckBox Name="CheckBox3" Margin="5,2,5,2" Foreground="White"/>
				</StackPanel>
			</ScrollViewer>
		</Border>

		<!-- Marco (Border) con ScrollViewer para los CheckBox -->
		<Border Grid.Row="1" Grid.Column="2" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
				<StackPanel Name="ListContainer4">
					<TextBlock Name="TextBlock4" Margin="5,2,5,2" TextWrapping="Wrap"/>
				</StackPanel>
			</ScrollViewer>
		</Border>

		<!-- Botón de Selección -->
		<Button Grid.Row="2" Grid.ColumnSpan="3" Content="$varAction" Height="30" Width="100" Background="LightGray" Foreground="Black" 
				Name="ActionButton" BorderBrush="Transparent" HorizontalAlignment="Center" Margin="10"/>
	</Grid>
"@
	
	# Cargar la interfaz
	$reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
	$gridWin = [Windows.Markup.XamlReader]::Load($reader)
	
	return $gridWin
}

function GenerateWinGUITriple ($varTitle, $varAction) {
	
	$XAML = @"
	<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
		<!-- Definición de Filas -->
		<Grid.RowDefinitions>
			<RowDefinition Height="Auto"/>
			<RowDefinition Height="*"/>
			<RowDefinition Height="Auto"/>
		</Grid.RowDefinitions>
			
		<!-- Definición de Columnas -->
		<Grid.ColumnDefinitions>
			<ColumnDefinition Width="*"/>
			<ColumnDefinition Width="*"/>
			<ColumnDefinition Width="*"/>
		</Grid.ColumnDefinitions>
			
		<!-- Titulo que describe qué se hace -->
		<TextBlock Grid.Row="0" Grid.ColumnSpan="3" Text="$varTitle" Margin="10" TextWrapping="Wrap"/>

		<!-- Panel de Lista 1 -->
		<Border Grid.Row="1" Grid.Column="0" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
				<StackPanel Name="ListContainer1">
					<TextBlock Name="TextBlock1" Margin="5,2,5,2" TextWrapping="Wrap"/>
				</StackPanel>
			</ScrollViewer>
		</Border>
			
		<!-- Panel de Lista 2 -->
		<Border Grid.Row="1" Grid.Column="1" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
				<StackPanel Name="ListContainer2">
					<TextBlock Name="TextBlock2" Margin="5,2,5,2" TextWrapping="Wrap"/>
				</StackPanel>
			</ScrollViewer>
		</Border>

		<!-- Panel de Lista 3 -->
		<Border Grid.Row="1" Grid.Column="2" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
				<StackPanel Name="ListContainer3">
					<TextBlock Name="TextBlock3" Margin="5,2,5,2" TextWrapping="Wrap"/>
				</StackPanel>
			</ScrollViewer>
		</Border>

		<!-- Botón de Selección -->
		<Button Grid.Row="2" Grid.ColumnSpan="3" Content="$varAction" Height="30" Width="100" Background="LightGray" Foreground="Black" 
				Name="ActionButton" BorderBrush="Transparent" HorizontalAlignment="Center" Margin="10"/>
	</Grid>
"@
	
	# Cargar la interfaz
	$reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
	$gridWin = [Windows.Markup.XamlReader]::Load($reader)
	
	return $gridWin
}

function GenerateWinGUIShell ($varTitle, $varAction) {
	
	$XAML = @"
	<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
		<!-- Definición de Filas -->
		<Grid.RowDefinitions>
			<RowDefinition Height="Auto"/>
			<RowDefinition Height="*"/>
			<RowDefinition Height="Auto"/>
		</Grid.RowDefinitions>
			
		<!-- Definición de Columnas -->
		<Grid.ColumnDefinitions>
			<ColumnDefinition Width="*"/>
			<ColumnDefinition Width="*"/>
			<ColumnDefinition Width="*"/>
		</Grid.ColumnDefinitions>
			
		<!-- Titulo que describe qué se hace -->
		<TextBlock Grid.Row="0" Grid.ColumnSpan="3" Text="$varTitle" Margin="10" TextWrapping="Wrap"/>

		<!-- Panel de Lista 1 -->
		<Border Grid.Row="1" Grid.Column="0" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto">
				<StackPanel>
					<TextBlock Name="TextBlock1" Margin="5,2,5,2" TextWrapping="Wrap"/>
					<CheckBox Name="CheckBox1" Margin="5,2,5,2" Foreground="White"/>
				</StackPanel>
			</ScrollViewer>
		</Border>
			
		<!-- Panel de Lista 2 -->
		<Border Grid.Row="1" Grid.Column="1" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto">
				<StackPanel>
					<TextBlock Name="TextBlock2" Margin="5,2,5,2" TextWrapping="Wrap"/>
					<CheckBox Name="CheckBox2" Margin="5,2,5,2" Foreground="White"/>
				</StackPanel>
			</ScrollViewer>
		</Border>
			
		<!-- Panel de Lista 3 -->
		<Border Grid.Row="1" Grid.Column="2" BorderBrush="Gray" BorderThickness="1" Margin="6" Padding="10" CornerRadius="7">
			<ScrollViewer VerticalScrollBarVisibility="Auto">
				<StackPanel>
					<TextBlock Name="TextBlock3" Margin="5,2,5,2" TextWrapping="Wrap"/>
					<CheckBox Name="CheckBox3" Margin="5,2,5,2" Foreground="White"/>
				</StackPanel>
			</ScrollViewer>
		</Border>

		<!-- Botón de Selección -->
		<Button Grid.Row="2" Grid.ColumnSpan="3" Content="$varAction" Height="30" Width="100" Background="LightGray" Foreground="Black" 
				Name="ActionButton" BorderBrush="Transparent" HorizontalAlignment="Center" Margin="10"/>
	</Grid>
"@
	
	# Cargar la interfaz
	$reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
	$gridWin = [Windows.Markup.XamlReader]::Load($reader)
	
	return $gridWin
}

# Diccionario global para almacenar referencias a CheckBoxes actuales
$global:CheckBoxRefs = @{}

function Add-GenerateTextBlock ($currentText, $window, $textBlockName) {
	$textBlock = $window.FindName($textBlockName)
	
	$textBlock.Text = $currentText
}

function GenerateCheckBoxList ($currentList, $window, $listContainerName) {
	$listContainer = $window.FindName($listContainerName)
	
	# Generar CheckBoxes dinámicamente y registrarlos en el objeto $window
	foreach ($item in $currentList) {
		$checkBox = New-Object System.Windows.Controls.CheckBox
		$checkBox.Content = $item.ShowInGUI
		$checkBox.Name = $item.IsXamlId
		$checkBox.Margin = "5,2,5,2"
		$checkBox.Foreground = "White"
		$checkBox.FontWeight = "Bold"
		$listContainer.Children.Add($checkBox)
		$global:CheckBoxRefs[$item.IsXamlId] = $checkBox
	}
	
	return $checkBox
}

function GenerateCheckBox ($checkBoxText, $window, $checkBoxName) {
	$checkBox = $window.FindName($checkBoxName)
	
	$checkBox.Content = $checkBoxText
	$global:CheckBoxRefs[$checkBoxName] = $checkBox
}

# Modification #: Configure preference in Windows
function Opt_AutoLogon {
	$path1 = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'
	$item1 = 'PasswordLess'

	Test-ItemPath $path1 $item1 "Directory"

	$path2 = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess'
	$item2 = 'Device'

	Test-ItemPath $path2 $item2 "Directory"
	
	$netplwizPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
	$property1 = 'DevicePasswordLessBuildVersion'
	$value1 = 0
	
	#"Show checkbox Netplwiz"
	Set-OptionValue $netplwizPath $property1 "DWord" $value1
	
	$AutoLogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
	$property2 = 'AutoAdminLogon'
	$value2 = 1

	#"Enable Auto Logon"
	Set-OptionValue $AutoLogonPath $property2 "DWord" $value2
}

function Opt_FastStartup {
	$fastStartupPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
	$property = 'HiberbootEnabled'
	$value = 0  #ON $value = 1

	#"FastStartup has been Disabled"
	Set-OptionValue $fastStartupPath $property "DWord" $value
}

function Opt_VerboseLogon {
	$verboseLogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	$property = 'VerboseStatus'
	$value = 1
	
	#"VerboseLogon has been Enabled"
	Set-OptionValue $verboseLogonPath $property "DWord" $value
}

function Opt_ShowBuildVersion {
	$showVersionPath = 'HKCU:\Control Panel\Desktop'
	$property = 'PaintDesktopVersion'
	$value = 1

	#"ShowVersion has been Enabled"
	Set-OptionValue $showVersionPath $property "DWord" $value
}

function Opt_HibernateMode {
	$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
	$item = 'FlyoutMenuSettings'

	Test-ItemPath $path $item "Directory"

	$hibernateOptPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings'
	$property1 = 'ShowHibernateOption'
	$value1 = 0

	#"Hide Option Hibernate"
	Set-OptionValue $hibernateOptPath $property1 "DWord" $value1

	$hibernateModePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
	$property2 = 'HibernateEnabled'
	$value2 = 0

	#"Hibernate has been Disabled"
	Set-OptionValue $hibernateModePath $property2 "DWord" $value2

	#"Disable Hibernate Mode"
	powercfg /hibernate off
}

function Opt_StartupSound {
	$path1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation'
	$property1 = 'DisableStartupSound'
	$value1 = 1

	# Option change value
	Set-OptionValue $path1 $property1 "DWord" $value1
	
	$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'
	$item = 'EditionOverrides'

	Test-ItemPath $path $item "Directory"
	
	$path2 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EditionOverrides'
	$property2 = 'UserSetting_DisableStartupSound'
	$value2 = 1
	
	# Option change value
	Set-OptionValue $path2 $property2 "DWord" $value2
}

function Opt_CommunicationsActivity {
	$comunicationPath = 'HKCU:\Software\Microsoft\Multimedia\Audio'
	$property = 'UserDuckingPreference'
	$value = 3

	# Option change value
	Set-OptionValue $comunicationPath $property "DWord" $value
}

function Opt_MousePrecision {
	$mousePath = 'HKCU:\Control Panel\Mouse'
	$property1 = 'MouseSpeed'
	$property2 = 'MouseThreshold1'
	$property3 = 'MouseThreshold2'
	$value = 0
	
	# Option change value
	Set-OptionValue $mousePath $property1 "DWord" $value
	Set-OptionValue $mousePath $property2 "DWord" $value
	Set-OptionValue $mousePath $property3 "DWord" $value
}

# Modification 1: StorageSense in Windows(revisar si existe)
function Opt_StorageSense {
	$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters'
	$item = 'StoragePolicy'

	Test-ItemPath $path $item "Directory"

	$storageSensePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
	$property1 = '01'
	$property2 = '04'
	$value = 0
	
	#"StorageSense has been Disabled"
	Set-OptionValue $storageSensePath $property1 "DWord" $value
	Set-OptionValue $storageSensePath $property2 "DWord" $value
}

function Opt_SnapSuggest {
	$snapSuggestPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property1 = 'SnapAssist'  # 1-Suggest Snap Next
	$property2 = 'EnableSnapAssistFlyout'  # 2-Show snap layouts I hover
	$property3 = 'EnableSnapBar'  # 3-Show snap layouts I drag
	$value = 0

	#"SnapSuggest has been Disabled"
	Set-OptionValue $snapSuggestPath $property1 "DWord" $value
	Set-OptionValue $snapSuggestPath $property2 "DWord" $value
	Set-OptionValue $snapSuggestPath $property3 "DWord" $value
}

function Opt_ShowTabsApps {
	$showTabsPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'MultiTaskingAltTabFilter'
	$value = 3
	
	#"Show TabsApps has been Disabled"
	Set-OptionValue $showTabsPath $property "DWord" $value
}

function Opt_ShowFileExtensions {
	$fileExtenPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'HideFileExt'
	$value = 0

	#"Show FileExtensions has been Enabled"
	Set-OptionValue $fileExtenPath $property "DWord" $value
}

function Opt_ShowHiddenFiles {
	$hiddenFilesPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'Hidden'
	$value = 1

	#"Show HiddenFilesFolders has been Enabled"
	Set-OptionValue $hiddenFilesPath $property "DWord" $value
}

function Opt_OpenFileExplorer {
	$openFileExpPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'LaunchTo'
	$value = 1

	Set-OptionValue $openFileExpPath $property "DWord" $value
}

function Opt_ShowSyncProvider {
	$syncProviderPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSyncProviderNotifications'
	$value = 0

	#"Show SyncProvider has been Disabled"
	Set-OptionValue $syncProviderPath $property "DWord" $value
}

function Opt_ShowEndTask {
	$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$item = 'TaskbarDeveloperSettings'

	Test-ItemPath $path $item "Directory"

	$showEndTaskPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'
	$property = 'TaskbarEndTask'
	$value = 1

	#"Show EndTask has been Enabled"
	Set-OptionValue $showEndTaskPath $property "DWord" $value
}

function Opt_SudoCommand {
	$sudoCommandPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
	$property = 'Enabled'
	$value = 3

	# Option change value
	Set-OptionValue $sudoCommandPath $property "DWord" $value
}

function Opt_DarkMode {
	$darkModeThemePath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property1 = 'SystemUsesLightTheme'  # 1-Choose Windows Mode
	$property2 = 'AppsUseLightTheme'  # 2-Choose App Mode
	$property3 = 'ColorPrevalence'  # 3-Show Accent color
	$value = 0
	
	#"Dark Mode has been Enabled"
	Set-OptionValue $darkModeThemePath $property1 "DWord" $value
	Set-OptionValue $darkModeThemePath $property2 "DWord" $value
	Set-OptionValue $darkModeThemePath $property3 "DWord" $value
}

function Opt_ShowItemSearch {
	$itemSearchPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
	$property = 'SearchboxTaskbarMode'
	$value = 0

	#"Show Item Search has been Disabled"
	Set-OptionValue $itemSearchPath $property "DWord" $value
}

function Opt_ShowItemTaskView {
	$itemTaskViewPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowTaskViewButton'
	$value = 0
	
	#"Show Item TaskView has been Disabled"
	Set-OptionValue $itemTaskViewPath $property "DWord" $value
}

function Opt_ShowDesktop {
	$showDesktopPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'TaskbarSd'
	$value = 1

	#"ShowDesktop has been Enabled"
	Set-OptionValue $showDesktopPath $property "DWord" $value
}

function Set-LanguageBarS {
	param (
		[string]$property,
		[string]$state
	)

	if ( (Get-WinLanguageBarOption).$property -notlike $state ) {

		Write-Host "Setting value [$_esc[1;36m$property$_esc[0m], Changing..."
		Set-WinLanguageBarOption -UseLegacyLanguageBar
	} 
	else {
		Write-Host "Value [$_esc[1;36m$property$_esc[0m] remains Changed."
	}
}

function Opt_ShowLanguageBar {
	#CAMBIAR PARA CORREGIR COMPORTAMIENTO
	# 1-Switching input methods
	$propertyM = 'IsLegacySwitchingMode'
	$propertyB = 'IsLegacyLanguageBar'
	$stateM = $false
	$stateB = $true

	# Option change state
	Set-LanguageBarS $propertyM $stateM  # IsLegacySwitchingMode: False
	Set-LanguageBarS $propertyB $stateB  # IsLegacyLanguageBar: True

	# 2-Language Bar
	$path = 'HKCU:\Software\Microsoft\CTF'
	$item = 'LangBar'

	Test-ItemPath $path $item "Directory"
	
	$LanguageBarPath = 'HKCU:\Software\Microsoft\CTF\LangBar'
	$property1 = 'ShowStatus'
	$property2 = 'Transparency'
	$property3 = 'ExtraIconsOnMinimized'
	$property4 = 'Label'
	$value1 = 3
	$value2 = 255
	$value3 = 0

	# Option change value
	Set-OptionValue $LanguageBarPath $property1 "DWord" $value1
	Set-OptionValue $LanguageBarPath $property2 "DWord" $value2
	Set-OptionValue $LanguageBarPath $property3 "DWord" $value3
	Set-OptionValue $LanguageBarPath $property4 "DWord" $value3
}

function Opt_ShowSeconds {
	#CAMBIAR PARA CORREGIR COMPORTAMIENTO
	$secondsClockPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ShowSecondsInSystemClock'
	$value = 1

	#"ShowSeconds has been Enabled"
	Set-OptionValue $secondsClockPath $property "DWord" $value
}

function Opt_GameBar {
	$gameBarPath = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'UseNexusForGameBarEnabled'
	$value = 0

	#"GameBar has been Disabled"
	Set-OptionValue $gameBarPath $property "DWord" $value
}

function Opt_GameMode {
	$gameModePath = 'HKCU:\Software\Microsoft\GameBar'
	$property = 'AutoGameModeEnabled'
	$value = 0

	#"GameMode has been Disabled"
	Set-OptionValue $gameModePath $property "DWord" $value
}

# Disables Bitlocker Auto Encryption on Windows(REVISAR)
function Opt_DeviceEncryption {
	$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
	$path2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices'
	$property1 = 'PreventDeviceEncryption'
	$property2 = 'TCGSecurityActivationDisabled'
	$value = 1
	
	#"Bitlocker has been Disabled"
	Set-OptionValue $path1 $property1 "DWord" $value
	Set-OptionValue $path2 $property2 "DWord" $value
}

function Remove_GalleryIcon {
	$path = 'HKCU:\Software\Classes\CLSID'
	$item = '{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}'

	Test-ItemPath $path $item "Directory"

	$rmGalleryPath = "HKCU:\Software\Classes\CLSID\$item"
	$property = 'System.IsPinnedToNamespaceTree'
	$value = 0

	# Change value option
	Set-OptionValue $rmGalleryPath $property "DWord" $value
}

function Remove_DesktopIcons {
	$rmIconsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
	$property1 = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'  # Show Computer Icon
	$property2 = '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}'  # Show Control Panel Icon
	$property3 = '{59031a47-3f72-44a7-89c5-5595fe6b30ee}'  # Show User´s Files Icon
	$property4 = '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'  # Show Network Icon
	$value = 1

	# Change value option
	Set-OptionValue $rmIconsPath $property1 "DWord" $value
	Set-OptionValue $rmIconsPath $property2 "DWord" $value
	Set-OptionValue $rmIconsPath $property3 "DWord" $value
	Set-OptionValue $rmIconsPath $property4 "DWord" $value
}

$optionList = @(
	@{ ShowInGUI = "Activar Logeo Automatico"; IsXamlId = "AutoLogon"; IsOperation = "Opt_AutoLogon" }
	@{ ShowInGUI = "Desactivar Inico Rapido"; IsXamlId = "FastStartup"; IsOperation = "Opt_FastStartup" }
	@{ ShowInGUI = "Activar Mensajes Detallados de Inicio"; IsXamlId = "VerboseLogon"; IsOperation = "Opt_VerboseLogon" }
	@{ ShowInGUI = "Mostrar Version de Build en Desktop"; IsXamlId = "ShowBuildVersion"; IsOperation = "Opt_ShowBuildVersion" }
	@{ ShowInGUI = "Desactivar Modo Hibernacion (Desktop PC)"; IsXamlId = "HibernateMode"; IsOperation = "Opt_HibernateMode" }
	@{ ShowInGUI = "Desactivar Sonidos de Inicio de Windows"; IsXamlId = "StartupSound"; IsOperation = "Opt_StartupSound" }
	@{ ShowInGUI = "Desactivar Ajustar Volumen de Sonidos"; IsXamlId = "CommunicationsActivity"; IsOperation = "Opt_CommunicationsActivity" }
	@{ ShowInGUI = "Desactivar Precision de Puntero"; IsXamlId = "MousePrecision"; IsOperation = "Opt_MousePrecision" }
	@{ ShowInGUI = "Desactivar Sensor de Almacenamiento"; IsXamlId = "StorageSense"; IsOperation = "Opt_StorageSense" }
	# @{ ShowInGUI = "Desactivar Encriptacion del Equipo"; IsXamlId = "DeviceEncryption"; IsOperation = "Opt_DeviceEncryption" }
	@{ ShowInGUI = "Desactivar Sugerencias para Snap"; IsXamlId = "SnapSuggest"; IsOperation = "Opt_SnapSuggest" }
	@{ ShowInGUI = "Desactivar Tabs Individuales para Edge"; IsXamlId = "ShowTabsApps"; IsOperation = "Opt_ShowTabsApps" }
	@{ ShowInGUI = "Mostrar Extensiones de Archivos"; IsXamlId = "ShowFileExtensions"; IsOperation = "Opt_ShowFileExtensions" }
	@{ ShowInGUI = "Mostrar Archivos Ocultos del Sistema"; IsXamlId = "ShowHiddenFiles"; IsOperation = "Opt_ShowHiddenFiles" }
	@{ ShowInGUI = "Siempre Iniciar FileExplorer en (Este Equipo)"; IsXamlId = "OpenFileExplorer"; IsOperation = "Opt_OpenFileExplorer" }
	@{ ShowInGUI = "Ocultar Proveedor de Sincronizacion"; IsXamlId = "ShowSyncProvider"; IsOperation = "Opt_ShowSyncProvider" }
	@{ ShowInGUI = "Habilitar Boton para Finalizar Tarea"; IsXamlId = "ShowEndTask"; IsOperation = "Opt_ShowEndTask" }
	# @{ ShowInGUI = "Habilitar Comando Sudo"; IsXamlId = "SudoCommand"; IsOperation = "Opt_SudoCommand" }
	@{ ShowInGUI = "Activar Full Modo Oscuro"; IsXamlId = "DarkMode"; IsOperation = "Opt_DarkMode" }
	@{ ShowInGUI = "Ocultar Icono de Search"; IsXamlId = "ShowItemSearch"; IsOperation = "Opt_ShowItemSearch" }
	@{ ShowInGUI = "Ocultar Icono de TaskView"; IsXamlId = "ShowItemTaskView"; IsOperation = "Opt_ShowItemTaskView" }
	@{ ShowInGUI = "Habilitar Boton para Mostrar el Desktop"; IsXamlId = "ShowDesktop"; IsOperation = "Opt_ShowDesktop" }
	# @{ ShowInGUI = "Ocultar la Barra de Lenguaje"; IsXamlId = "ShowLanguageBar"; IsOperation = "Opt_ShowLanguageBar" }
	# @{ ShowInGUI = "Mostrar Segundos en Reloj"; IsXamlId = "ShowSeconds"; IsOperation = "Opt_ShowSeconds" }
	@{ ShowInGUI = "Desactivar Barra de Juego"; IsXamlId = "GameBar"; IsOperation = "Opt_GameBar" }
	# @{ ShowInGUI = "Desactivar Modo de Juego"; IsXamlId = "GameMode"; IsOperation = "Opt_GameMode" }
	@{ ShowInGUI = "Remover Icono de Galeria en Explorer"; IsXamlId = "GalleryIcon"; IsOperation = "Remove_GalleryIcon" }
	@{ ShowInGUI = "Remover Iconos del Sistema en Desktop"; IsXamlId = "DesktopIcons"; IsOperation = "Remove_DesktopIcons" }
)

# Modification #: Configure service in Windows
# Get-Service | Sort-Object Status, DisplayName | Format-Table -GroupBy Status -Property Status, Name, DisplayName
function ConfigService ($serviceId, $startupType) {
	$service = Get-Service -Name $serviceId -ErrorAction SilentlyContinue
	
	if ( $null -ne $service ) {
		
		Write-Host "Setting service [$_esc[1;36m$serviceId$_esc[0m] to $startupType."
		Set-Service -Name "$serviceId" -StartupType $startupType
		Stop-Service -Name "$serviceId"
	} 
	else {
		Write-Warning "Setting service [$serviceId] to $startupType, Service not found."
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
	"SysMain",                        #SysMain
	"wuauserv"                        #Windows Update
)

function Set_Service_Startup () {
	
	foreach ($serviceId in $disableList) {
		ConfigService $serviceId Disabled
	}
	
	foreach ($serviceId in $manualList) {
		ConfigService $serviceId Manual
	}
}

# Modification #: Configure Task Sheduler in Windows
# Get-ScheduledTask | Sort-Object State, TaskPath, TaskName | Format-Table -GroupBy State -Property TaskPath, TaskName, State
function ConfigTask ($taskPath, $taskName, $stateType) {
	$task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
	
	$newState = $stateType.Substring(0, $stateType.Length - 1)
	if ( $null -ne $task ) {
		
		Write-Host "Setting task [$_esc[1;36m$taskName$_esc[0m] to $stateType."
		$null = Invoke-Expression "$newState-ScheduledTask -TaskPath `"$taskPath`" -TaskName `"$taskName`""
	}
	else {
		Write-Warning "Setting task [$taskName] to $stateType, Task not found."
	}
}

$disableTList = @(
	@{ Path = "\"; Name = "MicrosoftEdgeUpdateTaskMachineCore" }
	@{ Path = "\"; Name = "MicrosoftEdgeUpdateTaskMachineUA" }
	@{ Path = "\Microsoft\Windows\Application Experience\"; Name = "MareBackup" }
	@{ Path = "\Microsoft\Windows\Application Experience\"; Name = "Microsoft Compatibility Appraiser" }
	@{ Path = "\Microsoft\Windows\Application Experience\"; Name = "PcaPatchDbTask" }
	@{ Path = "\Microsoft\Windows\Application Experience\"; Name = "StartupAppTask" }
	@{ Path = "\Microsoft\Windows\Autochk\"; Name = "Proxy" }
	@{ Path = "\Microsoft\Windows\Customer Experience Improvement Program\"; Name = "Consolidator" }
	@{ Path = "\Microsoft\Windows\Customer Experience Improvement Program\"; Name = "UsbCeip" }
	@{ Path = "\Microsoft\Windows\DiskDiagnostic\"; Name = "Microsoft-Windows-DiskDiagnosticDataCollector" }
	@{ Path = "\Microsoft\Windows\Feedback\Siuf\"; Name = "DmClient" }
	@{ Path = "\Microsoft\Windows\Feedback\Siuf\"; Name = "DmClientOnScenarioDownload" }
	@{ Path = "\Microsoft\Windows\Maps\"; Name = "MapsUpdateTask" }
	@{ Path = "\Microsoft\Windows\Windows Defender\"; Name = "Windows Defender Verification" }
	@{ Path = "\Microsoft\Windows\Windows Error Reporting\"; Name = "QueueReporting" }
	@{ Path = "\Microsoft\Windows\WindowsUpdate\"; Name = "Scheduled Start" }
	@{ Path = "\Microsoft\XblGameSave\"; Name = "XblGameSaveTask" }
	@{ Path = "\Microsoft\Office\"; Name = "Office Performance Monitor" }
	@{ Path = "\Microsoft\Office\"; Name = "Office Feature Updates Logon" }
	@{ Path = "\Microsoft\Office\"; Name = "Office Feature Updates" }
	@{ Path = "\Microsoft\Office\"; Name = "Office Automatic Updates 2.0" }
)

function Set_Scheduled_Task () {
	
	foreach ($task in $disableTList) {
		ConfigTask $task.Path $task.Name Disabled
	}
}

# Modification #: Configure Enable or Disable features in Windows
# Get-WindowsOptionalFeature -Online | Sort-Object State, FeatureName | Format-Table -GroupBy State -Property FeatureName, State
function ConfigFeature ($featureName, $stateType) {
	$feature = Get-WindowsOptionalFeature -FeatureName $featureName -Online
	
	$newState = $stateType.Substring(0, $stateType.Length - 1)
	if ( $null -ne $feature ) {
		
		Write-Host "Setting feature [$_esc[1;36m$featureName$_esc[0m] to $stateType."
		$null = Invoke-Expression "$newState-WindowsOptionalFeature -FeatureName `"$featureName`" -NoRestart -Online"
	} 
	else {
		Write-Warning "Setting feature [$featureName] to $stateType, Feature not found."
		# "Cannot find path 'HKCU:\Software\Microsoft' because it does not exist."
	}
}

$disableFList = @(
	@{ ShowInGUI = "Desactivar Internet Explorer 11"; IsXamlId = "Internet_Explorer"; IsOperation = "Internet-Explorer-Optional-amd64" }
	@{ ShowInGUI = "Desactivar Media Features"; IsXamlId = "MediaPlay"; IsOperation = "MediaPlayback" }
	@{ ShowInGUI = "Desactivar Windows Media Player"; IsXamlId = "MediaPlayer"; IsOperation = "WindowsMediaPlayer" }
	@{ ShowInGUI = "Desactivar Microsoft XPS Document Writer"; IsXamlId = "XPSServices"; IsOperation = "Printing-XPSServices-Features" }
	@{ ShowInGUI = "Desactivar Work Folders Client"; IsXamlId = "WorkFolders"; IsOperation = "WorkFolders-Client" }
	@{ ShowInGUI = "Desactivar Windows Search"; IsXamlId = "SearchEngine"; IsOperation = "SearchEngine-Client-Package" }
	@{ ShowInGUI = "Desactivar Recall"; IsXamlId = "Recall"; IsOperation = "Recall" }
)

$enableFList = @(
	@{ ShowInGUI = "Activar .NET Framework 3.5"; IsXamlId = "NetFramework"; IsOperation = "NetFx3" }
	@{ ShowInGUI = "Activar Virtual Machine Platform"; IsXamlId = "VM_Platform"; IsOperation = "VirtualMachinePlatform" }
	@{ ShowInGUI = "Activar Windows Hypervisor Platform"; IsXamlId = "HypervisorPlatform"; IsOperation = "HypervisorPlatform" }
	@{ ShowInGUI = "Activar Windows Subsystem Linux"; IsXamlId = "SubsystemLinux"; IsOperation = "Microsoft-Windows-Subsystem-Linux" }
	@{ ShowInGUI = "Activar Windows Sandbox"; IsXamlId = "ClientVM"; IsOperation = "Containers-DisposableClientVM" }
)

function Set_Option_ServiceTask_Feature ($mainContent) {
	# Limpia las referencias de CheckBoxes previas
	$global:CheckBoxRefs.Clear()

	$varTextBlock1 = "SERVICIOS" +
	"`n- Se establece el modo deshabilitado para los servicios que no son requiridos para el usuario medio." +
	"`n- Se establece el modo manual para los servicios que son requeridos solo bajo demanda del usuario."
	$varTextBlock2 = "`nTAREAS PROGRAMADAS" +
	"`n- Se establece el modo deshabilitado para las tareas programadas que por temas de seguridad requieren confirmacion del usuario."

	$panelWindow = GenerateWinGUIMod "SELECCIONE LAS PREFERENCIAS, SETEE LOS SERVICIOS, SETEE LAS TAREAS PROGRAMADAS Y LAS CARACTERISTICAS OPCIONALES" "Aplicar"
	$mainContent.Children.Clear()
	$mainContent.Children.Add($panelWindow)

	Add-GenerateTextBlock "OPCIONES POR DEFECTO" $panelWindow "TextBlock1"
	GenerateCheckBoxList $optionList $panelWindow "ListContainer1"

	Add-GenerateTextBlock $varTextBlock1 $panelWindow "TextBlock2"
	GenerateCheckBox "Aplicar CONFIG" $panelWindow "CheckBox2"
	Add-GenerateTextBlock $varTextBlock2 $panelWindow "TextBlock3"
	GenerateCheckBox "Aplicar CONFIG" $panelWindow "CheckBox3"
	
	Add-GenerateTextBlock "CARACTERISTICAS OPCIONALES" $panelWindow "TextBlock4"
	GenerateCheckBoxList $disableFList $panelWindow "ListContainer4"
	GenerateCheckBoxList $enableFList $panelWindow "ListContainer4"
	
	$captPanelRef = $panelWindow
	$captPanelRef.FindName("ActionButton").Add_Click({
		
		Write-Host "==  SELECTED OPERATIONS  =="
		foreach ($listKey in $optionList) {
			$checkBox1 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox1 -and $checkBox1.IsChecked ) {
				& $listKey.IsOperation
			}
		}
		
		$checkBox2 = $global:CheckBoxRefs["CheckBox2"]
		if ( $checkBox2 -and $checkBox2.IsChecked ) {
			Set_Service_Startup
		}
		$checkBox3 = $global:CheckBoxRefs["CheckBox3"]
		if ( $checkBox3 -and $checkBox3.IsChecked ) {
			Set_Scheduled_Task
		}
		
		foreach ($listKey in $disableFList) {
			$checkBox4 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox4 -and $checkBox4.IsChecked ) {
				ConfigFeature $listKey.IsOperation Disabled
			}
		}
		foreach ($listKey in $enableFList) {
			$checkBox5 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox5 -and $checkBox5.IsChecked ) {
				ConfigFeature $listKey.IsOperation Enabled
			}
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
	})
}

# Modification #: Configure privacity in Windows
function Disable_Spotlight {
	# 1-Disable Spotlight on Desktop
	$spotlightPath1 = 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
	$property1 = 'DisableSpotlightCollectionOnDesktop'
	$value1 = 1

	# Change value option
	Set-OptionValue $spotlightPath1 $property1 "DWord" $value1

	# 2-Disable Windows Spotlight
	$path = 'HKLM:\Software\Policies\Microsoft\Windows'
	$item = 'CloudContent'

	Test-ItemPath $path $item "Directory"

	$spotlightPath2 = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
	$property2 = 'DisableWindowsSpotlightOnLockScreen'
	$property3 = 'DisableWindowsConsumerFeatures'
	$property4 = 'DisableWindowsSpotlightActiveUser'
	$value2 = 1

	# Change value option
	Set-OptionValue $spotlightPath2 $property2 "DWord" $value2
	Set-OptionValue $spotlightPath2 $property3 "DWord" $value2
	Set-OptionValue $spotlightPath2 $property4 "DWord" $value2
}

function Disable_AdditionalSettings {
	$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion'
	$item = 'UserProfileEngagement'

	Test-ItemPath $path $item "Directory"

	$path1 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$path2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'
	$property1 = 'SubscribedContent-310093Enabled'
	$property2 = 'ScoobeSystemSettingEnabled'
	$value = 0

	# Change value option
	Set-OptionValue $path1 $property1 "DWord" $value
	Set-OptionValue $path2 $property2 "DWord" $value
}

function Disable_GetTipsTricks {
	$pathTipsTricks = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$property1 = 'RotatingLockScreenOverlayEnabled'
	$property2 = 'SubscribedContent-338387Enabled'
	$value = 0
	
	#"Facts, Tips & Tricks has been Disabled"
	Set-OptionValue $pathTipsTricks $property1 "DWord" $value
	Set-OptionValue $pathTipsTricks $property2 "DWord" $value
}

function Disable_WinStartInfo {
	$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property1 = 'Start_TrackDocs'
	$property2 = 'Start_IrisRecommendations'
	$property3 = 'Start_AccountNotifications'
	$value = 0

	# Change value option
	Set-OptionValue $path $property1 "DWord" $value
	Set-OptionValue $path $property2 "DWord" $value
	Set-OptionValue $path $property3 "DWord" $value
}

function Disable_PersonalizeAds {
	$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'AdvertisingInfo'

	Test-ItemPath $path $item "Directory"

	# 1-Disable Advertising ID
	$pathProperty1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property1 = 'DisabledByGroupPolicy'
	$value1 = 1

	# Change value option
	Set-OptionValue $pathProperty1 $property1 "DWord" $value1

	# 2-Disable Website Access to Language List
	$pathProperty2 = 'HKCU:\Control Panel\International\User Profile'
	$property2 = 'HttpAcceptLanguageOptOut'
	$value2 = 1

	# Change value option
	Set-OptionValue $pathProperty2 $property2 "DWord" $value2

	# 3-Disable App Launch Tracking
	$pathProperty3 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property3 = 'Start_TrackProgs'
	$value3 = 0
	
	# Change value option
	Set-OptionValue $pathProperty3 $property3 "DWord" $value3

	# 4-Disable Suggested Content in Settings
	$pathProperty4 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	$property4 = 'SubscribedContent-338393Enabled'
	$property5 = 'SubscribedContent-353694Enabled'
	$property6 = 'SubscribedContent-353696Enabled'
	$value4 = 0

	# Change value option
	Set-OptionValue $pathProperty4 $property4 "DWord" $value4
	Set-OptionValue $pathProperty4 $property5 "DWord" $value4
	Set-OptionValue $pathProperty4 $property6 "DWord" $value4
}

function Disable_TypingPersonalization {
	$typingPath = 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings'
	$property = 'AcceptedPrivacyPolicy'
	$value = 0

	# Change value option
	Set-OptionValue $typingPath $property "DWord" $value
}

function Disable_DiagnosticData {
	$path = 'HKCU:\Software\Microsoft\Siuf'
	$item = 'Rules'

	Test-ItemPath $path $item "Directory"

	$telemetryPath1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
	$telemetryPath2 = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
	$telemetryPath3 = 'HKCU:\Software\Microsoft\Siuf\Rules'
	$telemetryPath4 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'
	$property1 = 'AllowTelemetry'
	$property2 = 'NumberOfSIUFInPeriod'
	$property3 = 'TailoredExperiencesWithDiagnosticDataEnabled'
	$value = 0

	# Change value option
	Set-OptionValue $telemetryPath1 $property1 "DWord" $value
	Set-OptionValue $telemetryPath2 $property1 "DWord" $value
	Set-OptionValue $telemetryPath3 $property2 "DWord" $value
	Set-OptionValue $telemetryPath4 $property3 "DWord" $value
}

function Disable_ActivityHistory {
	$activityHistoryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
	$property1 = 'EnableActivityFeed'
	$property2 = 'PublishUserActivities'
	$property3 = 'UploadUserActivities'
	$value = 0
	
	# Change value option
	Set-OptionValue $activityHistoryPath $property1 "DWord" $value
	Set-OptionValue $activityHistoryPath $property2 "DWord" $value
	Set-OptionValue $activityHistoryPath $property3 "DWord" $value
}

function Disable_CortanaResults {
	$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Windows Search'

	Test-ItemPath $path $item "Directory"

	$cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property = 'AllowCortana'
	$value = 0

	# Change value option
	Set-OptionValue $cortanaPath $property "DWord" $value
}

function Disable_WebResults {
	$webSearchPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
	$property1 = 'SafeSearchMode'
	$property2 = 'IsMSACloudSearchEnabled'
	$property3 = 'IsAADCloudSearchEnabled'
	$value1 = 0

	# Change value option
	Set-OptionValue $webSearchPath $property1 "DWord" $value1
	Set-OptionValue $webSearchPath $property2 "DWord" $value1
	Set-OptionValue $webSearchPath $property3 "DWord" $value1

	$webSuggestPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
	$property4 = 'BingSearchEnabled'
	$property5 = 'CortanaConsent'
	$value2 = 0

	# Change value option
	Set-OptionValue $webSuggestPath $property4 "DWord" $value2
	Set-OptionValue $webSuggestPath $property5 "DWord" $value2
}

function Disable_LocalResults {
	$localResultsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
	$property = 'IsDeviceSearchHistoryEnabled'
	$value = 0

	# Change value option
	Set-OptionValue $localResultsPath $property "DWord" $value
}

function Disable_LocationTracking {
	$loctPath1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
	$property1 = 'Value'
	$value1 = 'Deny'

	# Change value option
	Set-OptionValue $loctPath1 $property1 "DWord" $value1

	$loctPath2 = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
	$property2 = 'SensorPermissionState'
	$value2 = 0
	
	# Change value option
	Set-OptionValue $loctPath2 $property2 "DWord" $value2

	# REVISAR SI EXISTE
	# $loctPath3 = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
	# $property3 = 'Status'
	# $value3 = 0
	
	# # Change value option
	# Set-OptionValue $loctPath3 $property3 "DWord" $value3

	$loctPath4 = 'HKLM:\SYSTEM\Maps'
	$property4 = 'AutoUpdateEnabled'
	$value4 = 0
	
	# Change value option
	Set-OptionValue $loctPath4 $property4 "DWord" $value4
}

function Disable_RemoteAssistance {
	$remoteAssPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
	$property1 = 'fAllowFullControl'
	$property2 = 'fAllowToGetHelp'
	$value = 0

	Set-OptionValue $remoteAssPath $property1 "DWord" $value
	Set-OptionValue $remoteAssPath $property2 "DWord" $value
}

$privacyList = @(
	@{ ShowInGUI = "Desactivar Windows Spotlight"; IsXamlId = "Spotlight"; IsOperation = "Disable_Spotlight" }
	@{ ShowInGUI = "Desactivar Experiencia de Bienvenida"; IsXamlId = "AdditionalSettings"; IsOperation = "Disable_AdditionalSettings" }
	@{ ShowInGUI = "Desactivar Obtener Datos, Tips, Trucos"; IsXamlId = "GetTipsTricks"; IsOperation = "Disable_GetTipsTricks" }
	@{ ShowInGUI = "Desactivar Informacion de Menu Inicio"; IsXamlId = "WinStartInfo"; IsOperation = "Disable_WinStartInfo" }
	@{ ShowInGUI = "Desactivar Anuncios Personalizados"; IsXamlId = "PersonalizeAds"; IsOperation = "Disable_PersonalizeAds" }
	@{ ShowInGUI = "Desactivar Tipeo Personalizado"; IsXamlId = "TypingPersonalization"; IsOperation = "Disable_TypingPersonalization" }
	@{ ShowInGUI = "Desactivar Datos de Diagnostico"; IsXamlId = "DiagnosticData"; IsOperation = "Disable_DiagnosticData" }
	@{ ShowInGUI = "Desactivar Historial de Actividades"; IsXamlId = "ActivityHistory"; IsOperation = "Disable_ActivityHistory" }
	@{ ShowInGUI = "Desactivar Resultados de Cortana"; IsXamlId = "CortanaResults"; IsOperation = "Disable_CortanaResults" }
	@{ ShowInGUI = "Desactivar Resultados Web"; IsXamlId = "WebResults"; IsOperation = "Disable_WebResults" }
	@{ ShowInGUI = "Desactivar Resultados Locales"; IsXamlId = "LocalResults"; IsOperation = "Disable_LocalResults" }
	@{ ShowInGUI = "Desactivar Seguimiento de Ubicacion"; IsXamlId = "LocationTracking"; IsOperation = "Disable_LocationTracking" }
	@{ ShowInGUI = "Desactivar Asistencia Remota"; IsXamlId = "RemoteAssistance"; IsOperation = "Disable_RemoteAssistance" }
)

# Modification #: Configure Update behavior in Windows
function Set_DriverAutoInstalls {
	$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'DriverSearching'

	Test-ItemPath $path $item "Directory"

	$searchDriverPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching'
	$property1 = 'DontSearchWindowsUpdate'
	$value1 = 1

	# Change value option
	Set-OptionValue $searchDriverPath $property1 "DWord" $value1

	$path1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item1 = 'WindowsUpdate'
	
	Test-ItemPath $path1 $item1 "Directory"
	
	$excludeDriverPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	$property2 = 'ExcludeWUDriversInQualityUpdate'
	$value2 = 1

	# Change value option
	Set-OptionValue $excludeDriverPath $property2 "DWord" $value2
}

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
	$property4 = 'AUPowerManagement'
	$valueAUO = 2
	$valueNAU = 0
	$valueNAR = 1
	$valueAUP = 0

	# Change value option
	Set-OptionValue $pathUpdateType $property1 "DWord" $valueAUO
	Set-OptionValue $pathUpdateType $property2 "DWord" $valueNAU
	Set-OptionValue $pathUpdateType $property3 "DWord" $valueNAR
	Set-OptionValue $pathUpdateType $property4 "DWord" $valueAUP
}

function Set_PreliminaryUpdates {
	$preliminaryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	$property = 'ManagePreviewBuildsPolicyValue'
	$value = 1

	# Change value option
	Set-OptionValue $preliminaryPath $property "DWord" $value
}

function Set_GetLatestUpdates {
	$latestUpdatesPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property = 'IsContinuousInnovationOptedIn'
	$value = 0

	# Change value option
	Set-OptionValue $latestUpdatesPath $property "DWord" $value
}

function Set_DelayFeatureUpdates {
	$delayFeaturePath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property = 'DeferFeatureUpdatesPeriodInDays'
	$value = 180

	# Change value option
	Set-OptionValue $delayFeaturePath $property "DWord" $value
}

function Set_DelaySecurityUpdates {
	$delaySecurityPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property = 'DeferQualityUpdatesPeriodInDays'
	$value = 15

	# Change value option
	Set-OptionValue $delaySecurityPath $property "DWord" $value
}

function Set_NotifyRestart {
	$notifyrestartPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
	$property = 'RestartNotificationsAllowed2'
	$value = 1
	
	# Change value option
	Set-OptionValue $notifyrestartPath $property "DWord" $value
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
	Set-OptionValue $ActiveHoursPath $property1 "DWord" $value1
	Set-OptionValue $ActiveHoursPath $property2 "DWord" $value2
	Set-OptionValue $ActiveHoursPath $property3 "DWord" $value3
}

function Set_StoreAutoUpdates {
	$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore'
	$item = 'WindowsUpdate'

	Test-ItemPath $path $item "Directory"

	$updatesStorePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate'
	$property = 'AutoDownload'
	$value = 2

	# Change value option
	Set-OptionValue $updatesStorePath $property "DWord" $value
}

function Set_LimitBandwidthUpdates {
	$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
	$item = 'Psched'

	Test-ItemPath $path $item "Directory"

	$bandwidthPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$item"
	$property = 'NonBestEffortLimit'
	$value = 0

	# Change value option
	Set-OptionValue $bandwidthPath $property "DWord" $value
}

$updateList = @(
	@{ ShowInGUI = "Desactivar Instalacion de drivers por Windows Update"; IsXamlId = "DriverAutoInstalls"; IsOperation = "Set_DriverAutoInstalls" }
	@{ ShowInGUI = "Desactivar Actualizaciones Automaticas de Windows"; IsXamlId = "WinAutoUpdates"; IsOperation = "Set_WinAutoUpdates" }
	@{ ShowInGUI = "Desactivar Actualizaciones Preliminares"; IsXamlId = "PreliminaryUpdates"; IsOperation = "Set_PreliminaryUpdates" }
	@{ ShowInGUI = "Desactivar Obtener las ultimas Actualizaciones"; IsXamlId = "GetLatestUpdates"; IsOperation = "Set_GetLatestUpdates" }
	@{ ShowInGUI = "Retrasar Actualizaciones de Caracteristicas"; IsXamlId = "DelayFeatureUpdates"; IsOperation = "Set_DelayFeatureUpdates" }
	@{ ShowInGUI = "Retrasar Actualizaciones de Seguridad"; IsXamlId = "DelaySecurityUpdates"; IsOperation = "Set_DelaySecurityUpdates" }
	@{ ShowInGUI = "Notificar Reinicio para Finalizar Actualizaciones"; IsXamlId = "NotifyRestart"; IsOperation = "Set_NotifyRestart" }
	@{ ShowInGUI = "Habilitar Horas Activas de 06:00 a 23:00"; IsXamlId = "ActiveHours"; IsOperation = "Set_ActiveHours" }
	@{ ShowInGUI = "Desactivar Actualizaciones Automaticas de la Store"; IsXamlId = "StoreAutoUpdates"; IsOperation = "Set_StoreAutoUpdates" }
	@{ ShowInGUI = "Limitar Ancho de Banda Reservable a 0%"; IsXamlId = "LimitBandwidthUpdates"; IsOperation = "Set_LimitBandwidthUpdates" }
)

# Modification #: Configure performance in Windows
function Config_ScanCpuLoad {
	$property = 'ScanAvgCPULoadFactor'
	$value = 1

	if ( (Get-MpPreference).$property -ne $value ) {

		Write-Host "Setting value [$_esc[1;36m$property$_esc[0m], Changing..."
		Set-MpPreference -ScanAvgCPULoadFactor $value
	} 
	else {
		Write-Host "Value [$_esc[1;36m$property$_esc[0m] remains Changed."
	}
}

function Config_AutoSample {
	$property = 'SubmitSamplesConsent'
	$value = 2

	if ( (Get-MpPreference).$property -ne $value ) {

		Write-Host "Setting value [$_esc[1;36m$property$_esc[0m], Changing..."
		Set-MpPreference -SubmitSamplesConsent $value
	} 
	else {
		Write-Host "Value [$_esc[1;36m$property$_esc[0m] remains Changed."
	}
}

function Config_MemoryIntegrity {
	$mIntegrityPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
	$property = 'Enabled'
	$value = 0

	# Change value option
	Set-OptionValue $mIntegrityPath $property "DWord" $value
}

function Config_MemoryCompression {
	$property = 'MemoryCompression'
	$state = $true

	if ( (Get-MMAgent).$property -notlike $state ) {

		Write-Host "Setting state [$_esc[1;36m$property$_esc[0m], Changing..."
		Enable-MMAgent -MemoryCompression
	} 
	else {
		Write-Host "State [$_esc[1;36m$property$_esc[0m] remains Changed."
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

		Write-Host "Setting value [$_esc[1;36mTrimOperations$_esc[0m], Changing..."
		fsutil behavior set DisableDeleteNotify $value
	} 
	else {
		Write-Host "Value [$_esc[1;36mTrimOperations$_esc[0m] remains Changed."
	}
}

function Disable_BackgroundApp {
	$backgroundAppPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
	$property = 'GlobalUserDisabled'
	$value = 1

	# Change value option
	Set-OptionValue $backgroundAppPath $property "DWord" $value
}

function Disable_TransparencyEffects {
	$transparencyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
	$property = 'EnableTransparency'
	$value = 0

	# "Transparency has been Disabled"
	Set-OptionValue $transparencyPath $property "DWord" $value
}

function Minimum_Preferences {
	$preferMaskPath = 'HKCU:\Control Panel\Desktop'
	$property1 = 'UserPreferencesMask'
	$preferMask = (Get-ItemProperty -Path $preferMaskPath).$property1
	
	if ( ($preferMask[0] -ne 0x90) -or ($preferMask[1] -ne 0x12) ) {
		$preferMask[0] = 0x90 ; $preferMask[1] = 0x12
		$preferMask[2] = 0x03 ; $preferMask[4] = 0x10

		Write-Host "Setting value [$_esc[1;36m$preferMaskPath\$property1$_esc[0m], Changing..."
		Set-ItemProperty -Path $preferMaskPath -Name $property1 -Value $preferMask -Force
	} 
	else {
		Write-Host "Value [$_esc[1;36m$preferMaskPath\$property1$_esc[0m] remains Changed."
	}
}

function Animate_MinMax {
	$animateMinMaxPath = 'HKCU:\Control Panel\Desktop\WindowMetrics'
	$property = 'MinAnimate'
	$value = 0

	# Change value option
	Set-OptionValue $animateMinMaxPath $property "DWord" $value
}

function Animate_Taskbar {
	$taskbarAnimatiPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'TaskbarAnimations'
	$value = 0

	# Change value option
	Set-OptionValue $taskbarAnimatiPath $property "DWord" $value
}

function Enable_Peek {
	$enablePeekPath = 'HKCU:\Software\Microsoft\Windows\DWM'
	$property = 'EnableAeroPeek'
	$value = 0

	# Change value option
	Set-OptionValue $enablePeekPath $property "DWord" $value
}

function Show_Translucent {
	$translucentPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ListviewAlphaSelect'
	$value = 0

	# Change value option
	Set-OptionValue $translucentPath $property "DWord" $value
}

function Drop_Shadows {
	$dropShadowsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$property = 'ListviewShadow'
	$value = 0

	# Change value option
	Set-OptionValue $dropShadowsPath $property "DWord" $value
}

function Set_CustomAppearance {
	$visualEffectsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
	$property = 'VisualFXSetting'
	$value = 3

	# Change value option
	Set-OptionValue $visualEffectsPath $property "DWord" $value

	# Efectos visuales minimos
	# Minimum_Preferences
	Animate_MinMax
	Animate_Taskbar
	Enable_Peek
	Show_Translucent
	Drop_Shadows
}

function Set_PowerMode {
	$path = ''
	$property = ''
	$value = 0

	# Change value option
	Set-OptionValue $path $property "DWord" $value
}

function Set_GroupProcesses {
	$svchostPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
	$property = "SvcHostSplitThresholdInKB"  # $ram = 3670016 | value default in 8GB RAM
	$value = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
	
	# Change value option
	Set-OptionValue $svchostPath $property "DWord" $value
}

$performanceList = @(
	@{ ShowInGUI = "Limitar Carga de CPU al Escanear a 1%"; IsXamlId = "ScanCpuLoad"; IsOperation = "Config_ScanCpuLoad" }
	@{ ShowInGUI = "Desactivar Muestra Automática"; IsXamlId = "AutoSample"; IsOperation = "Config_AutoSample" }
	# @{ ShowInGUI = "Desactivar Integridad de Memoria"; IsXamlId = "MemoryIntegrity"; IsOperation = "Config_MemoryIntegrity" }
	@{ ShowInGUI = "Activar Compresion de Memoria"; IsXamlId = "MemoryCompression"; IsOperation = "Config_MemoryCompression" }
	@{ ShowInGUI = "Activar TRIM para SSD"; IsXamlId = "TrimSSD"; IsOperation = "Config_TrimSSD" }
	# @{ ShowInGUI = "Desactivar Aplicaciones en Segundo Plano"; IsXamlId = "BackgroundApp"; IsOperation = "Disable_BackgroundApp" }
	@{ ShowInGUI = "Desactivar Efectos de Transparencia"; IsXamlId = "TransparencyEffects"; IsOperation = "Disable_TransparencyEffects" }
	# @{ ShowInGUI = "Aplicar Efectos Visuales Minimos"; IsXamlId = "CustomAppearance"; IsOperation = "Set_CustomAppearance" }
	# @{ ShowInGUI = "Aplicar Modo de Mejor Rendimiento"; IsXamlId = "PowerMode"; IsOperation = "Set_PowerMode" }
	@{ ShowInGUI = "Agrupar Procesos Svchost"; IsXamlId = "GroupProcesses"; IsOperation = "Set_GroupProcesses" }
)

function Set_Privacy_Update_Performance ($mainContent) {
	# Limpia las referencias de CheckBoxes previas
	$global:CheckBoxRefs.Clear()

	$panelWindow = GenerateWinGUITriple "SELECCIONE LOS AJUSTES DE PRIVACIDAD, EL COMPORTAMIENTO DE LAS ACTUALIZACIONES Y LOS AJUSTES DE RENDIMIENTO" "Aplicar"
	$mainContent.Children.Clear()
	$mainContent.Children.Add($panelWindow)

	Add-GenerateTextBlock "PRIVACIDAD" $panelWindow "TextBlock1"
	GenerateCheckBoxList $privacyList $panelWindow "ListContainer1"

	Add-GenerateTextBlock "ACTUALIZACIONES" $panelWindow "TextBlock2"
	GenerateCheckBoxList $updateList $panelWindow "ListContainer2"

	Add-GenerateTextBlock "RENDIMIENTO" $panelWindow "TextBlock3"
	GenerateCheckBoxList $performanceList $panelWindow "ListContainer3"

	$captPanelRef = $panelWindow
	$captPanelRef.FindName("ActionButton").Add_Click({

		Write-Host "==  SELECTED OPERATIONS  =="
		foreach ($listKey in $privacyList) {
			$checkBox1 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox1 -and $checkBox1.IsChecked ) {
				& $listKey.IsOperation
			}
		}

		foreach ($listKey in $updateList) {
			$checkBox2 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox2 -and $checkBox2.IsChecked ) {
				& $listKey.IsOperation
			}
		}
		
		foreach ($listKey in $performanceList) {
			$checkBox3 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox3 -and $checkBox3.IsChecked ) {
				& $listKey.IsOperation
			}
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
	})
}

# Modification #: Configure Remove AppCapability in Windows
function Test-ModuleAppx {

	& { Import-Module -Name "Appx" -UseWindowsPowerShell } 3> $null
}

function Test-ModuleDism {

	InstallModule "Dism"; ActivateModule "Dism"
}

# Get-WindowsCapability -Online | Sort-Object State, Name | Format-Table -GroupBy State -Property Name, State
function RemoveCapabilityApp ($appName) {
	# $appc = Get-WindowsCapability -Online | Where-Object { $_.Name -like "*$appName*" }

	Write-Host "Removing Capability: $appName"
	if ( $appName.Count -gt 0 ) {

		# $null = Remove-WindowsCapability -Name "$($appc.Name)" -Online
		Get-WindowsCapability -Online | 
		Where-Object { $appName -contains ($_.Name -split '~')[0] } | 
		Remove-WindowsCapability -Online
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
	@{ ShowInGUI = "SnippingTool (OLD)"; IsXamlId = "SnippingTool"; IsOperation = "Microsoft.Windows.SnippingTool" }
	@{ ShowInGUI = "PowerShell ISE"; IsXamlId = "PowerShellISE"; IsOperation = "Microsoft.Windows.PowerShell.ISE" }
	@{ ShowInGUI = "WordPad"; IsXamlId = "WindowsWordPad"; IsOperation = "Microsoft.Windows.WordPad" }
	@{ ShowInGUI = "Print Fax"; IsXamlId = "PrintFax"; IsOperation = "Print.Fax.Scan" }
	@{ ShowInGUI = "VBScript"; IsXamlId = "VBSCRIPT"; IsOperation = "VBSCRIPT" }
	@{ ShowInGUI = "WMIC Command"; IsXamlId = "WMIC"; IsOperation = "WMIC" }
	@{ ShowInGUI = "XPS Viewer"; IsXamlId = "XPSViewer"; IsOperation = "XPS.Viewer" }
)

# Modification #: Configure Remove AppxPackage in Windows
# Get-AppxPackage | Where-Object { $_.NonRemovable -like "False" } | Sort-Object Name | Format-Table -Property Name, PackageFullName, NonRemovable
function RemovePackageAppx ($appxName) {
	# $appx = Get-AppxPackage | Where-Object { ($_.NonRemovable -like "False") -and ($_.PackageFullName -like "*$appxName*") }
	# $appx = Get-AppxPackage -Name "*$appxName*"

	Write-Host "Removing Package: $appxName"
	if ( $appxName.Count -gt 0 ) {
		
		# $null = Remove-AppxPackage -Package "$($appx.PackageFullName)"
		Get-AppxPackage | 
		Where-Object { $appxName -contains ($_.Name -split '_')[0] } | 
		Remove-AppxPackage
	}
}

$packageList = @(
	@{ ShowInGUI = "Microsoft Clipchamp"; IsXamlId = "MSClipchamp"; IsOperation = "Clipchamp.Clipchamp" }
	@{ ShowInGUI = "Cortana"; IsXamlId = "MSCortana"; IsOperation = "Microsoft.549981C3F5F10" }
	@{ ShowInGUI = "AV1 Video Extension"; IsXamlId = "MSAV1VideoExtension"; IsOperation = "Microsoft.AV1VideoExtension" }
	@{ ShowInGUI = "AVC Encoder Video Extension"; IsXamlId = "MSAVCVideoExtension"; IsOperation = "Microsoft.AVCEncoderVideoExtension" }
	@{ ShowInGUI = "Microsoft News"; IsXamlId = "MSBingNews"; IsOperation = "Microsoft.BingNews" }
	@{ ShowInGUI = "Microsoft Bing (Edge)"; IsXamlId = "MSBingSearch"; IsOperation = "Microsoft.BingSearch" }
	@{ ShowInGUI = "MSN Weather"; IsXamlId = "MSBingWeather"; IsOperation = "Microsoft.BingWeather" }
	# @{ ShowInGUI = "Copilot"; IsXamlId = "MSCopilot"; IsOperation = "Microsoft.Copilot" }
	@{ ShowInGUI = "Game Assist"; IsXamlId = "MSGameAssist"; IsOperation = "Microsoft.Edge.GameAssist" }
	@{ ShowInGUI = "Xbox App"; IsXamlId = "MSGamingApp"; IsOperation = "Microsoft.GamingApp" }
	@{ ShowInGUI = "Get Help"; IsXamlId = "MSGetHelp"; IsOperation = "Microsoft.GetHelp" }
	@{ ShowInGUI = "Get Started"; IsXamlId = "MSGetstarted"; IsOperation = "Microsoft.Getstarted" }
	@{ ShowInGUI = "HEIF Image Extension"; IsXamlId = "MSHEIFImageExtension"; IsOperation = "Microsoft.HEIFImageExtension" }
	@{ ShowInGUI = "HEVC Video Extension"; IsXamlId = "MSHEVCVideoExtension"; IsOperation = "Microsoft.HEVCVideoExtension" }
	@{ ShowInGUI = "Paint 3D"; IsXamlId = "MSMicrosoft3DViewer"; IsOperation = "Microsoft.Microsoft3DViewer" }
	# @{ ShowInGUI = "Microsoft Edge"; IsXamlId = "MSEdge"; IsOperation = "Microsoft.MicrosoftEdge.Stable" }
	@{ ShowInGUI = "Microsoft 365 (PWA)"; IsXamlId = "MSOfficeHub"; IsOperation = "Microsoft.MicrosoftOfficeHub" }
	@{ ShowInGUI = "Solitaire Collection"; IsXamlId = "MSSolitaireCollection"; IsOperation = "Microsoft.MicrosoftSolitaireCollection" }
	@{ ShowInGUI = "Microsoft Sticky Notes"; IsXamlId = "MSStickyNotes"; IsOperation = "Microsoft.MicrosoftStickyNotes" }
	@{ ShowInGUI = "Mixed Reality Portal"; IsXamlId = "MSMixedReality"; IsOperation = "Microsoft.MixedReality.Portal" }
	@{ ShowInGUI = "MPEG-2 Video Extension"; IsXamlId = "MSMPEG2VideoExtension"; IsOperation = "Microsoft.MPEG2VideoExtension" }
	@{ ShowInGUI = "Paint (OLD)"; IsXamlId = "MSPaint"; IsOperation = "Microsoft.MSPaint" }
	@{ ShowInGUI = "OneNote"; IsXamlId = "MSOneNote"; IsOperation = "Microsoft.Office.OneNote" }
	@{ ShowInGUI = "Outlook (new)"; IsXamlId = "MSOutlookForWindows"; IsOperation = "Microsoft.OutlookForWindows" }
	@{ ShowInGUI = "Microsoft People"; IsXamlId = "MSPeople"; IsOperation = "Microsoft.People" }
	@{ ShowInGUI = "Power Automate"; IsXamlId = "MSPowerAutomate"; IsOperation = "Microsoft.PowerAutomateDesktop" }
	@{ ShowInGUI = "Raw Image Extension"; IsXamlId = "MSRawImageExtension"; IsOperation = "Microsoft.RawImageExtension" }
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
	@{ ShowInGUI = "Game Bar"; IsXamlId = "MSXboxGamingOverlay"; IsOperation = "Microsoft.XboxGamingOverlay" }
	@{ ShowInGUI = "Xbox Provider"; IsXamlId = "MSXboxIdentityProvider"; IsOperation = "Microsoft.XboxIdentityProvider" }
	@{ ShowInGUI = "Xbox Text Overlay"; IsXamlId = "MSXboxSpeechToTextOverlay"; IsOperation = "Microsoft.XboxSpeechToTextOverlay" }
	@{ ShowInGUI = "Phone Link"; IsXamlId = "MSYourPhone"; IsOperation = "Microsoft.YourPhone" }
	@{ ShowInGUI = "Windows Media Player"; IsXamlId = "MSZuneMusic"; IsOperation = "Microsoft.ZuneMusic" }
	@{ ShowInGUI = "Movies & TV"; IsXamlId = "MSZuneVideo"; IsOperation = "Microsoft.ZuneVideo" }
	@{ ShowInGUI = "Microsoft Family Safety"; IsXamlId = "MSFamily"; IsOperation = "MicrosoftCorporationII.MicrosoftFamily" }
	@{ ShowInGUI = "Quick Assist"; IsXamlId = "MSQuickAssist"; IsOperation = "MicrosoftCorporationII.QuickAssist" }
	@{ ShowInGUI = "Widgets"; IsXamlId = "MSWebExperience"; IsOperation = "MicrosoftWindows.Client.WebExperience" }
	@{ ShowInGUI = "Cross Device Host"; IsXamlId = "MSCrossDevice"; IsOperation = "MicrosoftWindows.CrossDevice" }
	@{ ShowInGUI = "Widgets Platform"; IsXamlId = "MSWidgetsPlatform"; IsOperation = "Microsoft.WidgetsPlatformRuntime" }
	@{ ShowInGUI = "Microsoft Teams"; IsXamlId = "MSWTeams"; IsOperation = "MSTeams" }
	@{ ShowInGUI = "Spotify Music"; IsXamlId = "MSSpotifyMusic"; IsOperation = "SpotifyAB.SpotifyMusic" }
	# @{ ShowInGUI = "linkedin"; IsXamlId = "MSlinkedin"; IsOperation = "linkedin_searchId" }
	# @{ ShowInGUI = "Camo Studio"; IsXamlId = "MSCamoStudio"; IsOperation = "CamoStudio_searchId" }
)

# Modification #: Configure Remove ProvisionedAppxPackage in Windows
# Get-AppxProvisionedPackage -Online | Sort-Object DisplayName | Format-Table -Property DisplayName, PackageName
function RemoveProvisionedAppx ($appxName) {
	# $appx = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$appxName*" }

	Write-Host "Removing Provisioned: $appxName"
	if ( $appxName.Count -gt 0 ) {
		
		# $null = Remove-AppxProvisionedPackage -PackageName "$($appx.PackageName)" -Online
		Get-AppxProvisionedPackage -Online | 
		Where-Object { $appxName -contains ($_.DisplayName -split '_')[0] } | 
		Remove-AppxProvisionedPackage -Online
	}
}

$provisionedList = @(
	@{ ShowInGUI = "Microsoft Clipchamp"; IsXamlId = "PMSClipchamp"; IsOperation = "Clipchamp.Clipchamp" }
	@{ ShowInGUI = "Cortana"; IsXamlId = "PMSCortana"; IsOperation = "Microsoft.549981C3F5F10" }
	@{ ShowInGUI = "AV1 Video Extension"; IsXamlId = "PMSAV1VideoExtension"; IsOperation = "Microsoft.AV1VideoExtension" }
	@{ ShowInGUI = "AVC Encoder Video Extension"; IsXamlId = "PMSAVCVideoExtension"; IsOperation = "Microsoft.AVCEncoderVideoExtension" }
	@{ ShowInGUI = "Microsoft News"; IsXamlId = "PMSBingNews"; IsOperation = "Microsoft.BingNews" }
	@{ ShowInGUI = "Microsoft Bing (Edge)"; IsXamlId = "PMSBingSearch"; IsOperation = "Microsoft.BingSearch" }
	@{ ShowInGUI = "MSN Weather"; IsXamlId = "PMSBingWeather"; IsOperation = "Microsoft.BingWeather" }
	# @{ ShowInGUI = "Copilot"; IsXamlId = "PMSCopilot"; IsOperation = "Microsoft.Copilot" }
	@{ ShowInGUI = "Game Assist"; IsXamlId = "PMSGameAssist"; IsOperation = "Microsoft.Edge.GameAssist" }
	@{ ShowInGUI = "Xbox App"; IsXamlId = "PMSGamingApp"; IsOperation = "Microsoft.GamingApp" }
	@{ ShowInGUI = "Get Help"; IsXamlId = "PMSGetHelp"; IsOperation = "Microsoft.GetHelp" }
	@{ ShowInGUI = "Get Started"; IsXamlId = "PMSGetstarted"; IsOperation = "Microsoft.Getstarted" }
	@{ ShowInGUI = "HEIF Image Extension"; IsXamlId = "PMSHEIFImageExtension"; IsOperation = "Microsoft.HEIFImageExtension" }
	@{ ShowInGUI = "HEVC Video Extension"; IsXamlId = "PMSHEVCVideoExtension"; IsOperation = "Microsoft.HEVCVideoExtension" }
	@{ ShowInGUI = "Paint 3D"; IsXamlId = "PMSMicrosoft3DViewer"; IsOperation = "Microsoft.Microsoft3DViewer" }
	# @{ ShowInGUI = "Microsoft Edge"; IsXamlId = "PMSEdge"; IsOperation = "Microsoft.MicrosoftEdge.Stable" }
	@{ ShowInGUI = "Microsoft 365 (PWA)"; IsXamlId = "PMSOfficeHub"; IsOperation = "Microsoft.MicrosoftOfficeHub" }
	@{ ShowInGUI = "Solitaire Collection"; IsXamlId = "PMSSolitaireCollection"; IsOperation = "Microsoft.MicrosoftSolitaireCollection" }
	@{ ShowInGUI = "Microsoft Sticky Notes"; IsXamlId = "PMSStickyNotes"; IsOperation = "Microsoft.MicrosoftStickyNotes" }
	@{ ShowInGUI = "Mixed Reality Portal"; IsXamlId = "PMSMixedReality"; IsOperation = "Microsoft.MixedReality.Portal" }
	@{ ShowInGUI = "MPEG-2 Video Extension"; IsXamlId = "PMSMPEG2VideoExtension"; IsOperation = "Microsoft.MPEG2VideoExtension" }
	@{ ShowInGUI = "Paint (OLD)"; IsXamlId = "PMSPaint"; IsOperation = "Microsoft.MSPaint" }
	@{ ShowInGUI = "OneNote"; IsXamlId = "PMSOneNote"; IsOperation = "Microsoft.Office.OneNote" }
	@{ ShowInGUI = "Outlook (new)"; IsXamlId = "PMSOutlookForWindows"; IsOperation = "Microsoft.OutlookForWindows" }
	@{ ShowInGUI = "Microsoft People"; IsXamlId = "PMSPeople"; IsOperation = "Microsoft.People" }
	@{ ShowInGUI = "Power Automate"; IsXamlId = "PMSPowerAutomate"; IsOperation = "Microsoft.PowerAutomateDesktop" }
	@{ ShowInGUI = "Raw Image Extension"; IsXamlId = "PMSRawImageExtension"; IsOperation = "Microsoft.RawImageExtension" }
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
	@{ ShowInGUI = "Game Bar"; IsXamlId = "PMSXboxGamingOverlay"; IsOperation = "Microsoft.XboxGamingOverlay" }
	@{ ShowInGUI = "Xbox Provider"; IsXamlId = "PMSXboxIdentityProvider"; IsOperation = "Microsoft.XboxIdentityProvider" }
	@{ ShowInGUI = "Xbox Text Overlay"; IsXamlId = "PMSXboxSpeechToTextOverlay"; IsOperation = "Microsoft.XboxSpeechToTextOverlay" }
	@{ ShowInGUI = "Phone Link"; IsXamlId = "PMSYourPhone"; IsOperation = "Microsoft.YourPhone" }
	@{ ShowInGUI = "Windows Media Player"; IsXamlId = "PMSZuneMusic"; IsOperation = "Microsoft.ZuneMusic" }
	@{ ShowInGUI = "Movies & TV"; IsXamlId = "PMSZuneVideo"; IsOperation = "Microsoft.ZuneVideo" }
	@{ ShowInGUI = "Microsoft Family Safety"; IsXamlId = "PMSFamily"; IsOperation = "MicrosoftCorporationII.MicrosoftFamily" }
	@{ ShowInGUI = "Quick Assist"; IsXamlId = "PMSQuickAssist"; IsOperation = "MicrosoftCorporationII.QuickAssist" }
	@{ ShowInGUI = "Widgets"; IsXamlId = "PMSWebExperience"; IsOperation = "MicrosoftWindows.Client.WebExperience" }
	@{ ShowInGUI = "Cross Device Host"; IsXamlId = "PMSCrossDevice"; IsOperation = "MicrosoftWindows.CrossDevice" }
	@{ ShowInGUI = "Widgets Platform"; IsXamlId = "PMSWidgetsPlatform"; IsOperation = "Microsoft.WidgetsPlatformRuntime" }
	@{ ShowInGUI = "Microsoft Teams"; IsXamlId = "PMSWTeams"; IsOperation = "MSTeams" }
)

function Remove_Capability_Package_Provisioned ($mainContent) {
	# Limpia las referencias de CheckBoxes previas
	$global:CheckBoxRefs.Clear()

	$panelWindow = GenerateWinGUITriple "SELECCIONE LAS CAPACIDADES DE WINDOWS, LOS PAQUETES DE WINDOWS Y LOS PROVISIONADOS DE WINDOWS" "Remover"
	$mainContent.Children.Clear()
	$mainContent.Children.Add($panelWindow)

	Add-GenerateTextBlock "CAPACIDADES" $panelWindow "TextBlock1"
	GenerateCheckBoxList $capabilityList $panelWindow "ListContainer1"

	Add-GenerateTextBlock "PAQUETES" $panelWindow "TextBlock2"
	GenerateCheckBoxList $packageList $panelWindow "ListContainer2"

	Add-GenerateTextBlock "PROVISIONADOS" $panelWindow "TextBlock3"
	GenerateCheckBoxList $provisionedList $panelWindow "ListContainer3"

	$captPanelRef = $panelWindow
	$captPanelRef.FindName("ActionButton").Add_Click({

		Write-Host "==  SELECTED OPERATIONS  =="
		$CapabilityRmList = @()
		foreach ($listKey in $capabilityList) {
			$checkBox1 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox1 -and $checkBox1.IsChecked ) {
				$CapabilityRmList += $listKey.IsOperation
			}
		}
		RemoveCapabilityApp $CapabilityRmList

		$PackageRmList = @()
		foreach ($listKey in $packageList) {
			$checkBox2 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox2 -and $checkBox2.IsChecked ) {
				$PackageRmList += $listKey.IsOperation
			}
		}
		RemovePackageAppx $PackageRmList

		$ProvisionedRmList = @()
		foreach ($listKey in $provisionedList) {
			$checkBox3 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox3 -and $checkBox3.IsChecked ) {
				$ProvisionedRmList += $listKey.IsOperation
			}
		}
		RemoveProvisionedAppx $ProvisionedRmList
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
	})
}

# Modification #: Configure Install App
# winget list  |  winget upgrade --include-unknown  |  winget upgrade --all --include-unknown
# choco list   |  choco outdated                    |  choco upgrade all --confirm
function InstallPkgWinget ($appIdPkg, $sourceType) {

	Write-Host "Installing Winget: $appIdPkg"
	if ( $appIdPkg.Count -gt 0 ) {

		Start-Process -FilePath $sourceType -ArgumentList "install $appIdPkg --exact --no-upgrade --accept-source-agreements --accept-package-agreements" -NoNewWindow -Wait
	}
}

$appPkgList = @(
	@{ ShowInGUI = "Bitwarden"; IsXamlId = "BitwardenId"; IsOperation = "Bitwarden.Bitwarden" }
	@{ ShowInGUI = "Raindrop.io"; IsXamlId = "RaindropId"; IsOperation = "RustemMussabekov.Raindrop" }
	@{ ShowInGUI = "Mozilla Firefox"; IsXamlId = "FirefoxBrow"; IsOperation = "Mozilla.Firefox" }
	@{ ShowInGUI = "LibreWolf Browser"; IsXamlId = "LibreWolfBrow"; IsOperation = "LibreWolf.LibreWolf" }
	@{ ShowInGUI = "Vivaldi Browser"; IsXamlId = "VivaldiBrow"; IsOperation = "Vivaldi.Vivaldi" }
	@{ ShowInGUI = "OperaGX Browser"; IsXamlId = "OperaGXBrow"; IsOperation = "Opera.OperaGX" }
	@{ ShowInGUI = "FreeTube"; IsXamlId = "FreeTube"; IsOperation = "PrestonN.FreeTube" }
	@{ ShowInGUI = "YouTube Music (OSS)"; IsXamlId = "YouTubeMusic"; IsOperation = "th-ch.YouTubeMusic" }
	# @{ ShowInGUI = "Microsoft Edge"; IsXamlId = "MSEdgeBrow"; IsOperation = "Microsoft.Edge" }
	@{ ShowInGUI = "ZoomIt"; IsXamlId = "MSZoomIt"; IsOperation = "Microsoft.Sysinternals.ZoomIt" }
	@{ ShowInGUI = "Twinkle Tray"; IsXamlId = "TwinkleTray"; IsOperation = "xanderfrangos.twinkletray" }
	@{ ShowInGUI = "Energy Star X"; IsXamlId = "StoreEnergyStarX"; IsOperation = "9NF7JTB3B17P" }
	# @{ ShowInGUI = "Battery Tracker"; IsXamlId = "StoreBatteryTracker"; IsOperation = "9P1FBSLRNM43" }
	@{ ShowInGUI = "Microsoft PC Manager"; IsXamlId = "StorePCManager"; IsOperation = "9PM860492SZD" }
	@{ ShowInGUI = "AutoHotkey"; IsXamlId = "AutoHotkeyId"; IsOperation = "AutoHotkey.AutoHotkey" }
	@{ ShowInGUI = "Everything (x64)"; IsXamlId = "Everything"; IsOperation = "voidtools.Everything" }
	@{ ShowInGUI = "QuickLook"; IsXamlId = "QuickLookId"; IsOperation = "QL-Win.QuickLook" }
	@{ ShowInGUI = "Lightshot"; IsXamlId = "LightshotId"; IsOperation = "Skillbrains.Lightshot" }
	@{ ShowInGUI = "ChatGPT"; IsXamlId = "ChatGPTId"; IsOperation = "9NT1R1C2HH7J" }
	@{ ShowInGUI = "Perplexity"; IsXamlId = "PerplexityId"; IsOperation = "XP8JNQFBQH6PVF" }
	@{ ShowInGUI = "Quick Share Google"; IsXamlId = "QuickShare"; IsOperation = "Google.QuickShare" }
	@{ ShowInGUI = "LocalSend"; IsXamlId = "LocalSend"; IsOperation = "LocalSend.LocalSend" }
	@{ ShowInGUI = "KDE Connect"; IsXamlId = "KDEConnect"; IsOperation = "KDE.KDEConnect" }
	@{ ShowInGUI = "7-Zip"; IsXamlId = "SevenZip"; IsOperation = "7zip.7zip" }
	@{ ShowInGUI = "WinRAR"; IsXamlId = "WinRARId"; IsOperation = "RARLab.WinRAR" }
	@{ ShowInGUI = "TeraBox Desktop"; IsXamlId = "TeraBox"; IsOperation = "Baidu.TeraBox" }
	@{ ShowInGUI = "MEGA Drive"; IsXamlId = "MEGA"; IsOperation = "Mega.MEGASync" }
	@{ ShowInGUI = "Google Drive"; IsXamlId = "GoogleDrive"; IsOperation = "Google.GoogleDrive" }
	@{ ShowInGUI = "Dropbox Drive"; IsXamlId = "Dropbox"; IsOperation = "Dropbox.Dropbox" }
	@{ ShowInGUI = "Notepad++"; IsXamlId = "Notepadplusplus"; IsOperation = "Notepad++.Notepad++" }
	@{ ShowInGUI = "IrfanView (x64)"; IsXamlId = "IrfanView"; IsOperation = "IrfanSkiljan.IrfanView" }
	# @{ ShowInGUI = "AIMP Music Player"; IsXamlId = "Aimp"; IsOperation = "empresa.nombreApp" }
	@{ ShowInGUI = "VLC Media Player"; IsXamlId = "VLCMediaPlayer"; IsOperation = "VideoLAN.VLC" }
	@{ ShowInGUI = "SumatraPDF"; IsXamlId = "SumatraPDFId"; IsOperation = "SumatraPDF.SumatraPDF" }
	@{ ShowInGUI = "KDE Okular"; IsXamlId = "KDEOkularId"; IsOperation = "KDE.Okular" }
	@{ ShowInGUI = "Simplenote"; IsXamlId = "Simplenote"; IsOperation = "Automattic.Simplenote" }
	@{ ShowInGUI = "Joplin"; IsXamlId = "Joplin"; IsOperation = "Joplin.Joplin" }
	@{ ShowInGUI = "GIMP"; IsXamlId = "GimpId"; IsOperation = "GIMP.GIMP.3" }
	@{ ShowInGUI = "Audacity"; IsXamlId = "AudacityId"; IsOperation = "Audacity.Audacity" }
	@{ ShowInGUI = "Kdenlive"; IsXamlId = "KdenliveId"; IsOperation = "KDE.Kdenlive" }
	@{ ShowInGUI = "PDF24 Creator"; IsXamlId = "PDF24CreatorId"; IsOperation = "geeksoftwareGmbH.PDF24Creator" }
	@{ ShowInGUI = "PDFgear"; IsXamlId = "PDFgearId"; IsOperation = "PDFgear.PDFgear" }
	@{ ShowInGUI = "Scribus"; IsXamlId = "ScribusId"; IsOperation = "Scribus.Scribus" }
	@{ ShowInGUI = "Microsoft 365 Apps"; IsXamlId = "MSOffice"; IsOperation = "Microsoft.Office" }
	@{ ShowInGUI = "OnlyOffice"; IsXamlId = "OnlyOfficeId"; IsOperation = "ONLYOFFICE.DesktopEditors" }
	@{ ShowInGUI = "LibreOffice"; IsXamlId = "LibreOffice"; IsOperation = "TheDocumentFoundation.LibreOffice" }
	@{ ShowInGUI = "Mendeley Reference Manager"; IsXamlId = "MenRefManager"; IsOperation = "Elsevier.MendeleyReferenceManager" }
	
	@{ ShowInGUI = "Steam Launcher"; IsXamlId = "SteamLauncher"; IsOperation = "Valve.Steam" }
	@{ ShowInGUI = "Epic Games Launcher"; IsXamlId = "EpicLauncher"; IsOperation = "EpicGames.EpicGamesLauncher" }
	@{ ShowInGUI = "EA App Launcher"; IsXamlId = "EALauncher"; IsOperation = "ElectronicArts.EADesktop" }
	@{ ShowInGUI = "Ubisoft Connect"; IsXamlId = "UbisoftConnet"; IsOperation = "Ubisoft.Connect" }
	@{ ShowInGUI = "Bethesda.net Launcher"; IsXamlId = "Bethesda"; IsOperation = "Bethesda.Launcher" }
	@{ ShowInGUI = "Battle.net Launcher"; IsXamlId = "BattleNet"; IsOperation = "Blizzard.BattleNet" }
	@{ ShowInGUI = "Heroic Games Launcher"; IsXamlId = "HeroicGamesLauncher"; IsOperation = "HeroicGamesLauncher.HeroicGamesLauncher" }
	@{ ShowInGUI = "GOG GALAXY"; IsXamlId = "GOGGalaxy"; IsOperation = "GOG.Galaxy" }
	@{ ShowInGUI = "Google Play Games (Beta)"; IsXamlId = "PlayGamesBetaId"; IsOperation = "Google.PlayGames.Beta" }
	@{ ShowInGUI = "BlueStacks"; IsXamlId = "BlueStacksId"; IsOperation = "BlueStack.BlueStacks" }
	@{ ShowInGUI = "PPSSPP Emulator"; IsXamlId = "PPSSPPId"; IsOperation = "PPSSPPTeam.PPSSPP" }
	@{ ShowInGUI = "DOLPHIN Emulator"; IsXamlId = "DolphinId"; IsOperation = "DolphinEmulator.Dolphin" }
	@{ ShowInGUI = "PCSX2 Emulator"; IsXamlId = "PCSX2Id"; IsOperation = "PCSX2Team.PCSX2" }
	@{ ShowInGUI = "XENIA Emulator"; IsXamlId = "XeniaId"; IsOperation = "Xenia.Xenia" }

	@{ ShowInGUI = "qBittorrent"; IsXamlId = "qBittorrentId"; IsOperation = "qBittorrent.qBittorrent" }
	@{ ShowInGUI = "WhatsApp Desktop"; IsXamlId = "WhatsApp"; IsOperation = "9NKSQGP7F2NH" }
	@{ ShowInGUI = "Telegram Desktop"; IsXamlId = "Telegram"; IsOperation = "Telegram.TelegramDesktop" }
	@{ ShowInGUI = "Wino Mail"; IsXamlId = "WinoMail"; IsOperation = "9NCRCVJC50WL" }
	@{ ShowInGUI = "Mozilla Thunderbird"; IsXamlId = "Thunderbird"; IsOperation = "Mozilla.Thunderbird" }
	@{ ShowInGUI = "scrcpy"; IsXamlId = "scrcpyId"; IsOperation = "Genymobile.scrcpy" }
	@{ ShowInGUI = "Discord"; IsXamlId = "DiscordId"; IsOperation = "Discord.Discord" }
	@{ ShowInGUI = "Zoom Workplace"; IsXamlId = "ZoomId"; IsOperation = "Zoom.Zoom" }
	@{ ShowInGUI = "Microsoft Teams (New)"; IsXamlId = "MSTeams"; IsOperation = "Microsoft.Teams" }
	@{ ShowInGUI = "Slack"; IsXamlId = "SlackId"; IsOperation = "SlackTechnologies.Slack" }
	@{ ShowInGUI = "OBS Studio"; IsXamlId = "OBSStudio"; IsOperation = "OBSProject.OBSStudio" }
)

$appdevList = @(
	@{ ShowInGUI = "Visual C++ 2005 (x86)"; IsXamlId = "MSVisuCplusRedis2005_x86"; IsOperation = "Microsoft.VCRedist.2005.x86" }
	@{ ShowInGUI = "Visual C++ 2005 (x64)"; IsXamlId = "MSVisuCplusRedis2005_x64"; IsOperation = "Microsoft.VCRedist.2005.x64" }
	@{ ShowInGUI = "Visual C++ 2008 (x86)"; IsXamlId = "MSVisuCplusRedis2008_x86"; IsOperation = "Microsoft.VCRedist.2008.x86" }
	@{ ShowInGUI = "Visual C++ 2008 (x64)"; IsXamlId = "MSVisuCplusRedis2008_x64"; IsOperation = "Microsoft.VCRedist.2008.x64" }
	@{ ShowInGUI = "Visual C++ 2010 (x86)"; IsXamlId = "MSVisuCplusRedis2010_x86"; IsOperation = "Microsoft.VCRedist.2010.x86" }
	@{ ShowInGUI = "Visual C++ 2010 (x64)"; IsXamlId = "MSVisuCplusRedis2010_x64"; IsOperation = "Microsoft.VCRedist.2010.x64" }
	@{ ShowInGUI = "Visual C++ 2012 (x86)"; IsXamlId = "MSVisuCplusRedis2012_x86"; IsOperation = "Microsoft.VCRedist.2012.x86" }
	@{ ShowInGUI = "Visual C++ 2012 (x64)"; IsXamlId = "MSVisuCplusRedis2012_x64"; IsOperation = "Microsoft.VCRedist.2012.x64" }
	@{ ShowInGUI = "Visual C++ 2013 (x86)"; IsXamlId = "MSVisuCplusRedis2013_x86"; IsOperation = "Microsoft.VCRedist.2013.x86" }
	@{ ShowInGUI = "Visual C++ 2013 (x64)"; IsXamlId = "MSVisuCplusRedis2013_x64"; IsOperation = "Microsoft.VCRedist.2013.x64" }
	@{ ShowInGUI = "Visual C++ 2015-2022 (x86)"; IsXamlId = "MSVisuCplusRedis2015_x86"; IsOperation = "Microsoft.VCRedist.2015+.x86" }
	@{ ShowInGUI = "Visual C++ 2015-2022 (x64)"; IsXamlId = "MSVisuCplusRedis2015_x64"; IsOperation = "Microsoft.VCRedist.2015+.x64" }
	@{ ShowInGUI = "DirectX End-User Runtime"; IsXamlId = "MSDirectX"; IsOperation = "Microsoft.DirectX" }
	@{ ShowInGUI = "OpenAL"; IsXamlId = "OpenAL"; IsOperation = "CreativeTechnology.OpenAL" }
	@{ ShowInGUI = "Microsoft XNA Framework"; IsXamlId = "MS_XNARedist"; IsOperation = "Microsoft.XNARedist" }
	@{ ShowInGUI = "Godot Engine"; IsXamlId = "GodotEngine"; IsOperation = "GodotEngine.GodotEngine" }
	@{ ShowInGUI = "Unity 2023"; IsXamlId = "Unity"; IsOperation = "Unity.Unity.2023" }
	
	@{ ShowInGUI = "Balsamiq Wireframes"; IsXamlId = "Balsamiq"; IsOperation = "Balsamiq.Wireframes" }
	@{ ShowInGUI = "Figma"; IsXamlId = "Figma"; IsOperation = "Figma.Figma" }
	@{ ShowInGUI = "Inkscape"; IsXamlId = "Inkscape"; IsOperation = "Inkscape.Inkscape" }
	@{ ShowInGUI = "Krita"; IsXamlId = "KritaId"; IsOperation = "KDE.Krita" }
	@{ ShowInGUI = "blender"; IsXamlId = "Blenderd"; IsOperation = "BlenderFoundation.Blender" }
	@{ ShowInGUI = "blender LTS"; IsXamlId = "BlenderdLTS"; IsOperation = "BlenderFoundation.Blender.LTS.3.6" }
	@{ ShowInGUI = "PuTTY"; IsXamlId = "PuTTYId"; IsOperation = "PuTTY.PuTTY" }
	@{ ShowInGUI = "WinSCP"; IsXamlId = "WinSCPId"; IsOperation = "WinSCP.WinSCP" }
	@{ ShowInGUI = "RustDesk"; IsXamlId = "RustDeskId"; IsOperation = "RustDesk.RustDesk" }
	@{ ShowInGUI = "TeamViewer"; IsXamlId = "TeamViewerId"; IsOperation = "TeamViewer.TeamViewer" }
	@{ ShowInGUI = "Oracle VM VirtualBox"; IsXamlId = "VirtualBox"; IsOperation = "Oracle.VirtualBox" }
    @{ ShowInGui = "QEMU"; IsXamlId = "QemuId"; IsOperation = "SoftwareFreedomConservancy.QEMU" }

	@{ ShowInGUI = "FxSound"; IsXamlId = "FxSoundId"; IsOperation = "FxSound.FxSound" }
	@{ ShowInGUI = "Fan Control"; IsXamlId = "FanControl"; IsOperation = "Rem0o.FanControl" }
	@{ ShowInGUI = "MSI Afterburner"; IsXamlId = "Afterburner"; IsOperation = "Guru3D.Afterburner" }
	@{ ShowInGUI = "Lenovo Legion Toolkit"; IsXamlId = "LenovoLegionToolkit"; IsOperation = "BartoszCichecki.LenovoLegionToolkit" }
	@{ ShowInGUI = "Wireshark"; IsXamlId = "Wireshark"; IsOperation = "WiresharkFoundation.Wireshark" }
	@{ ShowInGUI = "WizTree"; IsXamlId = "WizTreeId"; IsOperation = "AntibodySoftware.WizTree" }
	@{ ShowInGUI = "WinDirStat"; IsXamlId = "WinDirStatId"; IsOperation = "WinDirStat.WinDirStat" }
	@{ ShowInGUI = "Recuva"; IsXamlId = "RecuvaId"; IsOperation = "Piriform.Recuva" }
	@{ ShowInGUI = "BleachBit"; IsXamlId = "BleachBitId"; IsOperation = "BleachBit.BleachBit" }
	@{ ShowInGUI = "NVCleanstall"; IsXamlId = "NVCleanstallId"; IsOperation = "TechPowerUp.NVCleanstall" }
	# @{ ShowInGUI = "MiniTool Partition Wizard"; IsXamlId = "PartitionWizard"; IsOperation = "MiniTool.PartitionWizard.Free" }
	
	@{ ShowInGUI = "UniGetUI"; IsXamlId = "UniGetUIId"; IsOperation = "MartiCliment.UniGetUI" }
	@{ ShowInGUI = "fastfetch"; IsXamlId = "FastfetchId"; IsOperation = "Fastfetch-cli.Fastfetch" }
	@{ ShowInGUI = "cpufetch"; IsXamlId = "CpufetchId"; IsOperation = "Dr-Noob.cpufetch" }
	# @{ ShowInGUI = "Oh My Posh"; IsXamlId = "OhmyposhId"; IsOperation = "JanDeDobbeleer.OhMyPosh" }
	# @{ ShowInGUI = "starship"; IsXamlId = "StarshipId"; IsOperation = "Starship.Starship" }
	@{ ShowInGUI = "Flow Launcher"; IsXamlId = "FlowLauncher"; IsOperation = "Flow-Launcher.Flow-Launcher" }
	@{ ShowInGUI = "PowerToys (Preview)"; IsXamlId = "PowerToys"; IsOperation = "Microsoft.PowerToys" }
	@{ ShowInGUI = "Windhawk"; IsXamlId = "Windhawk"; IsOperation = "RamenSoftware.Windhawk" }
	@{ ShowInGUI = "Neovim"; IsXamlId = "NeovimId"; IsOperation = "Neovim.Neovim" }
	@{ ShowInGUI = "VSCodium"; IsXamlId = "VSCodium"; IsOperation = "VSCodium.VSCodium" }
	@{ ShowInGUI = "Visual Studio Code"; IsXamlId = "VSCode"; IsOperation = "Microsoft.VisualStudioCode" }
	@{ ShowInGUI = "Git"; IsXamlId = "GitId"; IsOperation = "Git.Git" }
	@{ ShowInGUI = "Java SDK"; IsXamlId = "JavaSDK"; IsOperation = "Oracle.JDK.22" }
	@{ ShowInGUI = "Python 3.12"; IsXamlId = "Python"; IsOperation = "Python.Python.3.12" }
	@{ ShowInGUI = "Rustup: toolchain"; IsXamlId = "Rustlang"; IsOperation = "Rustlang.Rustup" }
	# @{ ShowInGUI = "Rust (MSVC)"; IsXamlId = "Rustlang"; IsOperation = "Rustlang.Rust.MSVC" }
	@{ ShowInGUI = "Node.js (LTS)"; IsXamlId = "NodeJS"; IsOperation = "OpenJS.NodeJS.LTS" }
	@{ ShowInGUI = "Hoppscotch"; IsXamlId = "HoppscotchId"; IsOperation = "hoppscotch.Hoppscotch" }
	@{ ShowInGUI = "HTTPie"; IsXamlId = "HTTPieId"; IsOperation = "HTTPie.HTTPie" }
	@{ ShowInGUI = "Postman"; IsXamlId = "PostmanId"; IsOperation = "Postman.Postman" }
	@{ ShowInGUI = "GitHub Desktop"; IsXamlId = "GitHubId"; IsOperation = "GitHub.GitHubDesktop" }
	@{ ShowInGUI = "Visual Studio Community"; IsXamlId = "VSCommunity"; IsOperation = "Microsoft.VisualStudio.2022.Community" }
	@{ ShowInGUI = "Apache NetBeans IDE"; IsXamlId = "NetBeans"; IsOperation = "Apache.NetBeans" }
	@{ ShowInGUI = "Android Studio"; IsXamlId = "AndroidStudio"; IsOperation = "Google.AndroidStudio" }
	@{ ShowInGUI = "MySQL"; IsXamlId = "MySQLId"; IsOperation = "Oracle.MySQL" }
	@{ ShowInGUI = "MariaDB"; IsXamlId = "MariaDBId"; IsOperation = "MariaDB.Server" }
	@{ ShowInGUI = "PostgreSQL 17"; IsXamlId = "PostgreSQL"; IsOperation = "PostgreSQL.PostgreSQL.17" }
	# @{ ShowInGUI = "SQLServer Express"; IsXamlId = "SQLServer"; IsOperation = "Microsoft.SQLServer.2022.Express" }
	@{ ShowInGUI = "SQLServer Management Studio"; IsXamlId = "SQLServerMS"; IsOperation = "Microsoft.SQLServerManagementStudio" }
	@{ ShowInGUI = "Docker Desktop"; IsXamlId = "Docker"; IsOperation = "Docker.DockerDesktop" }
)

function InstallPkgChoco ($appIdPkg, $sourceType) {
	
	Write-Host "Installing Choco: $appIdPkg"
	if ( $appIdPkg.Count -gt 0 ) {
		
		Start-Process -FilePath $sourceType -ArgumentList "install $appIdPkg --limit-output --confirm" -NoNewWindow -Wait
	}
}

$toolList = @(
	@{ ShowInGUI = "FileZilla Client"; IsXamlId = "FilezillaId"; IsOperation = "filezilla" }
	@{ ShowInGUI = "AIMP Music Player"; IsXamlId = "AimpId"; IsOperation = "aimp" }
	@{ ShowInGUI = "Keypirinha Launcher"; IsXamlId = "KeypirinhaId"; IsOperation = "keypirinha" }
	@{ ShowInGUI = "AnyDesk (portable)"; IsXamlId = "AnydeskId"; IsOperation = "anydesk.portable" }
	@{ ShowInGUI = "ShutUp10"; IsXamlId = "Shutup10Id"; IsOperation = "shutup10" }
	@{ ShowInGUI = "AutoRuns"; IsXamlId = "AutorunsId"; IsOperation = "autoruns" }
	@{ ShowInGUI = "Process Explorer"; IsXamlId = "ProcexpId"; IsOperation = "procexp" }
	@{ ShowInGUI = "Process Monitor"; IsXamlId = "ProcmonId"; IsOperation = "procmon" }
	@{ ShowInGUI = "VMware Workstation Pro"; IsXamlId = "VmwareId"; IsOperation = "vmwareworkstation" }
	@{ ShowInGUI = "PE Studio"; IsXamlId = "PestudioId"; IsOperation = "pestudio" }  #desactualizado
	@{ ShowInGUI = "TCPView"; IsXamlId = "TcpviewId"; IsOperation = "tcpview" }
	@{ ShowInGUI = "Fing Network Scanner"; IsXamlId = "FingId"; IsOperation = "fing" }
	@{ ShowInGUI = "Ventoy"; IsXamlId = "VentoyId"; IsOperation = "ventoy" }
	@{ ShowInGUI = "balenaEtcher"; IsXamlId = "EtcherId"; IsOperation = "etcher" }
	@{ ShowInGUI = "Rufus (portable)"; IsXamlId = "RufusId"; IsOperation = "rufus.portable" }
	@{ ShowInGUI = "CPU-Z (portable)"; IsXamlId = "Cpu_zId"; IsOperation = "cpu-z.portable" }
	@{ ShowInGUI = "GPU-Z (portable)"; IsXamlId = "Gpu_zId"; IsOperation = "gpu-z" }
	@{ ShowInGUI = "HWMonitor"; IsXamlId = "HwmonitorId"; IsOperation = "hwmonitor" }
	@{ ShowInGUI = "HWINFO (portable)"; IsXamlId = "HwinfoId"; IsOperation = "hwinfo.portable" }
	@{ ShowInGUI = "Hard Disk Sentinel"; IsXamlId = "HdsentinelId"; IsOperation = "hdsentinel" }
	@{ ShowInGUI = "CrystalDiskInfo (portable)"; IsXamlId = "CrystaldiskinfoId"; IsOperation = "crystaldiskinfo.portable" }
	@{ ShowInGUI = "CrystalDiskMark (portable)"; IsXamlId = "CrystaldiskmarkId"; IsOperation = "crystaldiskmark.portable" }
	@{ ShowInGUI = "H2testw"; IsXamlId = "h2testwId"; IsOperation = "h2testw" }
	@{ ShowInGUI = "FurMark"; IsXamlId = "FurmarkId"; IsOperation = "furmark" }
	@{ ShowInGUI = "OCCT"; IsXamlId = "OcctId"; IsOperation = "occt" }
	@{ ShowInGUI = "Revo Uninstaller"; IsXamlId = "RevoId"; IsOperation = "revo-uninstaller" }  #desactualizado
	@{ ShowInGUI = "Bulk Crap Uninstaller"; IsXamlId = "BulkcrapId"; IsOperation = "bulk-crap-uninstaller" }
	@{ ShowInGUI = "Display Driver Uninstaller (DDU)"; IsXamlId = "DduId"; IsOperation = "ddu" }
	@{ ShowInGUI = "Android SDK Platform Tools (ADB)"; IsXamlId = "AdbId"; IsOperation = "adb" }
)

function Install_AppPkg_AppDev_Tool ($mainContent) {
	# Limpia las referencias de CheckBoxes previas
	$global:CheckBoxRefs.Clear()

	$panelWindow = GenerateWinGUITriple "SELECCIONE LAS APLICACIONES, APPS DE DESARROLLO Y HERRAMIENTAS" "Instalar"
	$mainContent.Children.Clear()
	$mainContent.Children.Add($panelWindow)
	
	Add-GenerateTextBlock "APLICACIONES" $panelWindow "TextBlock1"
	GenerateCheckBoxList $appPkgList $panelWindow "ListContainer1"

	Add-GenerateTextBlock "APP-DEVELOPER" $panelWindow "TextBlock2"
	GenerateCheckBoxList $appdevList $panelWindow "ListContainer2"

	Add-GenerateTextBlock "HERRAMIENTAS" $panelWindow "TextBlock3"
	GenerateCheckBoxList $toolList $panelWindow "ListContainer3"

	$captPanelRef = $panelWindow
	$captPanelRef.FindName("ActionButton").Add_Click({
		
		Write-Host "==  SELECTED APP  =="
		$PackageWin1List = @()
		foreach ($listKey in $appPkgList) {
			$checkBox1 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox1 -and $checkBox1.IsChecked ) {
				$PackageWin1List += $listKey.IsOperation
			}
		}
		InstallPkgWinget $PackageWin1List "winget"
	
		$PackageWin2List = @()
		foreach ($listKey in $appdevList) {
			$checkBox2 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox2 -and $checkBox2.IsChecked ) {
				$PackageWin2List += $listKey.IsOperation
			}
		}
		InstallPkgWinget $PackageWin2List "winget"

		$PackageChocoList = @()
		foreach ($listKey in $toolList) {
			$checkBox3 = $global:CheckBoxRefs[$listKey.IsXamlId]
			if ( $checkBox3 -and $checkBox3.IsChecked ) {
				$PackageChocoList += $listKey.IsOperation
			}
		}
		InstallPkgChoco $PackageChocoList "choco"
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
	})
}

# Modification #: Configure custom system in Windows
function InstallModule ($moduleName) {
	$modComand = if ( $moduleName -eq "Terminal-Icons" ) { " -Repository PSGallery" } else { "" }
	
	$moduleComand = 'Install-Module -Name ' + $moduleName + $modComand + ' -Force'
	if ( -not (Get-Module -ListAvailable -Name $moduleName) ) {
		
		Write-Host "Module [$_esc[1;36m$moduleName$_esc[0m] not found, Installing..."
		Invoke-Expression $moduleComand
	} 
	else {
		Write-Host "Module [$_esc[1;36m$moduleName$_esc[0m] remains Installed."
	}
}

function ActivateModule ($moduleName) {

	$iconsComand = "Import-Module -Name $moduleName"
	if ( -not (Get-Module -Name $moduleName) ) {
		
		Write-Host "Module [$_esc[1;36m$moduleName$_esc[0m] disabled, Activating..."
		Invoke-Expression $iconsComand
	} 
	else {
		Write-Host "Module [$_esc[1;36m$moduleName$_esc[0m] remains Activated."
	}

	return $iconsComand
}

function Install_PromptT {
	param (
		[string]$themeName
	)

	# Cargar dependencias necesarias
	Write-Host "This profile requires the following packages!"
	InstallPkgChoco "nerd-fonts-cascadiacode" choco # CaskaydiaCove Nerd Font
	InstallPkgWinget "JanDeDobbeleer.OhMyPosh" winget

	# Mostrar mensaje de operacion
	Write-Host ">>  PROMPT CUSTOM"
	Write-Host "Loading the following config of prompt: OH-MY-POSH"
	
	# Cargar Oh-My-Posh en el perfil de la terminal
	$activatePrompt = 'oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\' + $themeName + '.omp.json" | Invoke-Expression'
	Write-Host "Config ==> $activatePrompt" -ForegroundColor Cyan
	
	return $activatePrompt
}

function Install_ModuleT {
	
	# MyTheme 7.2: Module Terminal-Icons
	Write-Host ">>  POWERSHELL MODULE"
	InstallModule "Terminal-Icons"
	$iconsComand = ActivateModule "Terminal-Icons"
	
	# MyTheme 7.2: Module z
	InstallModule "z"

	return $iconsComand
}

function Enable_ListViewT {
	
	$modeName = 'ListView'
	$option = Get-PSReadLineOption | Where-Object { $_.PredictionViewStyle -notlike "$modeName" }

	Write-Host ">>  POWERSHELL STYLE"
	$predictionComand = "Set-PSReadLineOption -PredictionViewStyle $modeName"
	if ($option) {
		
		Write-Host "Setting option [$_esc[1;36mPredictionViewStyle$_esc[0m], Changing..."
		Invoke-Expression $predictionComand
	}
	else {
		Write-Host "Option [$_esc[1;36mPredictionViewStyle$_esc[0m] remains Changed."
	}

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

	if ( -not ($fileContent -match [regex]::escape($valueToCompare)) ) {

		Write-Host "String [$valueToAdd] not found, Adding..." -ForegroundColor Yellow
		Add-Content -Path $filePath -Value $valueToAdd
	}
}

# MyTheme 7.5: Agregar imagen de fondo
function Test_ImagePath {
	param (
		[string]$localPath,
		[string]$httpsPath
	)

	if ( -not (Test-Path -Path $localPath) ) {

		Write-Host "File [$localPath] not found, Downloading..." -ForegroundColor Yellow
		Invoke-WebRequest -Uri $httpsPath -OutFile $localPath
	}
}

function Set_BackgroundType {
	$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers'
	$property = 'BackgroundType'
	$value = 0

	# Option change value
	"Enable [Picture] for Background."
	Set-OptionValue $path $property "DWord" $value
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
	Set-OptionValue $path $property "DWord" $value
}

function Custom_Background_Picture () {

	# Change to Picture
	Write-Host "-------------------------"
	Write-Host "==  MY WALLPAPER LIST  =="
	Write-Host "-------------------------"
	Write-Host "##  SET BACKGROUND TYPE"
	Set_BackgroundType

	Write-Host "`n##  SET BACKGROUND IMAGE"
	Write-Host "Checking the following file: MYWALLPAPER_DESKTOP_BACKGROUND"
	$filePath1 = "$env:USERPROFILE\Pictures\wallpaperbetter-3840-2160-3.jpg"
	$webPath1 = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/wallpaperbetter-3840-2160-3.jpg"
	Test_ImagePath $filePath1 $webPath1
	# Show File
	Write-Host "$filePath1`n" -ForegroundColor Cyan -NoNewline
	# Get-ChildItem "$env:USERPROFILE\Pictures\wallpaperbetter-3840-2160-3.jpg" | Format-Table

	# Change current picture
	Set_BackgroundImage "HKCU:\Control Panel\Desktop" "WallPaper" "$env:USERPROFILE\Pictures\wallpaperbetter-3840-2160-3.jpg"
	
	# Change to a Fill
	Write-Host "`n##  SET FIT TYPE"
	Set_FitType
	
	Write-Host "`n##  TEST BACKGROUND OTHER"
	Write-Host "Checking the following file: MYWALLPAPER_LOCK_SCREEN"
	$filePath2 = "$env:USERPROFILE\Pictures\cropped-3840-2160-310526.jpg"
	$webPath2 = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/cropped-3840-2160-310526.jpg"
	Test_ImagePath $filePath2 $webPath2
	# Show File
	Write-Host "$filePath2`n" -ForegroundColor Cyan -NoNewline
	# Get-ChildItem "$env:USERPROFILE\Pictures\cropped-3840-2160-310526.jpg" | Format-Table

	Write-Host "Checking the following file: MYWALLPAPER_BROWSER_BACKGROUND"
	$filePath3 = "$env:USERPROFILE\Pictures\dark-minimal-mountains.png"
	$webPath3 = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/dark-minimal-mountains.png"
	Test_ImagePath $filePath3 $webPath3
	# Show File
	Write-Host "$filePath3`n" -ForegroundColor Cyan -NoNewline
	# Get-ChildItem "$env:USERPROFILE\Pictures\dark-minimal-mountains.png" | Format-Table

	Write-Host "=========================="
	Write-Host "  Operation are Finished  "
	Write-Host "=========================="
}

function Custom_Shell_Pwsh () {

	Write-Host "::  PROFILE CUSTOM : SHELL PWSH"
	$addComment = "## Microsoft.PowerShell_profile.ps1"
	$activatePrompt = Install_PromptT "kushal"
	$iconsComand = Install_ModuleT
	$predictionComand = Enable_ListViewT

	Write-Host ">>  PROFILE BACKGROUND"
	Write-Host "Checking the following file: MYWALLPAPER_TERMINAL_BACKGROUND"
	$filePath = "$env:USERPROFILE\Pictures\wallpaperbetter.com_3840x2160 (1).jpg"
	$webPath = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/wallpaperbetter.com_3840x2160%20(1).jpg"
	Test_ImagePath $filePath $webPath

	Write-Host "$filePath`n" -ForegroundColor Cyan -NoNewline
	# Write-Host "Setting Background Image Path: PROFILE"
	
	# Write-Host "Checking the following file: SETTINGS"
	
	# Create File
	Write-Host ">>  PROFILE SHELL"
	Write-Host "Creating the following file: `$PROFILE"
	$PROFILE_TEMP1 = "$env:USERPROFILE\Documents\PowerShell"
	Test-ItemPath $PROFILE_TEMP1 "Microsoft.PowerShell_profile.ps1" "File"
	$PROFILE_PATH_1 = "$PROFILE_TEMP1\Microsoft.PowerShell_profile.ps1"

	# Show File
	Get-ChildItem $PROFILE_PATH_1 | Format-Table
	Write-Host $PROFILE_PATH_1 -ForegroundColor Cyan

	# Add Content
	Write-Host "Adding content the following file: `$PROFILE"
	# $stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26) #deprecated -ERROR DE THEMA
	Test-FileContent $PROFILE_PATH_1 $addComment $addComment
	Test-FileContent $PROFILE_PATH_1 $activatePrompt $activatePrompt
	Test-FileContent $PROFILE_PATH_1 $iconsComand $iconsComand
	Test-FileContent $PROFILE_PATH_1 $predictionComand $predictionComand

	# Show Content
	Write-Host "$(Get-Content -Path $PROFILE_PATH_1 -Raw)`n" -ForegroundColor Cyan -NoNewline
}

function Custom_Shell_Powershell () {
	
	Write-Host "::  PROFILE CUSTOM : SHELL POWERSHELL"
	$addComment = "## Microsoft.PowerShell_profile.ps1"
	$activatePrompt = Install_PromptT "kali"
	
	Write-Host ">>  PROFILE BACKGROUND"
	Write-Host "Checking the following file: MYWALLPAPER_TERMINAL_BACKGROUND"
	$filePath = "$env:USERPROFILE\Pictures\483179 - copia.jpg"
	$webPath = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/483179%20-%20copia.jpg"
	Test_ImagePath $filePath $webPath

	Write-Host "$filePath`n" -ForegroundColor Cyan -NoNewline
	# Write-Host "Setting Background Image Path: PROFILE"

	# Create File
	Write-Host ">>  PROFILE SHELL"
	Write-Host "Creating the following file: `$PROFILE"
	$PROFILE_TEMP2 = "$env:USERPROFILE\Documents\WindowsPowerShell"
	Test-ItemPath $PROFILE_TEMP2 "Microsoft.PowerShell_profile.ps1" "File"
	$PROFILE_PATH_2 = "$PROFILE_TEMP2\Microsoft.PowerShell_profile.ps1"

	# Show File
	Get-ChildItem $PROFILE_PATH_2 | Format-Table
	Write-Host $PROFILE_PATH_2 -ForegroundColor Cyan

	# Add Content
	Write-Host "Adding content the following file: `$PROFILE"
	# $stringReduce = $activatePrompt.Substring(0, $activatePrompt.Length - 26) #deprecated -ERROR DE THEMA
	Test-FileContent $PROFILE_PATH_2 $addComment $addComment
	Test-FileContent $PROFILE_PATH_2 $activatePrompt $activatePrompt

	# Show Content
	Write-Host "$(Get-Content -Path $PROFILE_PATH_2 -Raw)`n" -ForegroundColor Cyan -NoNewline
}

function Set-ClinkLogoMessage {
	param (
		[string]$filePath,
		[string]$typeMessage
	)
	$fileContent = Get-Content -Path $filePath -Raw

	if ( -not ($fileContent -notmatch [regex]::escape($typeMessage)) ) {
		
		Write-Host "Value [$typeMessage] not found, Changing..." -ForegroundColor Yellow
		$modContent = $fileContent -replace "clink.logo = full", "clink.logo = none"
		Set-Content -Path $filePath -Value $modContent
	}
}

function Install_PromptC {
	param (
		[string]$promptName
	)

	# Cargar dependencias necesarias
	Write-Host "This config requires the following packages!"
	InstallPkgChoco "nerd-fonts-cascadiacode" choco # CaskaydiaCove Nerd Font
	InstallPkgWinget @("chrisant996.Clink", "Starship.Starship") winget # (clink set clink.logo none)
	
	# Write-Host ">>  TOOL CUSTOM"  # EN DESARROLLO
	# Write-Host "Set content the following file: `$SETTING"
	# Set-ClinkLogoMessage "$env:LOCALAPPDATA\clink\clink_settings" "none"

	# Mostrar mensaje de operacion
	Write-Host ">>  PROMPT CUSTOM"
	Write-Host "Loading the following config of prompt: STARSHIP"
	
	# Cargar Starship en la config de la terminal
	$loadPrompt = "load(io.popen('$promptName init cmd'):read(`"*a`"))()"
	Write-Host "Config ==> $loadPrompt" -ForegroundColor Cyan

	return $loadPrompt
}

function Function_Name {
	param (
		[string]$path1,
		[string]$path2
	)
	
	# Establecer ruta de tema STARSHIP
	$path1 = "os.getenv(`"USERPROFILE`")"
	$path2 = '\\starship\\.config\\starship.toml'
	$themePath = "local preset_path = $path1 .. $path2"

	return $themePath
}

function Function_Name {
	param (
		[string]$path
	)
	
	# Establecer configuracion de tema STARSHIP
	$configPreset = "os.setenv(`"STARSHIP_CONFIG`", $path)"

	return $configPreset
}

function Custom_Shell_Cmd () {

	Write-Host "::  PROFILE CUSTOM : SHELL CMD"
	$addComment = "-- starship.lua"
	$loadPrompt = Install_PromptC "starship"
	# $themePath = Function_Name "USERPROFILE" "filePath_toml"
	# $configPreset = Funtcion_Name "preset_path"

	Write-Host ">>  PROFILE BACKGROUND"
	Write-Host "Checking the following file: MYWALLPAPER_TERMINAL_BACKGROUND"
	$filePath = "$env:USERPROFILE\Pictures\wallpaperbetter.com_3840x2160 (2).jpg"
	$webPath = "https://raw.githubusercontent.com/DiegoEli/wallpaper-dark/refs/heads/main/wallpaper_desktop/wallpaperbetter.com_3840x2160%20(2).jpg"
	Test_ImagePath $filePath $webPath

	Write-Host "$filePath`n" -ForegroundColor Cyan -NoNewline
	# Write-Host "Setting Background Image Path: PROFILE"
	
	# Create File
	Write-Host ">>  CONFIG SHELL"
	Write-Host "Creating the following file: `$CONFIG"
	$CONFIG_TEMP3 = "$env:LOCALAPPDATA\clink"
	Test-ItemPath $CONFIG_TEMP3 "starship.lua" "File"
	$CONFIG_PATH_3 = "$CONFIG_TEMP3\starship.lua"

	# Show File
	Get-ChildItem $CONFIG_PATH_3 | Format-Table
	Write-Host $CONFIG_PATH_3 -ForegroundColor Cyan
	
	# Add Content
	Write-Host "Adding content the following file: `$CONFIG"
	Test-FileContent $CONFIG_PATH_3 $addComment $addComment
	Test-FileContent $CONFIG_PATH_3 $loadPrompt $loadPrompt
	# Test-FileContent $CONFIG_PATH_3 $themePath $themePath
	# Test-FileContent $CONFIG_PATH_3 $configPreset $configPreset

	# Show Content
	Write-Host "$(Get-Content -Path $CONFIG_PATH_3 -Raw)" -ForegroundColor Cyan -NoNewline
}

function Custom_Pwsh_Powershell_Cmd ($mainContent) {
	# Limpia las referencias de CheckBoxes previas
	$global:CheckBoxRefs.Clear()

	$varTextBlock1 = "SHELL PWSH" + 
	"`n- Se agrega un prompt personalizado de oh-my-posh con el tema 'kushal'." + 
	"`n- Se agrega el modulo 'Terminal-Icons' para mostrar iconos en los archivos o carpetas." + 
	"`n- Se agrega el modulo 'z' para moverse entre directorios mas rapido." + 
	"`n- Se habilita el modo 'ListView' para mostrar las sugerencias en forma de lista."
	$varTextBlock2 = "SHELL POWERSHELL" + 
	"`n- Se agrega un prompt personalizado de oh-my-posh con el tema 'kali'."
	$varTextBlock3 = "SHELL CMD" + 
	"`n- Se agrega el complemento 'Clink' para ampliar las funcionalidades de la Shell." + 
	"`n- Se agrega un prompt personalizado de oh-my-posh con el tema 'stelbent'."

	$panelWindow = GenerateWinGUIShell "SELECCIONE LOS PERFILES QUE DESEA AÑADIR" "Aplicar"
	$mainContent.Children.Clear()
	$mainContent.Children.Add($panelWindow)
	
	Add-GenerateTextBlock $varTextBlock1 $panelWindow "TextBlock1"
	GenerateCheckBox "Aplicar PERFIL" $panelWindow "CheckBox1"

	Add-GenerateTextBlock $varTextBlock2 $panelWindow "TextBlock2"
	GenerateCheckBox "Aplicar PERFIL" $panelWindow "CheckBox2"

	Add-GenerateTextBlock $varTextBlock3 $panelWindow "TextBlock3"
	GenerateCheckBox "Aplicar CONFIG" $panelWindow "CheckBox3"

	$captPanelRef = $panelWindow
	$captPanelRef.FindName("ActionButton").Add_Click({
		
		Write-Host "==  SELECTED OPERATIONS  =="
		$checkBox1 = $global:CheckBoxRefs["CheckBox1"]
		if ( $checkBox1 -and $checkBox1.IsChecked ) {
			Custom_Shell_Pwsh
			# Write-Host "FUNCION EN MANTENIMIENTO => Custom_Shell_Pwsh" -ForegroundColor Yellow
		}

		$checkBox2 = $global:CheckBoxRefs["CheckBox2"]
		if ( $checkBox2 -and $checkBox2.IsChecked ) {
			Custom_Shell_Powershell
			# Write-Host "FUNCION EN MANTENIMIENTO => Custom_Shell_Powershell" -ForegroundColor Yellow
		}
		
		$checkBox3 = $global:CheckBoxRefs["CheckBox3"]
		if ( $checkBox3 -and $checkBox3.IsChecked ) {
			Custom_Shell_Cmd
			# Write-Host "FUNCION EN MANTENIMIENTO => Custom_Shell_Cmd" -ForegroundColor Yellow
		}
		Write-Host "=========================="
		Write-Host "  Operation are Finished  "
		Write-Host "=========================="
	})
}

#####################################################
#	PRINT_MENUS
#####################################################

# draw Show-InfoView
function Show-InfoView {
	Write-Host ""
	"$_esc[1;32mAuthor  : $_esc[0m$global:WPAuthor"
	"$_esc[1;32mProject : $_esc[0m$global:WPName"
	"$_esc[1;32mRelease : $_esc[0m$global:WPVersion"
	"💀 ██████╗ ███████╗ █████╗ ███╗   ███╗ ██████╗ ███╗   ██╗ 💀"
	"💀 ██╔══██╗██╔════╝██╔══██╗████╗ ████║██╔═══██╗████╗  ██║ 💀"
	"💀 ██║  ██║█████╗  ███████║██╔████╔██║██║   ██║██╔██╗ ██║ 💀"
	"💀 ██║  ██║██╔══╝  ██╔══██║██║╚██╔╝██║██║   ██║██║╚██╗██║ 💀"
	"💀 ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║ 💀"
	"💀 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ 💀"
	"Loading Main Deamon..."
}

#####################################################
#	MENU_OPTIONS
#####################################################

# call view Invoke-MainView
function Invoke-MainView {
	Show-InfoView
	$window = GenerateWinGUIMenu
	
	$btnChaPreference = $window.FindName("BtnChaPreference")
	$btnEsseTweaks = $window.FindName("BtnEsseTweaks")
	$btnRemBloatware = $window.FindName("BtnRemBloatware")
	$btnAddAppTool = $window.FindName("BtnAddAppTool")
	$btnCustoTerminal = $window.FindName("BtnCustoTerminal")

	$mainContent = $window.FindName("MainContent")

	$btnChaPreference.Add_Click({
		& { $null = Test-ModuleDism } 6> $null
		Set_Option_ServiceTask_Feature $mainContent
	})
	$btnEsseTweaks.Add_Click({
		Set_Privacy_Update_Performance $mainContent
	})
	$btnRemBloatware.Add_Click({
		& { $null = Test-ModuleDism } 6> $null
		Test-ModuleAppx
		Remove_Capability_Package_Provisioned $mainContent
	})
	$btnAddAppTool.Add_Click({
		Install_AppPkg_AppDev_Tool $mainContent
	})
	$btnCustoTerminal.Add_Click({
		Custom_Pwsh_Powershell_Cmd $mainContent
	})

	$window.ShowDialog()
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
function Test-CurrentRolScript {
	$userCurrent = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	$roleCurrent = ([Security.Principal.WindowsBuiltInRole] "Administrator")
	
	$adminCondition = $userCurrent.IsInRole($roleCurrent)
	if ( (-not $adminCondition) -or ($PSVersionTable.PSEdition -notlike "Core") ) {

		Write-Host "Checking if Rol is Administrator..."
		Write-Host " -The SCRIPT requires to run as Administrator" -ForegroundColor Yellow

		$scriptPath = $PSCommandPath
		$shellV7 = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
		$command = Get-CommandType $scriptPath
		
		Start-Process -FilePath "wt.exe" -ArgumentList "`"$shellV7`" $command" -Verb RunAs
		Start-Sleep -Milliseconds 3000
		exit
	}
}

# Test Winget
function Test-WingetVersion {
	try {

		$wingetCondition = Invoke-Expression "winget --version"
	} 
	catch {

		Write-Error "ERROR: $_"
		Write-Host "Checking if PkgMng Winget is Installed..."
		
		if ( -not $wingetCondition ) {

			Write-Host " -Installing WinGet PowerShell module from PSGallery" -ForegroundColor Yellow
			$null = Install-PackageProvider -Name "NuGet" -Force
			Install-Module -Name "Microsoft.WinGet.Client" -Repository "PSGallery" -Force
			
			Write-Host " -Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet" -ForegroundColor Yellow
			Repair-WinGetPackageManager
			
			Write-Host " -Accepting source and package agreements" -ForegroundColor Yellow
			$null = Invoke-Expression "winget upgrade --accept-source-agreements --accept-package-agreements"
		}
	}
}

# Test Choco
function Test-ChocoVersion {
	# $chocoCondition = $null
	$userCurrent = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	$roleCurrent = ([Security.Principal.WindowsBuiltInRole] "Administrator")
	try {

		$chocoCondition = Invoke-Expression "choco --version"
	} 
	catch {

		Write-Error "ERROR: $_"
		Write-Host "Checking if PkgMng Chocolatey is Installed..."

		if ( (-not $chocoCondition) -and ($userCurrent.IsInRole($roleCurrent)) ) {

			Write-Host " -Installing the package manager Chocolatey" -ForegroundColor Yellow
			Set-ExecutionPolicy Bypass -Scope "Process" -Force; 
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
			Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
		}
	}
}

# Test Scoop
function Test-ScoopVersion {
	try {

		$scoopCondition = Invoke-Expression "scoop --version" 6> $null
	} 
	catch {

		Write-Error "ERROR: $_"
		Write-Host "Checking if PkgMng Scoop is Installed..."

		if ( -not $scoopCondition ) {

			Write-Host " -Installing the package manager Scoop" -ForegroundColor Yellow
			Set-ExecutionPolicy -ExecutionPolicy "RemoteSigned" -Scope "CurrentUser" -Force
			Invoke-RestMethod -Uri 'https://get.scoop.sh' | Invoke-Expression
		}
	}
}

# Test PowerShell
function Test-PwshVersion {
	try {

		$pwshCondition = Invoke-Expression "pwsh --version"
	} 
	catch {
		
		Write-Error "ERROR: $_"
		Write-Host "Checking if Shell pwsh is Installed..."

		if ( -not $pwshCondition ) {

			$null = Invoke-Expression "winget upgrade --accept-source-agreements --accept-package-agreements"
			
			Write-Host " -Installing the shell PowerShell Core" -ForegroundColor Yellow
			InstallPkgWinget "Microsoft.PowerShell" winget
		}
	}
}

function Test-TerminalVersion {
	try {

		$packagePath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe"
		$wtCondition = Get-Item -Path $packagePath -ErrorAction Stop
	}
	catch {

		Write-Error "ERROR: $_"
		Write-Host "Checking if Windows Terminal is Installed..."

		if ( -not $wtCondition ) {
			
			Write-Host " -Installing the terminal Windows Terminal" -ForegroundColor Yellow
			InstallPkgWinget "Microsoft.WindowsTerminal" winget
		}
	}
}

Clear-Host
$Host.UI.RawUI.WindowTitle = "DeamonScript 💀"

Test-WingetVersion  # Checking if Winget is installed
Test-ChocoVersion  # Checking if Chocolatey is installed
Test-ScoopVersion  # Checking if Scoop is installed
Test-PwshVersion  # Checking if Shell pwsh is installed
Test-TerminalVersion  # Checking if Windows Terminal is installed

Test-CurrentRolScript  # Checking if Rol is Administrator for Script

# Establecer la página de códigos a UTF-8
chcp 65001 > $null

# Invoke the Main Menu the Script.
Invoke-MainView

# Sleep for 3 seconds
Start-Sleep -Milliseconds 3000

# Policy Execution Restart
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "CurrentUser" -Force
#Set-ExecutionPolicy -ExecutionPolicy "Undefined" -Scope "LocalMachine" -Force
