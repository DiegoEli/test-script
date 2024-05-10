function Test-CurrentRol () {
	$userCurrent = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	$roleCurrent = ([Security.Principal.WindowsBuiltInRole] "Administrator")
	
	$adminCondition = $userCurrent.IsInRole($roleCurrent)
	if (!$adminCondition) {

		Write-Host " -The script requires to run as Administrator..." -ForegroundColor Yellow

		$scriptPath = $PSCommandPath
		if ($scriptPath -match '^irm http(s)?://') {
  
      Write-Host "Ejecutando Archivo_Remoto"
			$command = "-Command `"irm https://raw.githubusercontent.com/DiegoEli/testScript.ps1 | iex`""
		} 
    else {
  
      Write-Host "Ejecutando Archivo_Local"
			$command = "-File `"$scriptPath`""
		}

		Write-Host "Type Argument -> {$scriptPath}"
		Start-Process -FilePath "wt.exe" -ArgumentList "pwsh $command" -Verb RunAs
		exit
	}
}

"Test...`nElevo el proceso??"
Get-AppxProvisionedPackage -Online | Format-Table
$PSVersionTable | Format-Table
Write-Host "Press any key to continue..."; Read-Host
