function Test-CurrentRol () {
	$userCurrent = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	$roleCurrent = ([Security.Principal.WindowsBuiltInRole] "Administrator")
	
	$adminCondition = $userCurrent.IsInRole($roleCurrent)
	if (!$adminCondition) {

		Write-Host " -The script requires to run as Administrator..." -ForegroundColor Yellow

		$scriptPath = $PSCommandPath
		$repositoryPath = 'https://raw.githubusercontent.com/DiegoEli/test-script/main/testScript.ps1'
		if ($scriptPath -match "^C:\.*" ) {
			
			Write-Host "Ejecutando Archivo_Local"
			$command = "-File `"$scriptPath`""
		} 
		else {
			
			Write-Host "Ejecutando Archivo_Remoto"
			$command = "-Command `"irm $repositoryPath | iex`""
  
		}

		Write-Host "Type Argument -> {$command}"
		Start-Process -FilePath "wt.exe" -ArgumentList "pwsh $command" -Verb RunAs
		#exit
  		Exit-PSSession
    		#Exit-PSHostProcess
	}
 	#exit
}

Clear-Host

Test-CurrentRol
"Test...`nElevo el proceso??"

Get-AppxProvisionedPackage -Online | Format-Table
$PSVersionTable | Format-Table
Write-Host "Press any key to continue..."; Read-Host
