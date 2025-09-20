## Informacion de Script.
Ejecucion sin restricciones, para la Sesión actual de PowerShell (SOLO em local).

   ```
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   ```

Ejecucion sin restricciones, para el Usuario actual (SOLO en local).

   ```
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

Ejecutar el script de manera remota en Powershell (INVOKE-REMOTE no necesita ExecutionPolicy)

   ```
   irm "https://raw.githubusercontent.com/DiegoEli/test-script/refs/heads/temp/testScript.ps1" | iex
   ```
