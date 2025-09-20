## Informacion de Script.
Ejecucion sin restricciones, para la Sesión actual de PowerShell.

   ```
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   ```

Ejecucion sin restricciones, para el Usuario actual.*

   ```
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

Ejecutar el script de manera remota en Powershell:

   ```
   irm https://raw.githubusercontent.com/DiegoEli/test-script/temp/testScript.ps1 | iex
   ```
