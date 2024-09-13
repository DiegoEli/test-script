## Informacion de Script.
Ejecucion sin restricciones, para la Sesión actual de PowerShell.

   ```
   Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
   ```

Ejecucion sin restricciones, para el Usuario actual.

   ```
   Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
   ```

Ejecutar el script de manera remota en Powershell:

   ```
   irm https://raw.githubusercontent.com/DiegoEli/test-script/preview/testScript.ps1 | iex
   ```
