## Informacion de Script.
Ejecucion sin restricciones, para la Sesión actual de PowerShell-(solo cuando em local).

   ```
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   ```

Ejecucion sin restricciones, para el Usuario actual-(solo en local).

   ```
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

Ejecutar el script de manera remota en Powershell-(llamada remota no necesita ExecutionPolicy)

   ```
   irm https://raw.githubusercontent.com/DiegoEli/test-script/temp/testScript.ps1 | iex
   ```
