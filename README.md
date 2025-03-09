## Informacion de Script.
Ejecucion sin restricciones, para el Usuario actual.

   ```
   Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope "CurrentUser" -Force
   ```

Ejecucion sin restricciones, para la Maquina local.

   ```
   Set-ExecutionPolicy -ExecutionPolicy "Unrestricted" -Scope "LocalMachine" -Force
   ```

Ejecutar el script de manera remota en Powershell:

   ```
   irm https://raw.githubusercontent.com/DiegoEli/test-script/dev/testScript.ps1 | iex
   ```
