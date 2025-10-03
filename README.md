# Script de Configuración de Equipos

- Este script automatiza la configuración inicial de un equipo Windows aplicando ***ajustes predefinidos***.
- Está diseñado para su uso en una ***instalación out-the-box***, es decir, una ***instalación limpia de Windows 11***.  
- Se ejecuta completamente ***en memoria***, por lo que al finalizar se elimina automáticamente del sistema, dejando solo los cambios aplicados.  
- No requiere ejecutarse en ***modo administrador***: el script está validado para ***auto-elevar privilegios*** en caso de que se ejecute en una sesión normal de usuario.

---

## Tecnologías utilizadas
- PowerShell
- .NET
- WPF
- XAML

---

<!-- Primer formato de comentario -->
## Requisitos previos
* PowerShell 5.0 o superior
* Windows 11 (instalación limpia recomendada)
* Acceso a internet para descargar los recursos

---

[//]: # (Segundo formato de comentario)
## Instalación y uso
1. Abrir PowerShell 5 (no es necesario como administrador).
2. Ejecutar el siguiente comando:
```powershell
irm "https://raw.githubusercontent.com/DiegoEli/test-script/refs/heads/testing/testScript.ps1" | iex
```

---

[comment]: # (Tercer formato de comentario)
## Observaciones
- El script se autoeleva si es necesario, por lo que no requiere abrir PowerShell como administrador.
- No es necesario cambiar la política de ejecución (ExecutionPolicy).
- Este script aplicará ajustes por defecto, asegúrese de revisarlos antes de usarlo en entornos personales.

<!--
[//]: # (Otro formato de comentario)
## Licencia
Este proyecto está bajo la licencia **MIT**.
Ver el archivo [LICENSE](LICENSE) para más detalles.

---

## Autor
Desarrollado por **Diego Mendoza**.
🔗 GitHub: [@DiegoEli](https://github.com/DiegoEli)
-->
---
