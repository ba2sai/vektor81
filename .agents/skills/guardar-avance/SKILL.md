---
name: guardar-avance
description: Use when the user asks to "guardar avance", save progress, or commit and push Vektor81 workspace changes to GitHub.
---

# Guardar Avance (Commit & Push a GitHub)

Procedimiento estandarizado para respaldar avances del proyecto Vektor81 en el repositorio remoto `https://github.com/ba2sai/vektor81.git` sin exponer credenciales ni artefactos locales.

## Cuándo Usar y Cuándo NO Usar

- **Usar cuando:** El usuario pida "guardar avance", respaldar cambios en GitHub, hacer commit y push de la rama activa.
- **NO usar cuando:** Existan secretos sin ignorar (`.env`, `.dev.vars`, llaves `.pem`/`.key`, `.tfvars` reales), bases de datos locales (`.db`/`.sqlite*`) o archivos de entorno pendientes de revisar, o si el usuario pide reescribir historial (`--force`).

## Procedimiento

1. **Inspeccionar estado y rama activa:**
   ```powershell
   git status --short
   git branch --show-current
   ```
   Confirmar que no estás en *detached HEAD*.

2. **Verificar remoto `origin`:**
   Debe apuntar a `https://github.com/ba2sai/vektor81.git`. Si `origin` apunta a otro repositorio distinto, **detente y consulta al usuario** antes de modificarlo.

3. **Ejecutar validación previa (`-DryRun` opcional) y guardar avance:**
   Usa el script auxiliar [guardar-avance.ps1](./scripts/guardar-avance.ps1):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .agents/skills/guardar-avance/scripts/guardar-avance.ps1 -Message "<tipo: resumen conciso del avance>"
   ```
   - El script bloquea archivos sensibles (`.env`, `.dev.vars`, `*.pem`, `*.key`, `*.tfvars`, `*.db`, `*.sqlite*`, `.venv/`, `node_modules/`), exceptuando plantillas `.example`.
   - Si no hay cambios locales pero existen commits sin subir, omite el commit y ejecuta el `git push -u origin <rama>`.
   - Ejecuta Git con `GIT_TERMINAL_PROMPT=0` para evitar bloqueos interactivos.

4. **Verificar resultado:**
   Comprueba que `git status --short` quede limpio, confirma el hash en `git log -n 2 --oneline` y reporta rama, commit y resultado del `push`.

## Referencia Rápida

| Acción | Comando |
| :--- | :--- |
| Simular sin modificar repo | `powershell -ExecutionPolicy Bypass -File .agents/skills/guardar-avance/scripts/guardar-avance.ps1 -DryRun -Message "test"` |
| Guardar avance con mensaje | `powershell -ExecutionPolicy Bypass -File .agents/skills/guardar-avance/scripts/guardar-avance.ps1 -Message "feat: descripcion"` |
| Guardar avance con mensaje automático | `powershell -ExecutionPolicy Bypass -File .agents/skills/guardar-avance/scripts/guardar-avance.ps1` |

## Errores Comunes

- **Fallo de autenticación en `push`:** Nunca incrustes tokens PAT en `.git/config` ni los escribas en archivos del repo. Pide al usuario iniciar sesión con Git Credential Manager o `gh auth login` y reintentar `git push -u origin <rama>`.
- **Remoto faltante o distinto:** El script registra `https://github.com/ba2sai/vektor81.git` únicamente si `origin` no existe; si ya apunta a otro repo, aborta para evitar sobrescritura accidental.
- **Archivos secretos detectados:** Añádelos a `.gitignore` o muévelos fuera del árbol versionado antes de reintentar.
