# Checkpoint Oleada 2 — Recolector On-Premise, Agente Windows Endurecido y Dashboard CISO/SOC/DPO

**Fecha:** 2026-11-21
**Rama:** `feat/hybrid-architecture-v2`

## Entregables Completados (3 subagentes en paralelo)
1. **`onprem-collector/` + `docker-compose.yml` + `.env.example` (`onprem-collector`)**:
   - Extracción real de `.docx` (`python-docx`), `.xlsx` (`openpyxl`), `.pdf` comprimidos (`pypdf`), texto plano e imágenes OCR (`pytesseract`/`Pillow` con degradación limpia cuando falta el binario `tesseract`).
   - Escáneres `smb_scanner.py` (`simulate_if_unreachable=False` por defecto, evalúa antigüedad 7 años general / 20 años Ley 68) y `db_scanner.py` (SQLite nativo + adaptadores PostgreSQL, MySQL, SQL Server y Oracle; emite únicamente metadatos anonimizados y muestras enmascaradas).
   - Conectores `adguard_connector.py` (en vivo `/control/status` + `/control/querylog`, reportando `OFFLINE` honestamente si no responde) y `wazuh_connector.py` (API REST desacoplada GPLv2-safe).
   - `health_monitor.py` + `sync_client.py` (store-and-forward sobre `PendingSyncQueue` en SQLite con reintentos hacia `/api/v2/health/heartbeat`, `/api/v2/ingest/findings`, `/api/v2/ingest/endpoint`, `/api/v2/ingest/shadow-ai`).
   - `report_generator.py` con citas legales corregidas (`DE 285 Art. 37 y Art. 48.3`, `Ley 81 Arts. 15-16/25/32-33/41.4/45`, `B/. 1,000 a B/. 10,000`, clausura BD, publicación sanciones, imprescriptibilidad, `Acuerdo 001-2022 SBP`, `Ley 68 de 2003`) y hoja de ruta híbrida Cloudflare; + `main.py` FastAPI con Bearer Auth y CORS estricto.
   - `docker-compose.yml` actualizado (`onprem-collector`, `frontend`, `adguard`, `cloudflared` con perfil `tunnel`) sin contraseñas débiles fijas.
2. **`agents/` (`windows-endpoint-agent`)**:
   - `Vektor81-EndpointCollector.ps1` v2.0.0: HTTPS obligatorio por defecto (`-AllowInsecureHttp` explícito para pruebas locales), `Authorization: Bearer` + `X-Tenant-Id`, soporte `-DryRun` y `-HeartbeatOnly`, validación `Test-PanamaNaturalId` alineada 100% con `panama_pii_test_vectors.json`, auditoría de **Box Drive + OneDrive** con enmascaramiento de muestras y cobertura completa del diccionario de 155 dominios IA.
   - `Test-EndpointCollector.ps1`: suite AST + pruebas funcionales.
3. **`frontend/` (`dashboard-ciso-soc`)**:
   - Nuevo Dashboard Híbrido con 4 vistas (`SystemHealthPage`, `CisoOverviewPage`, `ComplianceDpoPage`, `AssetsAdminPage`), `AuthGateModal` (401/token Bearer), `Layout` con selector de tenant, perfil regulatorio (`ANTAI_LEY81`, `SBP_001_2022`, `SALUD_LEY68`), píldora global de salud y banner rojo pulsante ante cualquier componente `OFFLINE`.
   - Nginx (`nginx.conf`) y Vite (`vite.config.ts`) configurados para `/api/v1` (collector) y `/api/v2` (control plane).

## Verificaciones Ejecutadas
| Módulo | Comando | Resultado |
| :--- | :--- | :--- |
| `onprem-collector` | `.venv\Scripts\python.exe -m unittest discover -s onprem-collector/tests -v` | **PASS** (11/11 tests en 6.44s) |
| `agents` | `powershell -ExecutionPolicy Bypass -File agents/Test-EndpointCollector.ps1` | **PASS** (24/24 aserciones, AST 0 errores) |
| `frontend` | `npm test && npx tsc --noEmit && npm run build` | **PASS** (4/4 tests `vitest`, 0 errores TS, `dist` compilado en 13.47s) |
| `docker-compose` | `docker compose --profile tunnel config --quiet` | **PASS** (exit 0) |
