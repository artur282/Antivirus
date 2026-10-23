# Antivirus Rust + Tauri

Aplicación de escritorio para escanear archivos y carpetas, detectar amenazas por hash, gestionar cuarentena y consultar el historial de análisis. Reescritura del antiguo cliente Python/Tkinter sobre Tauri v2, Rust y React.

## Características

- Escaneo de archivo, carpeta, zonas críticas y sistema completo.
- Detección por MD5, SHA1 y SHA256 contra `virus_data.db`.
- Progreso en tiempo real y cancelación de análisis.
- Historial filtrable con paginación y limpieza confirmada.
- Panel con totales, tasa de infección, distribución y actividad de 14 días.
- Exportación de reportes CSV y PDF.
- Cuarentena con restauración y eliminación definitiva confirmada.
- Tema claro y oscuro persistido localmente.
- Interfaz en español, sin dependencias de UI externas.

## Estructura

```text
crates/antivirus-core/   Motor de escaneo, base de datos, reportes y cuarentena
src-tauri/               Shell Tauri v2, comandos y estado de la aplicación
src/                     Interfaz React + TypeScript
src/ui/                  Componentes compartidos
src/features/            Vistas de escaneo, historial, panel y reportes
src/styles/              Sistema visual y estilos por vista
public/fonts/            IBM Plex Sans y IBM Plex Mono autoalojadas
docs/contracts.md        Contrato de comandos, tipos y propiedad de archivos
```

La implementación original en Python/Tkinter vive en la rama `legacy-python`.

## Requisitos

- Rust estable (probado con 1.99).
- Node.js 22 o superior y npm.
- Linux: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `librsvg2-dev`, `libayatana-appindicator3-dev` y `build-essential`.
- Windows: WebView2 y Visual Studio Build Tools.
- macOS: Xcode Command Line Tools.

## Preparación

```bash
npm install
cargo test -p antivirus-core
```

Descomprime la base de firmas incluida:

```bash
7z x virus_data.db.7z
```

La aplicación busca `virus_data.db` en este orden: variable `ANTIVIRUS_SIGNATURES_DB`, directorio actual, directorio padre, directorio del ejecutable y directorio de datos de la aplicación. También puedes seleccionarla desde la propia interfaz cuando falte.

## Desarrollo

```bash
npm run tauri dev
```

Para trabajar solo en la interfaz con el backend de demostración:

```bash
npm run dev
```

La vista de demostración permite navegar por escaneo, historial, panel y reportes con datos simulados. Las rutas aceptan `?view=scan`, `?view=history`, `?view=dashboard` y `?view=reports`.

## Compilación

```bash
npm run build
npm run tauri build
```

`npm run tauri build` genera el instalador para la plataforma actual. En Linux necesita los paquetes de desarrollo de WebKitGTK indicados arriba.

## Base de datos

- La base de firmas (`virus_data.db`) es de solo lectura para la aplicación. Los índices de los hashes se crean de forma best-effort; si el archivo no es escribible, el escaneo sigue funcionando.
- La base de la aplicación (`antivirus.db`) se guarda en el directorio de datos de la aplicación y contiene historial, cuarentena, actividad y ajustes.
- La ruta de firmas elegida por el usuario se conserva en los ajustes de la aplicación.

## Pruebas y verificación

```bash
cargo test -p antivirus-core
cargo fmt --check -p antivirus-core
npm run build
```

El motor Rust cubre detección, hashes, historial, estadísticas, cuarentena y reportes con pruebas de integración. La interfaz se verifica con TypeScript estricto y el build de Vite.

Limitaciones conocidas:

- Los escaneos rápido y completo dependen de las rutas del sistema operativo y no se ejecutan en el entorno de pruebas del proyecto.
- Las ramas específicas de Windows y macOS no se compilan en Linux.
- La cuarentena entre dispositivos distintos usa una copia y borrado de respaldo; solo se probó el caso de mismo dispositivo.
- El proyecto no incluye pruebas automatizadas del frontend.

## Diseño

La interfaz usa una dirección visual de «framed sheet»: marco tintado, hoja blanca, tipografía IBM Plex, superficies planas y color reservado para datos y estados. Las fuentes están autoalojadas en `public/fonts/` para que la aplicación funcione sin conexión.

## Licencia

MIT. Consulta el repositorio original para el aviso completo.
