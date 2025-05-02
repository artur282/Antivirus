# 🛡️ Antivirus Python

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

_Un antivirus moderno, eficiente y de código abierto desarrollado en Python_

</div>

## 🌟 Descripción

Antivirus Python es una solución de seguridad de código abierto que combina la potencia del análisis de hashes con una interfaz gráfica moderna y amigable. Diseñado para proporcionar protección en tiempo real contra amenazas, este antivirus implementa técnicas avanzadas de detección y ofrece una suite completa de herramientas de análisis y reportes.

## ✨ Características Principales

- 🔍 **Múltiples Tipos de Escaneo**

  - Escaneo de archivos individuales
  - Escaneo de directorios completos
  - Escaneo rápido de zonas críticas
  - Escaneo completo del sistema

- 🛡️ **Detección Avanzada**

  - Análisis mediante múltiples algoritmos de hash (MD5, SHA1, SHA256)
  - Comparación con base de datos de firmas
  - Detección en tiempo real

- 📊 **Dashboard Estadístico**

  - Visualización de datos de escaneo
  - Múltiples tipos de gráficos
  - Análisis de tendencias

- 📝 **Generación de Reportes**

  - Exportación a PDF
  - Exportación a CSV
  - Historial detallado de escaneos

- 🎨 **Interfaz Moderna**

  - Temas claro y oscuro
  - Diseño responsive
  - Interfaz intuitiva

- 🔒 **Gestión de Amenazas**
  - Sistema de cuarentena
  - Eliminación segura
  - Registro de actividades cifrado

## 🔧 Requisitos Técnicos

- Python 3.8 o superior
- Sistema operativo: Windows/Linux/MacOS
- Acceso de administrador (para escaneo completo)

## 📦 Instalación

1. Clona el repositorio:

   ```bash
   git clone https://github.com/artur282/Antivirus.git
   cd antivirus-python
   ```

2. Crea un entorno virtual (recomendado):

   ```bash
   python -m venv venv
   source venv/bin/activate  # En Linux/Mac
   # o
   venv\Scripts\activate  # En Windows
   ```

3. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

4. Desconprimir virus_data.db.7z

## 🚀 Uso

1. Ejecuta la aplicación:

   ```bash
   python main.py
   ```

2. Desde la interfaz principal puedes:
   - Seleccionar el tipo de escaneo
   - Configurar opciones
   - Ver estadísticas
   - Generar reportes

## 🏗️ Arquitectura

El proyecto está estructurado en varios componentes principales:

- **GUI**: Implementada con Tkinter para una experiencia de usuario fluida
- **Motor de Escaneo**: Sistema multihilo para análisis eficiente
- **Base de Datos**: SQLite para almacenamiento de datos y firmas
- **Sistema de Reportes**: Generación de informes en PDF y CSV
- **Módulo de Seguridad**: Gestión de amenazas y cuarentena

## 📋 Dependencias Principales

```
matplotlib==3.7.2
reportlab==4.0.4
cryptography==41.0.4
```

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Si deseas contribuir:

1. Haz fork del proyecto
2. Crea una rama para tu característica (`git checkout -b feature/AmazingFeature`)
3. Realiza tus cambios
4. Commit (`git commit -m 'Add some AmazingFeature'`)
5. Push a la rama (`git push origin feature/AmazingFeature`)
6. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - vea el archivo [LICENSE](LICENSE) para más detalles.

## ⭐ Soporte

Si este proyecto te ha sido útil, considera darle una estrella en GitHub y compartirlo con otros.

---

<div align="center">
Desarrollado con ❤️ por artur282
</div>
