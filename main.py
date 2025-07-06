import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import sqlite3
import os
import sys
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
import platform
from reportlab.lib.pagesizes import letter # type: ignore
from reportlab.pdfgen import canvas # type: ignore
import csv
from cryptography.fernet import Fernet # type: ignore
from PIL import Image, ImageTk  # Para procesamiento de imágenes

def resource_path(relative_path):
    """Obtener la ruta absoluta de un recurso, funciona tanto en desarrollo como en ejecutable"""
    try:
        # PyInstaller crea una carpeta temporal y almacena la ruta en _MEIPASS
        base_path = getattr(sys, '_MEIPASS', None)
        if base_path is None:
            raise AttributeError
    except AttributeError:
        # Si no estamos en un ejecutable, usar la ruta del script
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    return os.path.join(base_path, relative_path)

class BotApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bot Python - Protección Avanzada")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        self.root.minsize(800, 600)

        # Configurar icono de la ventana si existe
        try:
            self.root.iconphoto(False, tk.PhotoImage(file=resource_path("img/icono.png")))
        except:
            pass

        # Sistema de colores moderno
        self.colors = {
            'light': {
                'primary': '#2563eb',      # Azul moderno
                'primary_dark': '#1d4ed8', # Azul más oscuro
                'primary_light': '#3b82f6', # Azul más claro
                'secondary': '#64748b',     # Gris azulado
                'success': '#059669',       # Verde moderno
                'success_hover': '#047857', # Verde hover
                'danger': '#dc2626',        # Rojo moderno
                'danger_hover': '#b91c1c',  # Rojo hover
                'warning': '#d97706',       # Naranja
                'info': '#0891b2',          # Cyan
                'background': '#f8fafc',    # Fondo muy claro
                'surface': '#ffffff',       # Superficie blanca
                'surface_alt': '#f1f5f9',   # Superficie alternativa
                'text_primary': '#1e293b',  # Texto principal
                'text_secondary': '#64748b', # Texto secundario
                'border': '#e2e8f0',        # Bordes
                'shadow': '#00000010'       # Sombras
            },
            'dark': {
                'primary': '#4299e1',       # Azul brillante mejorado
                'primary_dark': '#3182ce',  # Azul más oscuro
                'primary_light': '#63b3ed', # Azul más claro
                'secondary': '#a0aec0',     # Gris claro mejorado
                'success': '#48bb78',       # Verde brillante mejorado
                'success_hover': '#38a169', # Verde hover
                'danger': '#f56565',        # Rojo brillante mejorado
                'danger_hover': '#e53e3e',  # Rojo hover
                'warning': '#ed8936',       # Naranja brillante mejorado
                'info': '#4fd1c7',          # Cyan brillante mejorado
                'background': '#1a202c',    # Fondo oscuro mejorado (menos extremo)
                'surface': '#2d3748',       # Superficie oscura mejorada
                'surface_alt': '#4a5568',   # Superficie alternativa más visible
                'text_primary': '#ffffff',  # Texto principal blanco puro
                'text_secondary': '#e2e8f0', # Texto secundario más claro
                'border': '#718096',        # Bordes más visibles
                'shadow': '#00000040'       # Sombras más visibles
            }
        }

        # Tema actual
        self.current_theme = "light"

        # Estilo moderno
        self.style = ttk.Style()
        self.setup_modern_styles()
        self.set_theme("light")  # Tema por defecto

        # Configuración de la interfaz principal con panel izquierdo para menú
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Panel izquierdo para el menú vertical que ocupa toda la altura
        self.menu_frame = tk.Frame(self.main_frame, width=220,
                                 bg=self.get_color('surface'),
                                 bd=0, relief=tk.FLAT)
        self.menu_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=0, pady=0)
        # Asegurar que el ancho se mantenga fijo
        self.menu_frame.pack_propagate(False)

        # Agregar sombra visual al sidebar
        shadow_frame = tk.Frame(self.main_frame, width=2, bg=self.get_color('border'))
        shadow_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        # Agregar logo en la parte superior del sidebar usando PIL con múltiples métodos de fallback
        self.logo_img = None
        logo_loaded = False
        
        # Método 1: Usar resource_path (recomendado para ejecutables)
        try:
            logo_path = resource_path("img/logo.png")
            
            if os.path.exists(logo_path):
                # Cargar la imagen con PIL
                original_img = Image.open(logo_path)
                
                # Calcular el nuevo tamaño manteniendo la proporción
                width = 120  # Ancho deseado (más proporcionado para la barra lateral)
                ratio = width / float(original_img.width)
                height = int(float(original_img.height) * ratio)
                
                # Redimensionar imagen
                resized_img = original_img.resize((width, height), Image.Resampling.LANCZOS)
                
                # Convertir la imagen de PIL a formato compatible con Tkinter
                self.logo_img = ImageTk.PhotoImage(resized_img)
                logo_loaded = True
            else:
                pass  # Archivo no encontrado
        except Exception as e:
            pass  # Error al cargar con resource_path
        
        # Método 2: Fallback usando ruta relativa directa
        if not logo_loaded:
            try:
                direct_path = "img/logo.png"
                
                if os.path.exists(direct_path):
                    original_img = Image.open(direct_path)
                    width = 120
                    ratio = width / float(original_img.width)
                    height = int(float(original_img.height) * ratio)
                    resized_img = original_img.resize((width, height), Image.Resampling.LANCZOS)
                    self.logo_img = ImageTk.PhotoImage(resized_img)
                    logo_loaded = True
                else:
                    pass  # Logo no encontrado con ruta directa
            except Exception as e:
                pass  # Error al cargar logo con ruta directa
        
        # Método 3: Usar tk.PhotoImage como fallback (más compatible con ejecutables)
        if not logo_loaded:
            try:
                # Intentar con tk.PhotoImage directamente
                logo_path = resource_path("img/logo.png")
                if os.path.exists(logo_path):
                    # Cargar imagen original
                    original_photo = tk.PhotoImage(file=logo_path)
                    
                    # Redimensionar con tk.PhotoImage (método más simple)
                    # Calcular factor de reducción
                    original_width = original_photo.width()
                    target_width = 120
                    if original_width > target_width:
                        factor = max(1, original_width // target_width)
                        self.logo_img = original_photo.subsample(factor)
                    else:
                        self.logo_img = original_photo
                        
                    logo_loaded = True
                else:
                    # Intentar con ruta directa
                    if os.path.exists("img/logo.png"):
                        original_photo = tk.PhotoImage(file="img/logo.png")
                        original_width = original_photo.width()
                        target_width = 120
                        if original_width > target_width:
                            factor = max(1, original_width // target_width)
                            self.logo_img = original_photo.subsample(factor)
                        else:
                            self.logo_img = original_photo
                        logo_loaded = True
            except Exception as e:
                pass  # Error al cargar logo con tk.PhotoImage
        
        # Crear el frame del logo y mostrar si se cargó
        logo_frame = tk.Frame(self.menu_frame, bg=self.get_color('surface'))
        logo_frame.pack(pady=(20, 15))
        
        if logo_loaded and self.logo_img:
            # Mostrar el logo
            logo_label = tk.Label(logo_frame, image=self.logo_img, bg=self.get_color('surface'))
            logo_label.pack()
        else:
            # Mostrar un placeholder de texto si no se pudo cargar el logo
            placeholder_label = tk.Label(logo_frame, 
                                       text="🛡️ ANTIVIRUS\nBOT", 
                                       font=("Segoe UI", 14, "bold"),
                                       bg=self.get_color('surface'),
                                       fg=self.get_color('text_primary'),
                                       justify=tk.CENTER)
            placeholder_label.pack()

        # Panel derecho para el contenido
        self.content_frame = ttk.Frame(self.main_frame, padding=25, style='Modern.TFrame')
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Fuentes modernas
        self.menu_font = ("Segoe UI", 11, "normal")
        self.menu_font_bold = ("Segoe UI", 11, "bold")
        self.button_font = ("Segoe UI", 10, "normal")
        self.button_font_bold = ("Segoe UI", 10, "bold")
        
        # Variables para seguir qué menú está activo
        self.active_menu = None
        
        # Crear los botones del menú vertical
        self.menu_buttons = {}
        self.submenu_frames = {}
        
        # Menú Archivo
        self.menu_buttons['archivo'] = tk.Button(
            self.menu_frame,
            text="📁 Archivo",
            font=self.menu_font,
            bg=self.get_color('surface'),
            fg=self.get_color('text_primary'),
            activebackground=self.get_color('primary_light'),
            activeforeground='white',
            anchor="w",
            padx=20,
            pady=15,
            relief=tk.FLAT,
            highlightthickness=0,
            borderwidth=0,
            cursor="hand2",
            command=lambda: self.show_submenu('archivo')
        )
        self.menu_buttons['archivo'].pack(fill=tk.X, pady=(10, 2), padx=10)
        
        # Separador moderno
        separator1 = tk.Frame(self.menu_frame, height=1, bg=self.get_color('border'))
        separator1.pack(fill=tk.X, pady=2, padx=15)

        # Submenú Archivo (inicialmente oculto)
        self.submenu_frames['archivo'] = tk.Frame(self.menu_frame, bg=self.get_color('surface_alt'))
        submenu_btn = tk.Button(
            self.submenu_frames['archivo'],
            text="   🚪 Salir",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('danger'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.root.quit
        )
        submenu_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Menú Ver
        self.menu_buttons['ver'] = tk.Button(
            self.menu_frame,
            text="👁️ Ver",
            font=self.menu_font,
            bg=self.get_color('surface'),
            fg=self.get_color('text_primary'),
            activebackground=self.get_color('primary_light'),
            activeforeground='white',
            anchor="w",
            padx=20,
            pady=15,
            relief=tk.FLAT,
            highlightthickness=0,
            borderwidth=0,
            cursor="hand2",
            command=lambda: self.show_submenu('ver')
        )
        self.menu_buttons['ver'].pack(fill=tk.X, pady=2, padx=10)
        
        # Separador moderno
        separator2 = tk.Frame(self.menu_frame, height=1, bg=self.get_color('border'))
        separator2.pack(fill=tk.X, pady=2, padx=15)

        # Submenú Ver (inicialmente oculto)
        self.submenu_frames['ver'] = tk.Frame(self.menu_frame, bg=self.get_color('surface_alt'))

        history_btn = tk.Button(
            self.submenu_frames['ver'],
            text="   📊 Historial de Escaneos",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('info'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.show_scan_history
        )
        history_btn.pack(fill=tk.X, padx=5, pady=2)

        dashboard_btn = tk.Button(
            self.submenu_frames['ver'],
            text="   📈 Dashboard Estadístico",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('info'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.show_dashboard
        )
        dashboard_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Menú Tema
        self.menu_buttons['tema'] = tk.Button(
            self.menu_frame,
            text="🎨 Tema",
            font=self.menu_font,
            bg=self.get_color('surface'),
            fg=self.get_color('text_primary'),
            activebackground=self.get_color('primary_light'),
            activeforeground='white',
            anchor="w",
            padx=20,
            pady=15,
            relief=tk.FLAT,
            highlightthickness=0,
            borderwidth=0,
            cursor="hand2",
            command=lambda: self.show_submenu('tema')
        )
        self.menu_buttons['tema'].pack(fill=tk.X, pady=2, padx=10)

        # Separador moderno
        separator3 = tk.Frame(self.menu_frame, height=1, bg=self.get_color('border'))
        separator3.pack(fill=tk.X, pady=2, padx=15)

        # Submenú Tema (inicialmente oculto)
        self.submenu_frames['tema'] = tk.Frame(self.menu_frame, bg=self.get_color('surface_alt'))

        light_btn = tk.Button(
            self.submenu_frames['tema'],
            text="   ☀️ Claro",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('warning'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=lambda: self.set_theme("light")
        )
        light_btn.pack(fill=tk.X, padx=5, pady=2)

        dark_btn = tk.Button(
            self.submenu_frames['tema'],
            text="   🌙 Oscuro",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('secondary'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=lambda: self.set_theme("dark")
        )
        dark_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Menú Reportes y Registros
        self.menu_buttons['reportes'] = tk.Button(
            self.menu_frame,
            text="📋 Reportes",
            font=self.menu_font,
            bg=self.get_color('surface'),
            fg=self.get_color('text_primary'),
            activebackground=self.get_color('primary_light'),
            activeforeground='white',
            anchor="w",
            padx=20,
            pady=15,
            relief=tk.FLAT,
            highlightthickness=0,
            borderwidth=0,
            cursor="hand2",
            command=lambda: self.show_submenu('reportes')
        )
        self.menu_buttons['reportes'].pack(fill=tk.X, pady=2, padx=10)
        
        # Separador moderno
        separator4 = tk.Frame(self.menu_frame, height=1, bg=self.get_color('border'))
        separator4.pack(fill=tk.X, pady=2, padx=15)

        # Submenú Reportes y Registros (inicialmente oculto)
        self.submenu_frames['reportes'] = tk.Frame(self.menu_frame, bg=self.get_color('surface_alt'))

        pdf_btn = tk.Button(
            self.submenu_frames['reportes'],
            text="   📄 Reporte PDF",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('danger'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.generate_pdf_report
        )
        pdf_btn.pack(fill=tk.X, padx=5, pady=2)

        csv_btn = tk.Button(
            self.submenu_frames['reportes'],
            text="   📊 Reporte CSV",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('success'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.generate_csv_report
        )
        csv_btn.pack(fill=tk.X, padx=5, pady=2)

        clear_btn = tk.Button(
            self.submenu_frames['reportes'],
            text="   🗑️ Limpiar Registros",
            anchor="w",
            bg=self.get_color('surface_alt'),
            fg=self.get_color('text_secondary'),
            activebackground=self.get_color('warning'),
            activeforeground="white",
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=8,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.clear_scan_history
        )
        clear_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Contenedor para el contenido principal (donde van los botones y resultados)
        self.frame = ttk.Frame(self.content_frame, padding=15, style='Modern.TFrame')
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Título de la sección principal
        title_frame = tk.Frame(self.frame, bg=self.get_color('background'))
        title_frame.pack(fill=tk.X, pady=(0, 20))

        title_label = tk.Label(title_frame,
                              text="🛡️ Centro de Control Bot",
                              font=("Segoe UI", 16, "bold"),
                              bg=self.get_color('background'),
                              fg=self.get_color('text_primary'))
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(title_frame,
                                 text="Seleccione el tipo de escaneo que desea realizar",
                                 font=("Segoe UI", 10),
                                 bg=self.get_color('background'),
                                 fg=self.get_color('text_secondary'))
        subtitle_label.pack(anchor="w", pady=(5, 0))

        # Frame para los botones de escaneo en la parte superior con estilo moderno
        self.button_frame = tk.Frame(self.frame, bg=self.get_color('background'))
        self.button_frame.pack(fill=tk.X, pady=(0, 15))

        # Primera fila de botones con estilo moderno
        button_row1 = tk.Frame(self.button_frame, bg=self.get_color('background'))
        button_row1.pack(fill=tk.X, pady=(0, 10))

        self.btn_scan_file = tk.Button(
            button_row1,
            text="📄 Escanear Archivo",
            command=self.scan_file,
            bg=self.get_color('primary'),
            fg="white",
            activebackground=self.get_color('primary_dark'),
            activeforeground="white",
            font=self.button_font_bold,
            relief=tk.FLAT,
            borderwidth=0,
            padx=20,
            pady=12,
            cursor="hand2"
        )
        self.btn_scan_file.pack(side=tk.LEFT, padx=(0, 10), expand=True, fill=tk.X)
        self.add_hover_effect(self.btn_scan_file, self.get_color('primary_dark'), self.get_color('primary'))
        self.add_click_effect(self.btn_scan_file)

        self.btn_scan_dir = tk.Button(
            button_row1,
            text="📁 Escanear Directorio",
            command=self.scan_directory,
            bg=self.get_color('primary'),
            fg="white",
            activebackground=self.get_color('primary_dark'),
            activeforeground="white",
            font=self.button_font_bold,
            relief=tk.FLAT,
            borderwidth=0,
            padx=20,
            pady=12,
            cursor="hand2"
        )
        self.btn_scan_dir.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.add_hover_effect(self.btn_scan_dir, self.get_color('primary_dark'), self.get_color('primary'))
        self.add_click_effect(self.btn_scan_dir)

        # Segunda fila de botones
        button_row2 = tk.Frame(self.button_frame, bg=self.get_color('background'))
        button_row2.pack(fill=tk.X)

        self.btn_quick_scan = tk.Button(
            button_row2,
            text="⚡ Escaneo Rápido",
            command=self.quick_scan,
            bg=self.get_color('warning'),
            fg="white",
            activebackground=self.get_color('warning'),
            activeforeground="white",
            font=self.button_font_bold,
            relief=tk.FLAT,
            borderwidth=0,
            padx=20,
            pady=12,
            cursor="hand2"
        )
        self.btn_quick_scan.pack(side=tk.LEFT, padx=(0, 10), expand=True, fill=tk.X)
        self.add_hover_effect(self.btn_quick_scan, "#e67e22", self.get_color('warning'))
        self.add_click_effect(self.btn_quick_scan)

        self.btn_full_scan = tk.Button(
            button_row2,
            text="🌍 Escaneo Completo",
            command=self.full_scan,
            bg=self.get_color('info'),
            fg="white",
            activebackground=self.get_color('info'),
            activeforeground="white",
            font=self.button_font_bold,
            relief=tk.FLAT,
            borderwidth=0,
            padx=20,
            pady=12,
            cursor="hand2"
        )
        self.btn_full_scan.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.add_hover_effect(self.btn_full_scan, "#0891b2", self.get_color('info'))
        self.add_click_effect(self.btn_full_scan)

        # Frame para los botones de control con separación visual
        control_section = tk.Frame(self.frame, bg=self.get_color('background'))
        control_section.pack(fill=tk.X, pady=(20, 15))

        control_title = tk.Label(control_section,
                               text="Control de Escaneo",
                               font=("Segoe UI", 12, "bold"),
                               bg=self.get_color('background'),
                               fg=self.get_color('text_primary'))
        control_title.pack(anchor="w", pady=(0, 10))

        self.control_frame = tk.Frame(control_section, bg=self.get_color('background'))
        self.control_frame.pack(fill=tk.X)

        # Botón verde para iniciar escaneo con estilo moderno
        self.btn_start_scan = tk.Button(
            self.control_frame,
            text="▶️ Iniciar Escaneo",
            command=self.start_scan,
            bg=self.get_color('success'),
            fg="white",
            activebackground=self.get_color('success_hover'),
            activeforeground="white",
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=15,
            cursor="hand2",
            state="disabled"
        )
        self.btn_start_scan.pack(side=tk.LEFT, padx=(0, 15), expand=True, fill=tk.X)
        self.add_hover_effect(self.btn_start_scan, self.get_color('success_hover'), self.get_color('success'))
        self.add_click_effect(self.btn_start_scan)

        # Botón rojo para detener escaneo con estilo moderno
        self.btn_stop_scan = tk.Button(
            self.control_frame,
            text="⏹️ Detener Escaneo",
            command=self.stop_scan,
            bg=self.get_color('danger'),
            fg="white",
            activebackground=self.get_color('danger_hover'),
            activeforeground="white",
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            borderwidth=0,
            padx=25,
            pady=15,
            cursor="hand2",
            state="disabled"
        )
        self.btn_stop_scan.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.add_hover_effect(self.btn_stop_scan, self.get_color('danger_hover'), self.get_color('danger'))
        self.add_click_effect(self.btn_stop_scan)

        # Sección de progreso con estilo moderno
        progress_section = tk.Frame(self.frame, bg=self.get_color('background'))
        progress_section.pack(fill=tk.X, pady=(15, 20))

        progress_title = tk.Label(progress_section,
                                text="Progreso del Escaneo",
                                font=("Segoe UI", 12, "bold"),
                                bg=self.get_color('background'),
                                fg=self.get_color('text_primary'))
        progress_title.pack(anchor="w", pady=(0, 8))

        # Barra de progreso moderna
        self.progress = ttk.Progressbar(progress_section,
                                      orient="horizontal",
                                      mode="determinate",
                                      style="Modern.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, pady=(0, 5))

        # Etiqueta de estado
        self.status_label = tk.Label(progress_section,
                                   text="Listo para escanear",
                                   font=("Segoe UI", 9),
                                   bg=self.get_color('background'),
                                   fg=self.get_color('text_secondary'))
        self.status_label.pack(anchor="w")

        # Sección de resultados con estilo moderno
        results_section = tk.Frame(self.frame, bg=self.get_color('background'))
        results_section.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        results_title = tk.Label(results_section,
                               text="📋 Resultados del Escaneo",
                               font=("Segoe UI", 12, "bold"),
                               bg=self.get_color('background'),
                               fg=self.get_color('text_primary'))
        results_title.pack(anchor="w", pady=(0, 10))

        # Frame para los resultados con borde moderno
        self.result_frame = tk.Frame(results_section,
                                   bg=self.get_color('surface'),
                                   relief=tk.FLAT,
                                   bd=1)
        self.result_frame.pack(fill=tk.BOTH, expand=True)

        # Área de texto para resultados con estilo moderno
        self.txt_result = tk.Text(self.result_frame,
                                height=12,
                                wrap="word",
                                bg=self.get_color('surface'),
                                fg=self.get_color('text_primary'),
                                font=("Consolas", 9),
                                relief=tk.FLAT,
                                borderwidth=0,
                                padx=15,
                                pady=10,
                                selectbackground=self.get_color('primary_light'),
                                selectforeground="white")
        self.txt_result.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar moderna
        self.scroll = ttk.Scrollbar(self.result_frame, orient="vertical", command=self.txt_result.yview)
        self.scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_result.configure(yscrollcommand=self.scroll.set)

        # Conexión a la base de datos para el hilo principal
        try:
            self.db_connection = sqlite3.connect(resource_path("virus_data.db"), check_same_thread=False) # Re-added connection for main thread
            self.create_tables() # This needs self.db_connection
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"No se pudo conectar a la base de datos: {e}")
            self.db_connection = None

        # Variable para almacenar la lista de archivos a escanear
        self.file_list = []
        self.scan_stopped = False
        self.collection_cancelled = False

        # Generar una clave de cifrado (esto debe hacerse una vez y guardarse de forma segura)
        self.LOG_KEY = Fernet.generate_key()
        self.cipher = Fernet(self.LOG_KEY)

    def setup_modern_styles(self):
        """Configurar estilos modernos para ttk widgets"""
        # Configurar el tema base
        self.style.theme_use('clam')

        # Estilos para botones
        self.style.configure('Modern.TButton',
                           font=('Segoe UI', 10, 'normal'),
                           borderwidth=1,
                           focuscolor='none',
                           relief='flat')

        self.style.map('Modern.TButton',
                      background=[('active', self.get_color('primary_light')),
                                ('pressed', self.get_color('primary_dark'))])

        # Estilos para frames
        self.style.configure('Modern.TFrame',
                           borderwidth=0,
                           relief='flat')

        # Estilos para labels
        self.style.configure('Modern.TLabel',
                           font=('Segoe UI', 10),
                           borderwidth=0)

        # Estilos para progressbar
        self.style.configure('Modern.Horizontal.TProgressbar',
                           background=self.get_color('primary'),
                           troughcolor=self.get_color('surface_alt'),
                           borderwidth=0,
                           lightcolor=self.get_color('primary'),
                           darkcolor=self.get_color('primary'))

        # Estilos para treeview
        self.style.configure('Modern.Treeview',
                           background=self.get_color('surface'),
                           foreground=self.get_color('text_primary'),
                           fieldbackground=self.get_color('surface'),
                           borderwidth=1,
                           relief='solid')

        self.style.configure('Modern.Treeview.Heading',
                           background=self.get_color('surface_alt'),
                           foreground=self.get_color('text_primary'),
                           font=('Segoe UI', 10, 'bold'),
                           borderwidth=1,
                           relief='flat')

        self.style.map('Modern.Treeview',
                      background=[('selected', self.get_color('primary_light'))],
                      foreground=[('selected', 'white')])

    def get_color(self, color_name):
        """Obtener color del tema actual"""
        return self.colors[self.current_theme].get(color_name, '#000000')

    def create_tables(self):
        # Crear tablas necesarias en la base de datos con manejo de errores
        try:
            if self.db_connection is None:
                return
            cursor = self.db_connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT,
                    is_infected INTEGER,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.db_connection.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"No se pudieron crear las tablas: {e}")

    def log_scan_result(self, file_path, is_infected):
        # Registrar el resultado del escaneo en la base de datos con manejo de errores
        db_conn = None # Initialize db_conn to None
        try:
            db_conn = sqlite3.connect(resource_path("virus_data.db")) # Create a new connection
            cursor = db_conn.cursor()
            cursor.execute("INSERT INTO scan_history (file_path, is_infected) VALUES (?, ?)", (file_path, is_infected))
            db_conn.commit()
        except sqlite3.Error as e:
            print(f"Error al registrar el resultado del escaneo (log_scan_result): {e}") # Added context to print
        finally:
            if db_conn:
                db_conn.close() # Close the connection in the finally block

    def show_scan_history(self):
        """Mostrar el historial de escaneos con diseño moderno"""
        try:
            history_window = tk.Toplevel(self.root)
            history_window.title("📊 Historial de Escaneos - Bot Python")
            history_window.geometry("900x600")
            history_window.minsize(700, 500)
            history_window.configure(bg=self.get_color('background'))

            # Configurar icono si existe
            try:
                history_window.iconphoto(False, tk.PhotoImage(file=resource_path("img/icono.png")))
            except:
                pass

            # Frame principal con padding
            main_frame = tk.Frame(history_window, bg=self.get_color('background'))
            main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

            # Título de la ventana
            title_frame = tk.Frame(main_frame, bg=self.get_color('background'))
            title_frame.pack(fill=tk.X, pady=(0, 20))

            title_label = tk.Label(title_frame,
                                 text="📊 Historial de Escaneos",
                                 font=("Segoe UI", 18, "bold"),
                                 bg=self.get_color('background'),
                                 fg=self.get_color('text_primary'))
            title_label.pack(anchor="w")

            subtitle_label = tk.Label(title_frame,
                                    text="Registro completo de todos los escaneos realizados",
                                    font=("Segoe UI", 10),
                                    bg=self.get_color('background'),
                                    fg=self.get_color('text_secondary'))
            subtitle_label.pack(anchor="w", pady=(5, 0))

            # Frame para estadísticas rápidas
            stats_frame = tk.Frame(main_frame, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
            stats_frame.pack(fill=tk.X, pady=(0, 20))

            # Obtener estadísticas
            if self.db_connection is None:
                messagebox.showerror("Error", "No hay conexión a la base de datos")
                history_window.destroy()
                return
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            total_scans = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE is_infected = 1")
            infected_count = cursor.fetchone()[0]

            safe_count = total_scans - infected_count

            # Mostrar estadísticas
            stats_title = tk.Label(stats_frame,
                                 text="📈 Estadísticas Rápidas",
                                 font=("Segoe UI", 12, "bold"),
                                 bg=self.get_color('surface'),
                                 fg=self.get_color('text_primary'))
            stats_title.pack(anchor="w", padx=15, pady=(15, 10))

            stats_row = tk.Frame(stats_frame, bg=self.get_color('surface'))
            stats_row.pack(fill=tk.X, padx=15, pady=(0, 15))

            # Total
            total_frame = tk.Frame(stats_row, bg=self.get_color('primary'), relief=tk.FLAT)
            total_frame.pack(side=tk.LEFT, padx=(0, 10), pady=5, fill=tk.X, expand=True)
            tk.Label(total_frame, text=str(total_scans), font=("Segoe UI", 16, "bold"),
                    bg=self.get_color('primary'), fg="white").pack(pady=(10, 5))
            tk.Label(total_frame, text="Total Escaneos", font=("Segoe UI", 9),
                    bg=self.get_color('primary'), fg="white").pack(pady=(0, 10))

            # Seguros
            safe_frame = tk.Frame(stats_row, bg=self.get_color('success'), relief=tk.FLAT)
            safe_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
            tk.Label(safe_frame, text=str(safe_count), font=("Segoe UI", 16, "bold"),
                    bg=self.get_color('success'), fg="white").pack(pady=(10, 5))
            tk.Label(safe_frame, text="Archivos Seguros", font=("Segoe UI", 9),
                    bg=self.get_color('success'), fg="white").pack(pady=(0, 10))

            # Infectados
            infected_frame = tk.Frame(stats_row, bg=self.get_color('danger'), relief=tk.FLAT)
            infected_frame.pack(side=tk.LEFT, padx=(10, 0), pady=5, fill=tk.X, expand=True)
            tk.Label(infected_frame, text=str(infected_count), font=("Segoe UI", 16, "bold"),
                    bg=self.get_color('danger'), fg="white").pack(pady=(10, 5))
            tk.Label(infected_frame, text="Archivos Infectados", font=("Segoe UI", 9),
                    bg=self.get_color('danger'), fg="white").pack(pady=(0, 10))

            # Frame para la tabla con título
            table_frame = tk.Frame(main_frame, bg=self.get_color('background'))
            table_frame.pack(fill=tk.BOTH, expand=True)

            table_title = tk.Label(table_frame,
                                 text="📋 Registro Detallado",
                                 font=("Segoe UI", 12, "bold"),
                                 bg=self.get_color('background'),
                                 fg=self.get_color('text_primary'))
            table_title.pack(anchor="w", pady=(0, 10))

            # Frame para el TreeView con scrollbars
            tree_frame = tk.Frame(table_frame, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
            tree_frame.pack(fill=tk.BOTH, expand=True)

            # TreeView moderno
            tree = ttk.Treeview(tree_frame,
                              columns=("Archivo", "Estado", "Fecha"),
                              show="headings",
                              style="Modern.Treeview")

            # Configurar columnas
            tree.heading("Archivo", text="📄 Archivo")
            tree.heading("Estado", text="🛡️ Estado")
            tree.heading("Fecha", text="📅 Fecha")

            tree.column("Archivo", width=400, minwidth=200)
            tree.column("Estado", width=120, minwidth=80, anchor="center")
            tree.column("Fecha", width=180, minwidth=120, anchor="center")

            # Scrollbars
            v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
            h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

            # Posicionar elementos
            tree.grid(row=0, column=0, sticky="nsew")
            v_scrollbar.grid(row=0, column=1, sticky="ns")
            h_scrollbar.grid(row=1, column=0, sticky="ew")

            tree_frame.grid_rowconfigure(0, weight=1)
            tree_frame.grid_columnconfigure(0, weight=1)

            # Cargar datos
            cursor.execute("SELECT file_path, is_infected, scan_date FROM scan_history ORDER BY scan_date DESC")
            for row in cursor.fetchall():
                status = "🔴 Infectado" if row[1] else "🟢 Seguro"
                # Formatear la fecha
                date_str = row[2] if row[2] else "N/A"
                tree.insert("", tk.END, values=(row[0], status, date_str))

            # Frame para botones de acción
            button_frame = tk.Frame(main_frame, bg=self.get_color('background'))
            button_frame.pack(fill=tk.X, pady=(20, 0))

            # Botón para actualizar
            refresh_btn = tk.Button(button_frame,
                                  text="🔄 Actualizar",
                                  command=lambda: self.refresh_history_window(tree),
                                  bg=self.get_color('info'),
                                  fg="white",
                                  activebackground=self.get_color('info'),
                                  font=("Segoe UI", 10, "bold"),
                                  relief=tk.FLAT,
                                  borderwidth=0,
                                  padx=20,
                                  pady=10,
                                  cursor="hand2")
            refresh_btn.pack(side=tk.LEFT, padx=(0, 10))

            # Botón para cerrar
            close_btn = tk.Button(button_frame,
                                text="❌ Cerrar",
                                command=history_window.destroy,
                                bg=self.get_color('secondary'),
                                fg="white",
                                activebackground=self.get_color('secondary'),
                                font=("Segoe UI", 10, "bold"),
                                relief=tk.FLAT,
                                borderwidth=0,
                                padx=20,
                                pady=10,
                                cursor="hand2")
            close_btn.pack(side=tk.RIGHT)

        except sqlite3.Error as e:
            messagebox.showerror("Error", f"No se pudo cargar el historial de escaneos: {e}")

    def refresh_history_window(self, tree):
        """Actualizar los datos del historial"""
        try:
            if self.db_connection is None:
                messagebox.showerror("Error", "No hay conexión a la base de datos")
                return
            # Limpiar el tree
            for item in tree.get_children():
                tree.delete(item)

            # Recargar datos
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT file_path, is_infected, scan_date FROM scan_history ORDER BY scan_date DESC")
            for row in cursor.fetchall():
                status = "🔴 Infectado" if row[1] else "🟢 Seguro"
                date_str = row[2] if row[2] else "N/A"
                tree.insert("", tk.END, values=(row[0], status, date_str))
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"No se pudo actualizar el historial: {e}")

    def show_dashboard(self):
        """Crear una ventana de dashboard moderna con estadísticas visuales"""
        dashboard_window = tk.Toplevel(self.root)
        dashboard_window.title("📈 Dashboard Estadístico - Bot Python")
        dashboard_window.geometry("1000x700")
        dashboard_window.minsize(800, 600)
        dashboard_window.configure(bg=self.get_color('background'))

        # Configurar icono si existe
        try:
            dashboard_window.iconphoto(False, tk.PhotoImage(file=resource_path("img/icono.png")))
        except:
            pass

        # Obtener datos de la base de datos
        if self.db_connection is None:
            messagebox.showerror("Error", "No hay conexión a la base de datos")
            dashboard_window.destroy()
            return
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        total_scanned = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE is_infected = 1")
        total_infected = cursor.fetchone()[0]

        # Evitar división por cero
        if total_scanned == 0:
            # Ventana de sin datos con mejor diseño
            no_data_frame = tk.Frame(dashboard_window, bg=self.get_color('background'))
            no_data_frame.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)

            icon_label = tk.Label(no_data_frame,
                                text="📊",
                                font=("Segoe UI", 48),
                                bg=self.get_color('background'),
                                fg=self.get_color('text_secondary'))
            icon_label.pack(pady=(0, 20))

            title_label = tk.Label(no_data_frame,
                                 text="Sin Datos Disponibles",
                                 font=("Segoe UI", 18, "bold"),
                                 bg=self.get_color('background'),
                                 fg=self.get_color('text_primary'))
            title_label.pack(pady=(0, 10))

            subtitle_label = tk.Label(no_data_frame,
                                    text="Realice algunos escaneos para ver estadísticas aquí",
                                    font=("Segoe UI", 12),
                                    bg=self.get_color('background'),
                                    fg=self.get_color('text_secondary'))
            subtitle_label.pack(pady=(0, 30))

            close_btn = tk.Button(no_data_frame,
                                text="Cerrar",
                                command=dashboard_window.destroy,
                                bg=self.get_color('primary'),
                                fg="white",
                                font=("Segoe UI", 11, "bold"),
                                relief=tk.FLAT,
                                borderwidth=0,
                                padx=30,
                                pady=12,
                                cursor="hand2")
            close_btn.pack()
            return

        # Frame principal con padding
        main_frame = tk.Frame(dashboard_window, bg=self.get_color('background'))
        main_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        # Título del dashboard
        title_frame = tk.Frame(main_frame, bg=self.get_color('background'))
        title_frame.pack(fill=tk.X, pady=(0, 25))

        title_label = tk.Label(title_frame,
                             text="📈 Dashboard Estadístico",
                             font=("Segoe UI", 20, "bold"),
                             bg=self.get_color('background'),
                             fg=self.get_color('text_primary'))
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(title_frame,
                                text="Análisis visual de los resultados de escaneo",
                                font=("Segoe UI", 11),
                                bg=self.get_color('background'),
                                fg=self.get_color('text_secondary'))
        subtitle_label.pack(anchor="w", pady=(5, 0))

        # Datos para el gráfico
        safe_count = total_scanned - total_infected
        labels = ['Archivos Seguros', 'Archivos Infectados']
        values = [safe_count, total_infected]
        colors = [self.get_color('success'), self.get_color('danger')]

        # Frame para estadísticas principales
        stats_frame = tk.Frame(main_frame, bg=self.get_color('background'))
        stats_frame.pack(fill=tk.X, pady=(0, 25))

        # Tarjetas de estadísticas
        stats_row = tk.Frame(stats_frame, bg=self.get_color('background'))
        stats_row.pack(fill=tk.X)

        # Total
        total_card = tk.Frame(stats_row, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
        total_card.pack(side=tk.LEFT, padx=(0, 15), pady=10, fill=tk.X, expand=True)
        tk.Label(total_card, text="📊", font=("Segoe UI", 24),
                bg=self.get_color('surface'), fg=self.get_color('primary')).pack(pady=(15, 5))
        tk.Label(total_card, text=str(total_scanned), font=("Segoe UI", 20, "bold"),
                bg=self.get_color('surface'), fg=self.get_color('text_primary')).pack()
        tk.Label(total_card, text="Total Escaneados", font=("Segoe UI", 10),
                bg=self.get_color('surface'), fg=self.get_color('text_secondary')).pack(pady=(0, 15))

        # Seguros
        safe_card = tk.Frame(stats_row, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
        safe_card.pack(side=tk.LEFT, padx=7, pady=10, fill=tk.X, expand=True)
        tk.Label(safe_card, text="🟢", font=("Segoe UI", 24),
                bg=self.get_color('surface'), fg=self.get_color('success')).pack(pady=(15, 5))
        tk.Label(safe_card, text=str(safe_count), font=("Segoe UI", 20, "bold"),
                bg=self.get_color('surface'), fg=self.get_color('text_primary')).pack()
        tk.Label(safe_card, text="Archivos Seguros", font=("Segoe UI", 10),
                bg=self.get_color('surface'), fg=self.get_color('text_secondary')).pack(pady=(0, 15))

        # Infectados
        infected_card = tk.Frame(stats_row, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
        infected_card.pack(side=tk.LEFT, padx=(15, 0), pady=10, fill=tk.X, expand=True)
        tk.Label(infected_card, text="🔴", font=("Segoe UI", 24),
                bg=self.get_color('surface'), fg=self.get_color('danger')).pack(pady=(15, 5))
        tk.Label(infected_card, text=str(total_infected), font=("Segoe UI", 20, "bold"),
                bg=self.get_color('surface'), fg=self.get_color('text_primary')).pack()
        tk.Label(infected_card, text="Archivos Infectados", font=("Segoe UI", 10),
                bg=self.get_color('surface'), fg=self.get_color('text_secondary')).pack(pady=(0, 15))

        # Frame para controles del gráfico
        control_frame = tk.Frame(main_frame, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
        control_frame.pack(fill=tk.X, pady=(0, 20))

        control_title = tk.Label(control_frame,
                               text="🎨 Opciones de Visualización",
                               font=("Segoe UI", 12, "bold"),
                               bg=self.get_color('surface'),
                               fg=self.get_color('text_primary'))
        control_title.pack(anchor="w", padx=20, pady=(15, 10))

        # Menú desplegable para seleccionar el tipo de gráfico
        chart_controls = tk.Frame(control_frame, bg=self.get_color('surface'))
        chart_controls.pack(fill=tk.X, padx=20, pady=(0, 15))

        chart_type_var = tk.StringVar(value="🃏 Tarjetas Visuales")
        chart_types = [
            "🃏 Tarjetas Visuales",
            "🔥 Mapa de Intensidad",
            "🎯 Gráfico de Dona"
        ]

        tk.Label(chart_controls,
                text="Tipo de gráfico:",
                font=("Segoe UI", 10, "bold"),
                bg=self.get_color('surface'),
                fg=self.get_color('text_primary')).pack(side=tk.LEFT, padx=(0, 10))

        chart_type_menu = ttk.OptionMenu(chart_controls, chart_type_var, chart_types[0], *chart_types)
        chart_type_menu.pack(side=tk.LEFT)

        # Contenedor para el gráfico con estilo moderno
        chart_section = tk.Frame(main_frame, bg=self.get_color('background'))
        chart_section.pack(fill=tk.BOTH, expand=True)

        chart_title = tk.Label(chart_section,
                             text="📊 Visualización de Datos",
                             font=("Segoe UI", 14, "bold"),
                             bg=self.get_color('background'),
                             fg=self.get_color('text_primary'))
        chart_title.pack(anchor="w", pady=(0, 15))

        chart_frame = tk.Frame(chart_section, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
        chart_frame.pack(fill=tk.BOTH, expand=True)

        def draw_chart():
            """Dibujar el gráfico según el tipo seleccionado usando solo tkinter"""
            try:
                # Limpiar el marco del gráfico
                for widget in chart_frame.winfo_children():
                    widget.destroy()

                # Verificar que tenemos datos válidos
                if not values or not labels:
                    error_label = tk.Label(chart_frame,
                                         text="❌ Error: No hay datos para mostrar",
                                         font=("Segoe UI", 12, "bold"),
                                         bg=self.get_color('surface'),
                                         fg=self.get_color('danger'))
                    error_label.pack(expand=True)
                    return

                chart_type = chart_type_var.get()
                
                # Usar solo gráficos alternativos con tkinter
                if chart_type == "🃏 Tarjetas Visuales":
                    # Mostrar información en formato de tarjetas
                    self.draw_card_chart(chart_frame, values, labels, chart_type)
                elif chart_type == "🔥 Mapa de Intensidad":
                    # Usar mapa de calor alternativo
                    self.draw_heatmap_chart(chart_frame, values, labels)
                elif chart_type == "🎯 Gráfico de Dona":
                    # Usar gráfico circular tipo dona
                    self.draw_donut_chart(chart_frame, values, labels)
                else:
                    # Fallback por defecto
                    self.draw_card_chart(chart_frame, values, labels, chart_type)

            except Exception as e:
                # Mostrar error si algo falla
                error_label = tk.Label(chart_frame,
                                     text=f"❌ Error al crear gráfico: {str(e)[:100]}...",
                                     font=("Segoe UI", 10),
                                     bg=self.get_color('surface'),
                                     fg=self.get_color('danger'),
                                     wraplength=400)
                error_label.pack(expand=True, padx=20, pady=20)
                print(f"Error en draw_chart: {e}")  # Para debugging

        # Dibujar el gráfico inicial automáticamente
        chart_type_var.trace_add("write", lambda *args: draw_chart())
        draw_chart()

        # Frame para botones de acción
        button_frame = tk.Frame(main_frame, bg=self.get_color('background'))
        button_frame.pack(fill=tk.X, pady=(20, 0))

        # Botón para actualizar datos
        refresh_btn = tk.Button(button_frame,
                              text="🔄 Actualizar Datos",
                              command=lambda: [dashboard_window.destroy(), self.show_dashboard()],
                              bg=self.get_color('info'),
                              fg="white",
                              activebackground=self.get_color('info'),
                              font=("Segoe UI", 10, "bold"),
                              relief=tk.FLAT,
                              borderwidth=0,
                              padx=20,
                              pady=12,
                              cursor="hand2")
        refresh_btn.pack(side=tk.LEFT, padx=(0, 15))

        # Botón para cerrar el Dashboard
        close_btn = tk.Button(button_frame,
                            text="❌ Cerrar Dashboard",
                            command=dashboard_window.destroy,
                            bg=self.get_color('secondary'),
                            fg="white",
                            activebackground=self.get_color('secondary'),
                            font=("Segoe UI", 10, "bold"),
                            relief=tk.FLAT,
                            borderwidth=0,
                            padx=20,
                            pady=12,
                            cursor="hand2")
        close_btn.pack(side=tk.RIGHT)

    def set_theme(self, theme):
        """Cambiar entre tema claro y oscuro con colores modernos"""
        if theme in self.colors:
            self.current_theme = theme

            # Actualizar colores de ttk widgets
            self.style.configure("TButton",
                               font=("Segoe UI", 10),
                               background=self.get_color('surface'),
                               foreground=self.get_color('text_primary'),
                               borderwidth=1,
                               relief='flat')

            self.style.configure("TLabel",
                               font=("Segoe UI", 10),
                               background=self.get_color('background'),
                               foreground=self.get_color('text_primary'))

            self.style.configure("TFrame",
                               background=self.get_color('background'),
                               borderwidth=0)

            self.style.configure("TEntry",
                               font=("Segoe UI", 10),
                               fieldbackground=self.get_color('surface'),
                               foreground=self.get_color('text_primary'),
                               borderwidth=1,
                               relief='solid')

            # Actualizar progressbar
            self.style.configure("TProgressbar",
                               background=self.get_color('primary'),
                               troughcolor=self.get_color('surface_alt'),
                               borderwidth=0)

            # Actualizar colores de la ventana principal
            self.root.configure(bg=self.get_color('background'))

            # Actualizar colores del menú lateral si existe
            if hasattr(self, 'menu_frame'):
                self.menu_frame.configure(bg=self.get_color('surface'))
                self.update_menu_colors()

            # Actualizar colores de botones principales si existen
            if hasattr(self, 'button_frame'):
                self.update_main_button_colors()

            # Actualizar área de resultados si existe
            if hasattr(self, 'txt_result'):
                self.update_result_area_colors()

            # Actualizar elementos adicionales de la interfaz
            self.update_additional_interface_colors()

    def update_menu_colors(self):
        """Actualizar colores del menú lateral"""
        self.menu_frame.configure(bg=self.get_color('surface'))

        # Actualizar colores de botones del menú
        for menu_name, button in self.menu_buttons.items():
            if self.active_menu == menu_name:
                button.configure(bg=self.get_color('primary_light'),
                               fg='white')
            else:
                button.configure(bg=self.get_color('surface'),
                               fg=self.get_color('text_primary'),
                               activebackground=self.get_color('primary_light'))

        # Actualizar submenús
        for submenu_frame in self.submenu_frames.values():
            submenu_frame.configure(bg=self.get_color('surface_alt'))
            for child in submenu_frame.winfo_children():
                if isinstance(child, tk.Button):
                    child.configure(bg=self.get_color('surface_alt'),
                                  fg=self.get_color('text_secondary'))

    def update_main_button_colors(self):
        """Actualizar colores de botones principales"""
        self.button_frame.configure(bg=self.get_color('background'))

        # Actualizar botones de escaneo
        if hasattr(self, 'btn_scan_file'):
            self.btn_scan_file.configure(bg=self.get_color('primary'),
                                       activebackground=self.get_color('primary_dark'))
        if hasattr(self, 'btn_scan_dir'):
            self.btn_scan_dir.configure(bg=self.get_color('primary'),
                                      activebackground=self.get_color('primary_dark'))
        if hasattr(self, 'btn_quick_scan'):
            self.btn_quick_scan.configure(bg=self.get_color('warning'))
        if hasattr(self, 'btn_full_scan'):
            self.btn_full_scan.configure(bg=self.get_color('info'))

        # Actualizar botones de control
        if hasattr(self, 'btn_start_scan'):
            self.btn_start_scan.configure(bg=self.get_color('success'),
                                        activebackground=self.get_color('success_hover'))
        if hasattr(self, 'btn_stop_scan'):
            self.btn_stop_scan.configure(bg=self.get_color('danger'),
                                       activebackground=self.get_color('danger_hover'))

    def update_result_area_colors(self):
        """Actualizar colores del área de resultados"""
        if hasattr(self, 'txt_result'):
            self.txt_result.configure(bg=self.get_color('surface'),
                                    fg=self.get_color('text_primary'),
                                    selectbackground=self.get_color('primary_light'))
        if hasattr(self, 'result_frame'):
            self.result_frame.configure(bg=self.get_color('surface'))

    def update_additional_interface_colors(self):
        """Actualizar colores de elementos adicionales de la interfaz"""
        # Actualizar frames principales (solo tk.Frame, no ttk.Frame)
        # self.frame es ttk.Frame, no necesita actualización de bg
        # content_frame es ttk.Frame, por lo que no necesita configuración de bg

        # Actualizar frames de título y subtítulo (solo tk.Frame dentro de ttk.Frame)
        if hasattr(self, 'frame'):
            for widget in self.frame.winfo_children():
                if isinstance(widget, tk.Frame):
                    widget.configure(bg=self.get_color('background'))
                    # Actualizar labels dentro de los frames
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Label):
                            child.configure(bg=self.get_color('background'))
                            # Determinar si es título principal o secundario
                            font = child.cget('font')
                            if isinstance(font, tuple) and len(font) >= 3 and 'bold' in font:
                                child.configure(fg=self.get_color('text_primary'))
                            else:
                                child.configure(fg=self.get_color('text_secondary'))

        # Actualizar separadores
        if hasattr(self, 'menu_frame'):
            for widget in self.menu_frame.winfo_children():
                if isinstance(widget, tk.Frame) and widget.winfo_height() <= 2:
                    widget.configure(bg=self.get_color('border'))

        # Actualizar logo frame si existe
        if hasattr(self, 'logo_img') and hasattr(self, 'menu_frame'):
            for widget in self.menu_frame.winfo_children():
                if isinstance(widget, tk.Frame):
                    widget.configure(bg=self.get_color('surface'))
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Label) and child.cget('image'):
                            child.configure(bg=self.get_color('surface'))

        # Actualizar shadow frame
        if hasattr(self, 'main_frame'):
            for widget in self.main_frame.winfo_children():
                if isinstance(widget, tk.Frame) and widget.winfo_width() <= 3:
                    widget.configure(bg=self.get_color('border'))

        # Actualizar frames de control
        if hasattr(self, 'control_frame'):
            self.control_frame.configure(bg=self.get_color('background'))
            for child in self.control_frame.winfo_children():
                if isinstance(child, tk.Frame):
                    child.configure(bg=self.get_color('background'))

    def show_custom_dialog(self, title, message, dialog_type="info", buttons=None, return_dialog=False, callback=None):
        """Mostrar un diálogo personalizado con estilo moderno"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("450x300")
        dialog.resizable(False, False)
        dialog.configure(bg=self.get_color('background'))
        dialog.transient(self.root)
        dialog.grab_set()

        # Centrar el diálogo
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        # Frame principal
        main_frame = tk.Frame(dialog, bg=self.get_color('background'))
        main_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        # Icono según el tipo
        icon_map = {
            "info": "ℹ️",
            "warning": "⚠️",
            "error": "❌",
            "success": "✅",
            "question": "❓"
        }

        color_map = {
            "info": self.get_color('info'),
            "warning": self.get_color('warning'),
            "error": self.get_color('danger'),
            "success": self.get_color('success'),
            "question": self.get_color('primary')
        }

        # Icono
        icon_label = tk.Label(main_frame,
                            text=icon_map.get(dialog_type, "ℹ️"),
                            font=("Segoe UI", 32),
                            bg=self.get_color('background'),
                            fg=color_map.get(dialog_type, self.get_color('info')))
        icon_label.pack(pady=(0, 15))

        # Título
        title_label = tk.Label(main_frame,
                             text=title,
                             font=("Segoe UI", 14, "bold"),
                             bg=self.get_color('background'),
                             fg=self.get_color('text_primary'))
        title_label.pack(pady=(0, 10))

        # Mensaje
        message_label = tk.Label(main_frame,
                               text=message,
                               font=("Segoe UI", 10),
                               bg=self.get_color('background'),
                               fg=self.get_color('text_secondary'),
                               wraplength=400,
                               justify="center")
        message_label.pack(pady=(0, 20))

        # Frame para botones
        button_frame = tk.Frame(main_frame, bg=self.get_color('background'))
        button_frame.pack(fill=tk.X)

        result = [None]  # Para almacenar el resultado

        if buttons is None:
            if callback:
                buttons = ["Sí", "No"]
            else:
                buttons = ["OK"]

        def handle_button_click(button_index):
            result[0] = button_index
            dialog.destroy()
            # Si hay callback y se presionó el primer botón (Sí/Aceptar)
            if callback and button_index == 0:
                callback()

        for i, button_text in enumerate(buttons):
            btn_color = self.get_color('primary')
            if button_text.lower() in ['cancel', 'cancelar', 'no']:
                btn_color = self.get_color('secondary')
            elif button_text.lower() in ['delete', 'eliminar']:
                btn_color = self.get_color('danger')
            elif button_text.lower() in ['cerrar', 'close']:
                btn_color = self.get_color('secondary')

            btn = tk.Button(button_frame,
                          text=button_text,
                          command=lambda r=i: handle_button_click(r),
                          bg=btn_color,
                          fg="white",
                          activebackground=btn_color,
                          font=("Segoe UI", 10, "bold"),
                          relief=tk.FLAT,
                          borderwidth=0,
                          padx=20,
                          pady=10,
                          cursor="hand2")

            if len(buttons) == 1:
                btn.pack(pady=5)
            else:
                side = tk.LEFT if i == 0 else tk.RIGHT
                padx = (0, 10) if i == 0 else (10, 0)
                btn.pack(side=side, padx=padx, pady=5, expand=True, fill=tk.X)

        # Si se solicita retornar el diálogo, no esperar
        if return_dialog:
            return dialog

        # Si hay callback, no bloquear la ejecución
        if callback:
            return dialog

        # Esperar a que se cierre el diálogo
        dialog.wait_window()
        return result[0]

    def show_scan_completed_dialog(self, total_files, infected_count, infected_files=None):
        """Mostrar diálogo de escaneo completado con opciones avanzadas"""
        dialog = tk.Toplevel(self.root)
        dialog.title("✅ Escaneo Completado - Bot Python")
        dialog.geometry("500x400")
        dialog.resizable(False, False)
        dialog.configure(bg=self.get_color('background'))
        dialog.transient(self.root)
        dialog.grab_set()

        # Centrar el diálogo
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        # Frame principal
        main_frame = tk.Frame(dialog, bg=self.get_color('background'))
        main_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        # Icono de éxito
        icon_label = tk.Label(main_frame,
                            text="✅",
                            font=("Segoe UI", 40),
                            bg=self.get_color('background'),
                            fg=self.get_color('success'))
        icon_label.pack(pady=(0, 15))

        # Título
        title_label = tk.Label(main_frame,
                             text="Escaneo Completado Exitosamente",
                             font=("Segoe UI", 16, "bold"),
                             bg=self.get_color('background'),
                             fg=self.get_color('text_primary'))
        title_label.pack(pady=(0, 20))

        # Frame para estadísticas
        stats_frame = tk.Frame(main_frame, bg=self.get_color('surface'), relief=tk.FLAT, bd=1)
        stats_frame.pack(fill=tk.X, pady=(0, 20))

        stats_title = tk.Label(stats_frame,
                             text="📊 Resumen del Escaneo",
                             font=("Segoe UI", 12, "bold"),
                             bg=self.get_color('surface'),
                             fg=self.get_color('text_primary'))
        stats_title.pack(pady=(15, 10))

        # Estadísticas en filas
        stats_content = tk.Frame(stats_frame, bg=self.get_color('surface'))
        stats_content.pack(fill=tk.X, padx=20, pady=(0, 15))

        # Total de archivos
        total_frame = tk.Frame(stats_content, bg=self.get_color('surface'))
        total_frame.pack(fill=tk.X, pady=2)
        tk.Label(total_frame, text="📄 Total de archivos escaneados:",
                font=("Segoe UI", 10), bg=self.get_color('surface'),
                fg=self.get_color('text_secondary')).pack(side=tk.LEFT)
        tk.Label(total_frame, text=str(total_files),
                font=("Segoe UI", 10, "bold"), bg=self.get_color('surface'),
                fg=self.get_color('text_primary')).pack(side=tk.RIGHT)

        # Archivos seguros
        safe_count = total_files - infected_count
        safe_frame = tk.Frame(stats_content, bg=self.get_color('surface'))
        safe_frame.pack(fill=tk.X, pady=2)
        tk.Label(safe_frame, text="🛡️ Archivos seguros:",
                font=("Segoe UI", 10), bg=self.get_color('surface'),
                fg=self.get_color('text_secondary')).pack(side=tk.LEFT)
        tk.Label(safe_frame, text=str(safe_count),
                font=("Segoe UI", 10, "bold"), bg=self.get_color('surface'),
                fg=self.get_color('success')).pack(side=tk.RIGHT)

        # Archivos infectados
        infected_frame = tk.Frame(stats_content, bg=self.get_color('surface'))
        infected_frame.pack(fill=tk.X, pady=2)
        tk.Label(infected_frame, text="🦠 Archivos infectados:",
                font=("Segoe UI", 10), bg=self.get_color('surface'),
                fg=self.get_color('text_secondary')).pack(side=tk.LEFT)
        tk.Label(infected_frame, text=str(infected_count),
                font=("Segoe UI", 10, "bold"), bg=self.get_color('surface'),
                fg=self.get_color('danger') if infected_count > 0 else self.get_color('success')).pack(side=tk.RIGHT)

        # Frame para botones
        button_frame = tk.Frame(main_frame, bg=self.get_color('background'))
        button_frame.pack(fill=tk.X, pady=(10, 0))

        # Si hay archivos infectados, mostrar botón de acción
        if infected_count > 0 and infected_files:
            action_btn = tk.Button(button_frame,
                                 text="🛡️ Gestionar Archivos Infectados",
                                 command=lambda: [dialog.destroy(),
                                                self.handle_infected_files(infected_files, infected_count, total_files)],
                                 bg=self.get_color('warning'),
                                 fg="white",
                                 activebackground=self.get_color('warning'),
                                 font=("Segoe UI", 10, "bold"),
                                 relief=tk.FLAT,
                                 borderwidth=0,
                                 padx=20,
                                 pady=12,
                                 cursor="hand2")
            action_btn.pack(side=tk.LEFT, padx=(0, 10), expand=True, fill=tk.X)

        # Botón para ver historial
        history_btn = tk.Button(button_frame,
                              text="📊 Ver Historial",
                              command=lambda: [dialog.destroy(), self.show_scan_history()],
                              bg=self.get_color('info'),
                              fg="white",
                              activebackground=self.get_color('info'),
                              font=("Segoe UI", 10, "bold"),
                              relief=tk.FLAT,
                              borderwidth=0,
                              padx=20,
                              pady=12,
                              cursor="hand2")

        if infected_count > 0:
            history_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        else:
            history_btn.pack(side=tk.LEFT, padx=(0, 10), expand=True, fill=tk.X)

        # Botón para cerrar
        close_btn = tk.Button(button_frame,
                            text="❌ Cerrar",
                            command=dialog.destroy,
                            bg=self.get_color('secondary'),
                            fg="white",
                            activebackground=self.get_color('secondary'),
                            font=("Segoe UI", 10, "bold"),
                            relief=tk.FLAT,
                            borderwidth=0,
                            padx=20,
                            pady=12,
                            cursor="hand2")
        close_btn.pack(side=tk.RIGHT, padx=(10, 0))

        # Agregar efectos hover a los botones
        if infected_count > 0 and infected_files:
            self.add_hover_effect(action_btn, "#e67e22", self.get_color('warning'))
        self.add_hover_effect(history_btn, "#0891b2", self.get_color('info'))
        self.add_hover_effect(close_btn, "#64748b", self.get_color('secondary'))

    def add_hover_effect(self, widget, hover_color=None, normal_color=None):
        """Agregar efecto hover a un widget"""
        if hover_color is None:
            hover_color = self.get_color('primary_light')
        if normal_color is None:
            normal_color = widget.cget('bg')

        def on_enter(event):
            widget.configure(bg=hover_color)

        def on_leave(event):
            widget.configure(bg=normal_color)

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def add_click_effect(self, widget):
        """Agregar efecto de click a un widget"""
        original_relief = widget.cget('relief')

        def on_click(event):
            widget.configure(relief=tk.SUNKEN)
            widget.after(100, lambda: widget.configure(relief=original_relief))

        widget.bind("<Button-1>", on_click)

    def animate_progress_bar(self, target_value, duration=1000):
        """Animar la barra de progreso hacia un valor objetivo"""
        if not hasattr(self, 'progress'):
            return

        current_value = self.progress['value']
        steps = 50
        step_size = (target_value - current_value) / steps
        step_duration = duration // steps

        def update_progress(step):
            if step <= steps:
                new_value = current_value + (step_size * step)
                self.progress['value'] = new_value
                self.root.after(step_duration, lambda: update_progress(step + 1))

        update_progress(1)

    def show_status_message(self, message, duration=3000, message_type="info"):
        """Mostrar mensaje de estado temporal"""
        if hasattr(self, 'status_label'):
            # Colores según el tipo de mensaje
            color_map = {
                "info": self.get_color('info'),
                "success": self.get_color('success'),
                "warning": self.get_color('warning'),
                "error": self.get_color('danger')
            }

            # Iconos según el tipo
            icon_map = {
                "info": "ℹ️",
                "success": "✅",
                "warning": "⚠️",
                "error": "❌"
            }

            icon = icon_map.get(message_type, "ℹ️")
            color = color_map.get(message_type, self.get_color('info'))

            self.status_label.configure(text=f"{icon} {message}", fg=color)

            # Restaurar mensaje original después del tiempo especificado
            self.root.after(duration, lambda: self.status_label.configure(
                text="Listo para escanear",
                fg=self.get_color('text_secondary')
            ))

    def pulse_widget(self, widget, color=None, duration=500):
        """Crear efecto de pulso en un widget"""
        if color is None:
            color = self.get_color('primary_light')

        original_bg = widget.cget('bg')

        def pulse_step(step, direction):
            if step <= 10:
                # Calcular la intensidad del pulso
                intensity = step / 10.0 if direction == 1 else (10 - step) / 10.0

                # Interpolar entre el color original y el color de pulso
                # (Simplificado - en una implementación real usarías interpolación de color)
                widget.configure(bg=color if intensity > 0.5 else original_bg)

                next_step = step + 1 if direction == 1 else step - 1
                next_direction = direction if (direction == 1 and step < 10) or (direction == -1 and step > 0) else -direction

                if step == 0 and direction == -1:
                    widget.configure(bg=original_bg)
                    return

                widget.after(duration // 20, lambda: pulse_step(next_step, next_direction))

        pulse_step(0, 1)

    def compute_hashes(self, file_path):
        # Calcular hashes de un archivo con manejo de excepciones
        try:
            hashers = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha256': hashlib.sha256()
            }
            
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    for h in hashers.values():
                        h.update(chunk)
            
            return {
                'md5': hashers['md5'].hexdigest(),
                'sha1': hashers['sha1'].hexdigest(),
                'sha256': hashers['sha256'].hexdigest()
            }
        except FileNotFoundError:
            print(f"Archivo no encontrado: {file_path}")
            return None
        except Exception as e:
            print(f"Error al calcular hashes para {file_path}: {e}")
            return None
    
    # Método para verificar si un archivo es un virus comparando sus hashes con la base de datos
    def check_virus(self, hashes):
        # Verificar si un archivo es un virus con manejo de errores
        db_conn = None  # Initialize db_conn to None
        try:
            db_conn = sqlite3.connect(resource_path("virus_data.db")) # Create a new connection
            cursor = db_conn.cursor()
            
            # Verificar si el hash MD5 está en la tabla de virus
            cursor.execute("SELECT COUNT(*) FROM virus_md5 WHERE md5_hash = ?", (hashes['md5'],))
            md5_count = cursor.fetchone()[0]
            
            # Verificar si el hash SHA1 está en la tabla de virus
            cursor.execute("SELECT COUNT(*) FROM virus_sha1 WHERE sha1_hash = ?", (hashes['sha1'],))
            sha1_count = cursor.fetchone()[0]
            
            # Verificar si el hash SHA256 está en la tabla de virus
            cursor.execute("SELECT COUNT(*) FROM virus_sha256 WHERE sha256_hash = ?", (hashes['sha256'],))
            sha256_count = cursor.fetchone()[0]
            
            # Retornar True si alguno de los hashes coincide con un registro en la base de datos
            return md5_count > 0 or sha1_count > 0 or sha256_count > 0
        except sqlite3.Error as e:
            # Manejo de errores en caso de problemas con la base de datos
            print(f"Error en base de datos (check_virus): {e}") # Added context to print
            return False
        finally:
            if db_conn:
                db_conn.close() # Close the connection in the finally block

    # Método para escanear un archivo seleccionado por el usuario
    def scan_file(self):
        """Abrir un cuadro de diálogo para seleccionar un archivo"""
        file_path = filedialog.askopenfilename(
            title="Seleccionar archivo para escanear",
            filetypes=[
                ("Todos los archivos", "*.*"),
                ("Ejecutables", "*.exe"),
                ("Documentos", "*.pdf;*.doc;*.docx"),
                ("Imágenes", "*.jpg;*.png;*.gif")
            ]
        )
        if file_path:
            self.file_list = [file_path]
            self.btn_start_scan.config(state="normal")
            self.show_status_message(f"Archivo seleccionado: {os.path.basename(file_path)}", 3000, "success")
            # Efecto visual en el botón de inicio
            self.pulse_widget(self.btn_start_scan, self.get_color('success_hover'))

    # Método para escanear todos los archivos de un directorio seleccionado por el usuario
    def scan_directory(self):
        """Abrir un cuadro de diálogo para seleccionar un directorio"""
        dir_path = filedialog.askdirectory(title="Seleccionar directorio para escanear")
        if dir_path:
            self.file_list = [os.path.join(root, f) for root, _, files in os.walk(dir_path) for f in files]
            self.btn_start_scan.config(state="normal")
            file_count = len(self.file_list)
            self.show_status_message(f"Directorio seleccionado: {file_count} archivos encontrados", 3000, "success")
            # Efecto visual en el botón de inicio
            self.pulse_widget(self.btn_start_scan, self.get_color('success_hover'))

    def start_scan(self):
        """Iniciar el escaneo con manejo de excepciones y feedback visual"""
        if self.file_list:
            self.btn_start_scan.config(state="disabled")
            self.btn_stop_scan.config(state="normal")
            self.txt_result.delete(1.0, tk.END)
            self.scan_stopped = False

            # Feedback visual y de estado
            self.show_status_message("Iniciando escaneo...", 2000, "info")
            self.animate_progress_bar(0)  # Resetear barra de progreso

            # Manejo de excepciones en el hilo
            def scan_thread():
                try:
                    self.perform_scan(self.file_list)
                except Exception as e:
                    messagebox.showerror("Error", f"Se produjo un error durante el escaneo: {e}")
                    self.toggle_buttons("normal")
                    self.btn_stop_scan.config(state="disabled")

            Thread(target=scan_thread).start()

    def stop_scan(self):
        self.scan_stopped = True  # Activar la bandera para detener el escaneo
        self.btn_stop_scan.config(state="disabled")  # Deshabilitar el botón "Detener"

    # Método para actualizar el progreso en la barra de progreso
    def update_progress(self, value):
        # Actualizar el valor de la barra de progreso
        self.progress['value'] = value
        # Refrescar la interfaz gráfica
        self.root.update_idletasks()

    # Método para deshabilitar los botones durante el escaneo
    def toggle_buttons(self, state):
        # Deshabilitar o habilitar los botones relacionados con el escaneo
        self.btn_scan_file.config(state=state)
        self.btn_scan_dir.config(state=state)
        self.btn_quick_scan.config(state=state)  # Agregar botón de escaneo rápido
        self.btn_full_scan.config(state=state)   # Agregar botón de escaneo completo
        
        # Actualizar colores si están deshabilitados
        if state == "disabled":
            # Si los botones están deshabilitados, oscurecemos los colores
            disabled_success = "#1a654c"  # Verde más oscuro
            disabled_danger = "#8b1a1a"   # Rojo más oscuro
            self.btn_start_scan.config(bg=disabled_success)
            self.btn_stop_scan.config(bg=disabled_danger)
        else:
            # Si los botones están habilitados, volvemos a los colores originales
            self.btn_start_scan.config(bg=self.get_color('success'))
            self.btn_stop_scan.config(bg=self.get_color('danger'))

    # Método para realizar el escaneo rápido
    def quick_scan(self):
        # Definir zonas críticas y extensiones de archivos ejecutables
        if platform.system() == "Windows":
            critical_paths = ["C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)"]
            executable_extensions = [".exe", ".dll", ".bat"]
        else:  # Linux/Unix
            critical_paths = ["/usr/bin", "/usr/local/bin"]
            executable_extensions = [".sh", ".bin"]

        # Recopilar archivos prioritarios
        self.file_list = []
        for path in critical_paths:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        if any(file.endswith(ext) for ext in executable_extensions):
                            self.file_list.append(os.path.join(root, file))

        if self.file_list:
            self.start_scan()
        else:
            self.show_custom_dialog(
                "⚡ Escaneo Rápido",
                "No se encontraron archivos para escanear en las zonas críticas del sistema.",
                "info"
            )
    
    # Método para realizar el escaneo de una lista de archivos con multithreading avanzado
    def perform_scan(self, file_list):
        # Realizar el escaneo con manejo de errores y optimización
        try:
            # Deshabilitar los botones al iniciar el escaneo
            self.toggle_buttons("disabled")
            self.progress['value'] = 0
            self.progress_label = ttk.Label(self.frame, text="Escaneando...")
            self.progress_label.pack(fill=tk.X, padx=5, pady=5)

            total_files = len(file_list)  # Número total de archivos a escanear
            infected_count = 0  # Contador de archivos infectados
            infected_files = []  # Lista de archivos infectados

            def scan_file(file_path):
                nonlocal infected_count
                nonlocal infected_files

                # Verificar si se solicitó detener el escaneo
                if self.scan_stopped:
                    return

                # Crear una conexión local a la base de datos para este hilo
                db_connection = sqlite3.connect(resource_path("virus_data.db"))
                cursor = db_connection.cursor()

                try:
                    # Verificar si el archivo existe y es válido
                    if not os.path.isfile(file_path):
                        return

                    # Calcular los hashes del archivo
                    hashes = self.compute_hashes(file_path)
                    if not hashes:
                        return

                    # Verificar si el archivo está infectado
                    is_infected = self.check_virus(hashes)

                    # Construir el texto de resultados para el archivo
                    result_text = f"Archivo: {file_path}\n"
                    result_text += f"MD5: {hashes['md5']}\n"
                    result_text += f"SHA1: {hashes['sha1']}\n"
                    result_text += f"SHA256: {hashes['sha256']}\n"
                    result_text += "Estado: "

                    if is_infected:
                        infected_count += 1
                        infected_files.append(file_path)
                        result_text += "¡VIRUS DETECTADO! 🔴\n\n"
                    else:
                        result_text += "Seguro 🟢\n\n"

                    self.txt_result.insert(tk.END, result_text)
                    self.txt_result.see(tk.END)

                    # Registrar el resultado del escaneo en la base de datos
                    cursor.execute("INSERT INTO scan_history (file_path, is_infected) VALUES (?, ?)", (file_path, is_infected))
                    db_connection.commit()
                except sqlite3.Error as e:
                    print(f"Error en base de datos: {e}")
                finally:
                    db_connection.close()  # Cerrar la conexión local

            # Usar ThreadPoolExecutor para escanear archivos en paralelo
            with ThreadPoolExecutor() as executor:
                for i, _ in enumerate(executor.map(scan_file, file_list), 1):
                    # Verificar si se solicitó detener el escaneo
                    if self.scan_stopped:
                        break

                    # Actualizar el progreso en la barra de progreso
                    self.update_progress((i / total_files) * 100)

            # Restablecer la barra de progreso al finalizar
            self.update_progress(0)
            self.progress_label.destroy()

            # Habilitar los botones al finalizar el escaneo
            self.toggle_buttons("normal")
            self.btn_stop_scan.config(state="disabled")  # Deshabilitar el botón "Detener"

            if not self.scan_stopped:
                # Usar el nuevo diálogo de escaneo completado
                self.show_scan_completed_dialog(total_files, infected_count, infected_files if infected_count > 0 else None)
            else:
                self.show_custom_dialog(
                    "⏹️ Escaneo Detenido",
                    "El escaneo fue detenido por el usuario.",
                    "warning"
                )
        except Exception as e:
            print(f"Error durante el escaneo: {e}")
        finally:
            # Asegurar que los botones se habiliten al finalizar
            self.toggle_buttons("normal")
            self.btn_stop_scan.config(state="disabled")

    def handle_infected_files(self, infected_files, infected_count, total_files):
        """Mostrar opciones para manejar archivos infectados con diálogo moderno"""
        response = self.show_custom_dialog(
            "🦠 Archivos Infectados Detectados",
            f"Se encontraron {infected_count} archivos infectados de {total_files}.\n\n"
            "¿Qué acción desea realizar?",
            "warning",
            ["🛡️ Cuarentena", "🗑️ Eliminar", "❌ Cancelar"]
        )

        if response is None or response == 2:  # Cancelar
            return

        quarantine_dir = "cuarentena"
        if response == 0:  # Mover a cuarentena
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)
            moved_count = 0
            for file in infected_files:
                try:
                    base_name = os.path.basename(file)
                    quarantine_path = os.path.join(quarantine_dir, base_name)
                    if os.path.exists(quarantine_path):
                        quarantine_path = os.path.join(quarantine_dir, f"{base_name}_{int(time.time())}")
                    os.rename(file, quarantine_path)
                    moved_count += 1
                except Exception as e:
                    print(f"Error al mover {file} a cuarentena: {e}")

            self.show_custom_dialog(
                "✅ Cuarentena Completada",
                f"Se movieron {moved_count} archivos a la carpeta '{quarantine_dir}'.",
                "success"
            )

        elif response == 1:  # Eliminar archivos
            # Confirmación adicional para eliminación
            confirm = self.show_custom_dialog(
                "⚠️ Confirmar Eliminación",
                f"¿Está seguro de que desea eliminar permanentemente {infected_count} archivos?\n\n"
                "Esta acción no se puede deshacer.",
                "warning",
                ["🗑️ Eliminar", "❌ Cancelar"]
            )

            if confirm == 0:  # Confirmar eliminación
                deleted_count = 0
                for file in infected_files:
                    try:
                        os.remove(file)
                        deleted_count += 1
                    except Exception as e:
                        print(f"Error al eliminar {file}: {e}")

                self.show_custom_dialog(
                    "✅ Eliminación Completada",
                    f"Se eliminaron {deleted_count} archivos infectados.",
                    "success"
                )
    
    # Método para realizar el escaneo completo
    def is_excluded_path(self, path):
        # Lista de directorios del sistema a excluir del escaneo para evitar errores de permisos
        excluded_dirs = [
            "/proc",    # Archivos de procesos virtuales
            "/sys",     # Archivos del sistema virtual
            "/dev",     # Dispositivos
            "/run",     # Archivos temporales en tiempo de ejecución
            "/var/lock", # Archivos de bloqueo
            "/var/run"   # Archivos de ejecución de servicios
        ]
        
        # Comprobar si la ruta comienza con alguno de los directorios excluidos
        return any(path.startswith(excluded) for excluded in excluded_dirs)
    
    def full_scan(self):
        """Escaneo completo del sistema con recopilación asíncrona de archivos"""
        # Resetear variables
        self.file_list = []
        self.scan_stopped = False
        self.collection_cancelled = False

        # Crear ventana de progreso para la recopilación
        self.create_collection_progress_window()

        # Iniciar recopilación de archivos en hilo separado
        def collect_files_thread():
            try:
                self.collect_files_async()
            except Exception as e:
                print(f"Error durante la recopilación de archivos: {e}")
                self.root.after(0, self.close_collection_progress)
                self.root.after(0, lambda: self.show_custom_dialog(
                    "❌ Error",
                    f"Error durante la recopilación de archivos: {e}",
                    "error"
                ))

        Thread(target=collect_files_thread, daemon=True).start()

    def create_collection_progress_window(self):
        """Crear ventana de progreso para la recopilación de archivos"""
        self.collection_window = tk.Toplevel(self.root)
        self.collection_window.title("🔍 Recopilando Archivos - Escaneo Completo")
        self.collection_window.geometry("600x300")
        self.collection_window.resizable(False, False)
        self.collection_window.configure(bg=self.get_color('background'))
        self.collection_window.transient(self.root)
        self.collection_window.grab_set()

        # Centrar ventana
        self.collection_window.update_idletasks()
        x = (self.collection_window.winfo_screenwidth() // 2) - (self.collection_window.winfo_width() // 2)
        y = (self.collection_window.winfo_screenheight() // 2) - (self.collection_window.winfo_height() // 2)
        self.collection_window.geometry(f"+{x}+{y}")

        # Frame principal
        main_frame = tk.Frame(self.collection_window, bg=self.get_color('background'))
        main_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        # Título
        title_label = tk.Label(main_frame,
                              text="🔍 Recopilando Archivos del Sistema",
                              font=("Segoe UI", 16, "bold"),
                              bg=self.get_color('background'),
                              fg=self.get_color('text_primary'))
        title_label.pack(pady=(0, 20))

        # Información de progreso
        self.collection_info_label = tk.Label(main_frame,
                                            text="Iniciando recopilación...",
                                            font=("Segoe UI", 11),
                                            bg=self.get_color('background'),
                                            fg=self.get_color('text_secondary'))
        self.collection_info_label.pack(pady=(0, 10))

        # Directorio actual
        self.current_dir_label = tk.Label(main_frame,
                                        text="",
                                        font=("Segoe UI", 10),
                                        bg=self.get_color('background'),
                                        fg=self.get_color('text_secondary'),
                                        wraplength=550)
        self.current_dir_label.pack(pady=(0, 15))

        # Contador de archivos
        self.file_count_label = tk.Label(main_frame,
                                       text="Archivos encontrados: 0",
                                       font=("Segoe UI", 12, "bold"),
                                       bg=self.get_color('background'),
                                       fg=self.get_color('primary'))
        self.file_count_label.pack(pady=(0, 20))

        # Barra de progreso indeterminada
        self.collection_progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.collection_progress.pack(fill=tk.X, pady=(0, 20))
        self.collection_progress.start(10)

        # Botón cancelar
        cancel_btn = tk.Button(main_frame,
                             text="❌ Cancelar Recopilación",
                             command=self.cancel_collection,
                             bg=self.get_color('danger'),
                             fg="white",
                             activebackground=self.get_color('danger'),
                             font=("Segoe UI", 10, "bold"),
                             relief=tk.FLAT,
                             borderwidth=0,
                             padx=20,
                             pady=12,
                             cursor="hand2")
        cancel_btn.pack()

    def collect_files_async(self):
        """Recopilar archivos de forma asíncrona con feedback visual"""
        # Directorios a escanear con mejor filtrado
        dirs_to_scan = ["/home", "/usr", "/opt", "/bin", "/sbin", "/etc"]

        # Directorios adicionales a excluir para mejorar rendimiento
        additional_excluded = [
            "/usr/share/doc",      # Documentación
            "/usr/share/man",      # Páginas de manual
            "/usr/share/locale",   # Archivos de localización
            "/usr/lib/debug",      # Símbolos de debug
            "/var/cache",          # Cache del sistema
            "/var/tmp",            # Archivos temporales
            "/tmp"                 # Archivos temporales
        ]

        file_count = 0

        for base_dir in dirs_to_scan:
            if self.collection_cancelled:
                break

            if not os.path.exists(base_dir):
                continue

            # Actualizar directorio actual
            self.root.after(0, lambda d=base_dir: self.current_dir_label.config(
                text=f"Escaneando: {d}"
            ))

            try:
                for root, dirs, files in os.walk(base_dir):
                    if self.collection_cancelled:
                        break

                    # Filtrar directorios problemáticos antes de continuar
                    if (self.is_excluded_path(root) or
                        any(excluded in root for excluded in additional_excluded) or
                        "/." in root):  # Directorios ocultos
                        dirs.clear()  # No explorar subdirectorios
                        continue

                    # Actualizar directorio actual cada ciertos directorios
                    if file_count % 100 == 0:
                        self.root.after(0, lambda r=root: self.current_dir_label.config(
                            text=f"Escaneando: {r[:60]}..." if len(r) > 60 else f"Escaneando: {r}"
                        ))

                    for file in files:
                        if self.collection_cancelled:
                            break

                        # Saltar archivos ocultos y ciertos tipos
                        if (file.startswith(".") or
                            file.endswith(('.tmp', '.cache', '.log')) or
                            file.startswith('~')):
                            continue

                        file_path = os.path.join(root, file)

                        # Verificar que el archivo sea accesible
                        try:
                            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                                self.file_list.append(file_path)
                                file_count += 1

                                # Actualizar contador cada 50 archivos
                                if file_count % 50 == 0:
                                    self.root.after(0, lambda c=file_count: self.file_count_label.config(
                                        text=f"Archivos encontrados: {c:,}"
                                    ))
                        except (OSError, PermissionError):
                            continue

            except (OSError, PermissionError) as e:
                print(f"Error accediendo a {base_dir}: {e}")
                continue

        # Finalizar recopilación
        self.root.after(0, self.finish_collection)

    def cancel_collection(self):
        """Cancelar la recopilación de archivos"""
        self.collection_cancelled = True
        self.close_collection_progress()
        self.show_custom_dialog(
            "⏹️ Recopilación Cancelada",
            "La recopilación de archivos fue cancelada por el usuario.",
            "warning"
        )

    def finish_collection(self):
        """Finalizar la recopilación e iniciar el escaneo"""
        self.close_collection_progress()

        if self.collection_cancelled:
            return

        if self.file_list:
            file_count = len(self.file_list)
            self.show_custom_dialog(
                "✅ Recopilación Completada",
                f"Se encontraron {file_count:,} archivos para escanear.\n\n"
                "¿Desea proceder con el escaneo completo?",
                "success",
                callback=lambda: self.start_scan()
            )
        else:
            self.show_custom_dialog(
                "🌍 Escaneo Completo",
                "No se encontraron archivos para escanear en el sistema.",
                "warning"
            )

    def close_collection_progress(self):
        """Cerrar ventana de progreso de recopilación"""
        if hasattr(self, 'collection_window') and self.collection_window:
            try:
                self.collection_progress.stop()
                self.collection_window.destroy()
            except:
                pass



    def draw_card_chart(self, parent_frame, values, labels, chart_type="🃏 Tarjetas Visuales"):
        """Crear gráfico tipo tarjetas mejorado para mostrar la distribución"""
        try:
            # Verificar que tenemos datos válidos
            if not values or not labels:
                error_label = tk.Label(parent_frame,
                                     text="❌ No hay datos para mostrar en las tarjetas",
                                     font=("Segoe UI", 12, "bold"),
                                     bg=self.get_color('surface'),
                                     fg=self.get_color('danger'))
                error_label.pack(expand=True, pady=50)
                return

            total = sum(values)
            
            # Título específico según el tipo de gráfico
            title_text = "🃏 Tarjetas Visuales de Datos"
            title_label = tk.Label(parent_frame,
                                 text=title_text,
                                 font=("Segoe UI", 14, "bold"),
                                 bg=self.get_color('surface'),
                                 fg=self.get_color('text_primary'))
            title_label.pack(pady=(10, 20))
            
            # Frame principal para las tarjetas
            main_cards_frame = tk.Frame(parent_frame, bg=self.get_color('surface'))
            main_cards_frame.pack(fill=tk.X, expand=True, padx=20, pady=10)

            # Configuración de colores e iconos
            colors = [self.get_color('success'), self.get_color('danger')]
            icons = ['🛡️', '🦠']

            for i, (label, value) in enumerate(zip(labels, values)):
                percentage = (value / total * 100) if total > 0 else 0
                
                # Container para cada tarjeta con sombra
                card_container = tk.Frame(main_cards_frame, bg=self.get_color('surface'))
                card_container.pack(side=tk.LEFT, padx=15, pady=10, fill=tk.BOTH, expand=True)
                
                # Tarjeta principal
                card = tk.Frame(card_container, bg=colors[i % len(colors)], relief=tk.RAISED, bd=2)
                card.pack(fill=tk.BOTH, expand=True)

                # Icono
                icon_label = tk.Label(card,
                                    text=icons[i % len(icons)],
                                    font=("Segoe UI", 36),
                                    bg=colors[i % len(colors)],
                                    fg="white")
                icon_label.pack(pady=(20, 10))

                # Valor principal
                value_label = tk.Label(card,
                                     text=f"{value:,}",
                                     font=("Segoe UI", 24, "bold"),
                                     bg=colors[i % len(colors)],
                                     fg="white")
                value_label.pack(pady=5)

                # Porcentaje
                percentage_label = tk.Label(card,
                                          text=f"{percentage:.1f}%",
                                          font=("Segoe UI", 16, "bold"),
                                          bg=colors[i % len(colors)],
                                          fg="white")
                percentage_label.pack(pady=5)

                # Etiqueta descriptiva
                label_text = tk.Label(card,
                                    text=label,
                                    font=("Segoe UI", 12, "bold"),
                                    bg=colors[i % len(colors)],
                                    fg="white",
                                    wraplength=150)
                label_text.pack(pady=(10, 20))

            # Estadísticas adicionales
            stats_frame = tk.Frame(parent_frame, bg=self.get_color('surface_alt'), relief=tk.FLAT, bd=1)
            stats_frame.pack(fill=tk.X, pady=(20, 10), padx=20)

            stats_title = tk.Label(stats_frame,
                                 text="📊 Resumen Estadístico",
                                 font=("Segoe UI", 12, "bold"),
                                 bg=self.get_color('surface_alt'),
                                 fg=self.get_color('text_primary'))
            stats_title.pack(pady=(15, 10))

            safe_ratio = (values[0] / total * 100) if total > 0 else 0
            stats_text = f"Total de Archivos: {total:,} | Archivos Seguros: {safe_ratio:.1f}% | Estado: {'SEGURO' if safe_ratio > 90 else 'REQUIERE ATENCIÓN'}"
            
            stats_label = tk.Label(stats_frame,
                                 text=stats_text,
                                 font=("Segoe UI", 10),
                                 bg=self.get_color('surface_alt'),
                                 fg=self.get_color('text_secondary'))
            stats_label.pack(pady=(0, 15))

        except Exception as e:
            print(f"Error en draw_card_chart: {e}")
            # Mostrar error en el frame
            error_label = tk.Label(parent_frame,
                                 text=f"❌ Error al crear tarjetas visuales: {str(e)}",
                                 font=("Segoe UI", 12),
                                 bg=self.get_color('surface'),
                                 fg=self.get_color('danger'))
            error_label.pack(expand=True, padx=20, pady=20)



    def draw_heatmap_chart(self, parent_frame, values, labels):
        """Crear visualización tipo mapa de calor alternativo"""
        try:
            # Frame para el mapa de calor alternativo
            heatmap_frame = tk.Frame(parent_frame, bg=self.get_color('surface'))
            heatmap_frame.pack(fill=tk.BOTH, expand=True, pady=10)

            # Título del mapa de calor
            title_label = tk.Label(heatmap_frame,
                                 text="🔥 Mapa de Calor - Intensidad de Archivos",
                                 font=("Segoe UI", 14, "bold"),
                                 bg=self.get_color('surface'),
                                 fg=self.get_color('text_primary'))
            title_label.pack(pady=(0, 20))

            # Crear visualización tipo termómetro para cada categoría
            max_value = max(values) if values else 1
            
            for i, (label, value) in enumerate(zip(labels, values)):
                # Frame para cada "termómetro"
                thermo_frame = tk.Frame(heatmap_frame, bg=self.get_color('surface'))
                thermo_frame.pack(fill=tk.X, pady=10, padx=20)

                # Etiqueta de categoría
                label_frame = tk.Frame(thermo_frame, bg=self.get_color('surface'))
                label_frame.pack(fill=tk.X, pady=(0, 5))

                tk.Label(label_frame,
                        text=f"{label}: {value:,}",
                        font=("Segoe UI", 12, "bold"),
                        bg=self.get_color('surface'),
                        fg=self.get_color('text_primary'),
                        anchor="w").pack(side=tk.LEFT)

                # Calcular intensidad (0-100%)
                intensity = (value / max_value) * 100 if max_value > 0 else 0

                # Determinar color basado en la intensidad
                if intensity > 75:
                    color = "#dc2626"  # Rojo intenso
                    intensity_text = "🔥 Muy Alto"
                elif intensity > 50:
                    color = "#f59e0b"  # Amarillo/Naranja
                    intensity_text = "🌡️ Alto"
                elif intensity > 25:
                    color = "#10b981"  # Verde
                    intensity_text = "📊 Medio"
                else:
                    color = "#3b82f6"  # Azul
                    intensity_text = "❄️ Bajo"

                # Barra de intensidad visual
                intensity_bar_frame = tk.Frame(thermo_frame, bg=self.get_color('surface_alt'), height=30)
                intensity_bar_frame.pack(fill=tk.X, pady=(0, 5))
                intensity_bar_frame.pack_propagate(False)

                # Parte llena de la barra (proporcional a la intensidad)
                if intensity > 0:
                    filled_width = int(intensity * 3)  # Convertir porcentaje a píxeles aproximados
                    filled_bar = tk.Frame(intensity_bar_frame, bg=color, height=30)
                    filled_bar.pack(side=tk.LEFT, fill=tk.Y)
                    filled_bar.configure(width=filled_width)

                # Etiqueta de intensidad
                intensity_label = tk.Label(thermo_frame,
                                          text=f"{intensity_text} ({intensity:.1f}%)",
                                          font=("Segoe UI", 10),
                                          bg=self.get_color('surface'),
                                          fg=color)
                intensity_label.pack(anchor="e")

            # Leyenda de colores
            legend_frame = tk.Frame(heatmap_frame, bg=self.get_color('surface'))
            legend_frame.pack(fill=tk.X, pady=(20, 10), padx=20)

            legend_title = tk.Label(legend_frame,
                                  text="🎨 Leyenda de Intensidad:",
                                  font=("Segoe UI", 11, "bold"),
                                  bg=self.get_color('surface'),
                                  fg=self.get_color('text_primary'))
            legend_title.pack(anchor="w", pady=(0, 10))

            # Elementos de la leyenda
            legend_items = [
                ("🔥 Muy Alto (75-100%)", "#dc2626"),
                ("🌡️ Alto (50-75%)", "#f59e0b"),
                ("📊 Medio (25-50%)", "#10b981"),
                ("❄️ Bajo (0-25%)", "#3b82f6")
            ]

            for legend_text, legend_color in legend_items:
                item_frame = tk.Frame(legend_frame, bg=self.get_color('surface'))
                item_frame.pack(side=tk.LEFT, padx=(0, 15))

                # Cuadrito de color
                color_box = tk.Frame(item_frame, bg=legend_color, width=15, height=15)
                color_box.pack(side=tk.LEFT, padx=(0, 5))
                color_box.pack_propagate(False)

                # Texto de la leyenda
                tk.Label(item_frame,
                        text=legend_text,
                        font=("Segoe UI", 9),
                        bg=self.get_color('surface'),
                        fg=self.get_color('text_secondary')).pack(side=tk.LEFT)

        except Exception as e:
            print(f"Error en draw_heatmap_chart: {e}")

    def draw_donut_chart(self, parent_frame, values, labels):
        """Crear visualización circular tipo dona usando tkinter"""
        try:
            # Frame para el gráfico de dona
            donut_frame = tk.Frame(parent_frame, bg=self.get_color('surface'))
            donut_frame.pack(fill=tk.BOTH, expand=True, pady=10)

            # Título del gráfico
            title_label = tk.Label(donut_frame,
                                 text="🎯 Gráfico de Dona - Distribución Circular",
                                 font=("Segoe UI", 14, "bold"),
                                 bg=self.get_color('surface'),
                                 fg=self.get_color('text_primary'))
            title_label.pack(pady=(0, 20))

            # Frame principal para el gráfico
            main_chart_frame = tk.Frame(donut_frame, bg=self.get_color('surface'))
            main_chart_frame.pack(fill=tk.BOTH, expand=True)

            # Canvas para dibujar el gráfico circular
            canvas_size = 300
            canvas = tk.Canvas(main_chart_frame, 
                             width=canvas_size, 
                             height=canvas_size,
                             bg=self.get_color('surface'),
                             highlightthickness=0)
            canvas.pack(side=tk.LEFT, padx=20, pady=20)

            # Calcular datos para el gráfico
            total = sum(values) if values else 1
            center_x = canvas_size // 2
            center_y = canvas_size // 2
            outer_radius = 100
            inner_radius = 50

            # Colores para los segmentos
            colors = [self.get_color('success'), self.get_color('danger'), self.get_color('warning')]
            
            # Dibujar los segmentos de la dona
            start_angle = 0
            for i, (value, label) in enumerate(zip(values, labels)):
                # Calcular ángulo del segmento
                angle = (value / total) * 360 if total > 0 else 0
                
                # Dibujar arco exterior
                canvas.create_arc(
                    center_x - outer_radius, center_y - outer_radius,
                    center_x + outer_radius, center_y + outer_radius,
                    start=start_angle, extent=angle,
                    fill=colors[i % len(colors)],
                    outline=self.get_color('background'),
                    width=2
                )
                
                # Calcular posición para etiqueta
                mid_angle = start_angle + angle/2
                label_radius = (outer_radius + inner_radius) / 2
                label_x = center_x + label_radius * 0.7 * (1 if mid_angle < 180 else -1)
                label_y = center_y + label_radius * 0.7 * (1 if 90 < mid_angle < 270 else -1)
                
                # Agregar etiqueta con porcentaje
                percentage = (value / total * 100) if total > 0 else 0
                if percentage > 5:  # Solo mostrar etiqueta si el segmento es suficientemente grande
                    canvas.create_text(label_x, label_y,
                                     text=f"{percentage:.1f}%",
                                     fill="white",
                                     font=("Segoe UI", 10, "bold"))
                
                start_angle += angle

            # Dibujar círculo interior (agujero de la dona)
            canvas.create_oval(
                center_x - inner_radius, center_y - inner_radius,
                center_x + inner_radius, center_y + inner_radius,
                fill=self.get_color('surface'),
                outline=self.get_color('border'),
                width=2
            )

            # Texto central con total
            canvas.create_text(center_x, center_y - 10,
                             text="Total",
                             fill=self.get_color('text_secondary'),
                             font=("Segoe UI", 12, "bold"))
            canvas.create_text(center_x, center_y + 10,
                             text=f"{total:,}",
                             fill=self.get_color('text_primary'),
                             font=("Segoe UI", 16, "bold"))

            # Leyenda lateral
            legend_frame = tk.Frame(main_chart_frame, bg=self.get_color('surface'))
            legend_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=20)

            # Título de la leyenda
            legend_title = tk.Label(legend_frame,
                                  text="📋 Leyenda",
                                  font=("Segoe UI", 12, "bold"),
                                  bg=self.get_color('surface'),
                                  fg=self.get_color('text_primary'))
            legend_title.pack(pady=(0, 15))

            # Elementos de la leyenda
            for i, (label, value) in enumerate(zip(labels, values)):
                percentage = (value / total * 100) if total > 0 else 0
                
                # Frame para cada elemento
                item_frame = tk.Frame(legend_frame, bg=self.get_color('surface'))
                item_frame.pack(fill=tk.X, pady=5)

                # Indicador de color
                color_indicator = tk.Frame(item_frame, 
                                         bg=colors[i % len(colors)], 
                                         width=20, height=20)
                color_indicator.pack(side=tk.LEFT, padx=(0, 10))
                color_indicator.pack_propagate(False)

                # Texto de la leyenda
                text_frame = tk.Frame(item_frame, bg=self.get_color('surface'))
                text_frame.pack(side=tk.LEFT, fill=tk.X)

                tk.Label(text_frame,
                        text=label,
                        font=("Segoe UI", 11, "bold"),
                        bg=self.get_color('surface'),
                        fg=self.get_color('text_primary'),
                        anchor="w").pack(fill=tk.X)

                tk.Label(text_frame,
                        text=f"{value:,} ({percentage:.1f}%)",
                        font=("Segoe UI", 10),
                        bg=self.get_color('surface'),
                        fg=self.get_color('text_secondary'),
                        anchor="w").pack(fill=tk.X)

            # Estadísticas adicionales
            stats_frame = tk.Frame(donut_frame, bg=self.get_color('surface_alt'), relief=tk.FLAT, bd=1)
            stats_frame.pack(fill=tk.X, pady=(20, 0), padx=20)

            stats_title = tk.Label(stats_frame,
                                 text="📊 Estadísticas del Gráfico Circular",
                                 font=("Segoe UI", 11, "bold"),
                                 bg=self.get_color('surface_alt'),
                                 fg=self.get_color('text_primary'))
            stats_title.pack(pady=(10, 5))

            # Mostrar dominancia del segmento mayor
            if values:
                max_value = max(values)
                max_index = values.index(max_value)
                dominance = (max_value / total * 100) if total > 0 else 0
                
                stats_text = f"Categoría Dominante: {labels[max_index]} ({dominance:.1f}%) | "
                stats_text += f"Total de Categorías: {len(values)} | "
                stats_text += f"Distribución: {'Equilibrada' if dominance < 70 else 'Concentrada'}"
                
                stats_label = tk.Label(stats_frame,
                                     text=stats_text,
                                     font=("Segoe UI", 10),
                                     bg=self.get_color('surface_alt'),
                                     fg=self.get_color('text_secondary'))
                stats_label.pack(pady=(0, 10))

        except Exception as e:
            print(f"Error en draw_donut_chart: {e}")
            # Mostrar error en el frame
            error_label = tk.Label(parent_frame,
                                 text=f"❌ Error al crear gráfico de dona: {str(e)}",
                                 font=("Segoe UI", 12),
                                 bg=self.get_color('surface'),
                                 fg=self.get_color('danger'))
            error_label.pack(expand=True, padx=20, pady=20)
    
    def generate_pdf_report(self):
        # Generar un reporte PDF con manejo de errores
        try:
            # Crear un archivo PDF
            pdf_file = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
            if not pdf_file:
                return

            # Obtener datos estadísticos de la base de datos
            if self.db_connection is None:
                messagebox.showerror("Error", "No hay conexión a la base de datos")
                return
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            total_scanned = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE is_infected = 1")
            total_infected = cursor.fetchone()[0]

            # Calcular estadísticas
            total_safe = total_scanned - total_infected
            infection_rate = (total_infected / total_scanned * 100) if total_scanned > 0 else 0

            # Crear el contenido del PDF
            c = canvas.Canvas(pdf_file, pagesize=letter)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(100, 750, "Reporte Estadístico de Escaneos - Bot Python")
            c.setFont("Helvetica", 12)
            c.drawString(100, 720, f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(100, 690, f"Total de Archivos Escaneados: {total_scanned}")
            c.drawString(100, 670, f"Archivos Seguros: {total_safe}")
            c.drawString(100, 650, f"Archivos Infectados: {total_infected}")
            c.drawString(100, 630, f"Tasa de Infección: {infection_rate:.2f}%")

            # Finalizar y guardar el PDF
            c.save()
            messagebox.showinfo("Reporte PDF", f"Reporte generado exitosamente en: {pdf_file}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el reporte PDF: {e}")

    def generate_csv_report(self):
        # Generar un reporte CSV con manejo de errores
        try:
            # Crear un archivo CSV
            csv_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if not csv_file:
                return

            with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["Archivo", "Estado", "Fecha"])

                # Obtener datos de la base de datos
                if self.db_connection is None:
                    messagebox.showerror("Error", "No hay conexión a la base de datos")
                    return
                cursor = self.db_connection.cursor()
                cursor.execute("SELECT file_path, is_infected, scan_date FROM scan_history")
                results = cursor.fetchall()

                for file_path, is_infected, scan_date in results:
                    status = "Infectado" if is_infected else "Seguro"
                    writer.writerow([file_path, status, scan_date])

            messagebox.showinfo("Reporte CSV", f"Reporte generado exitosamente en: {csv_file}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el reporte CSV: {e}")

    def log_activity(self, message):
        try:
            # Archivo de logs cifrados
            log_file = "logs_encrypted.txt"

            # Leer logs existentes
            if os.path.exists(log_file):
                with open(log_file, "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = self.cipher.decrypt(encrypted_data).decode("utf-8")
            else:
                decrypted_data = ""

            # Agregar nuevo mensaje
            decrypted_data += f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n"

            # Cifrar y guardar los logs
            encrypted_data = self.cipher.encrypt(decrypted_data.encode("utf-8"))
            with open(log_file, "wb") as file:
                file.write(encrypted_data)
        except Exception as e:
            print(f"Error al registrar actividad: {e}")

    def clear_scan_history(self):
        try:
            # Confirmar la acción con el usuario
            confirm = messagebox.askyesno("Confirmar", "¿Estás seguro de que deseas eliminar todos los registros de escaneos?")
            if not confirm:
                return

            # Limpiar la tabla de historial de escaneos
            if self.db_connection is None:
                messagebox.showerror("Error", "No hay conexión a la base de datos")
                return
            cursor = self.db_connection.cursor()
            cursor.execute("DELETE FROM scan_history")
            self.db_connection.commit()

            messagebox.showinfo("Éxito", "Todos los registros de escaneos han sido eliminados.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron eliminar los registros: {e}")

    def show_submenu(self, menu_name):
        """Mostrar/ocultar submenú con colores modernos"""
        # Reset previous active button color
        if self.active_menu:
            self.menu_buttons[self.active_menu].configure(
                bg=self.get_color('surface'),
                fg=self.get_color('text_primary')
            )
            self.submenu_frames[self.active_menu].pack_forget()

        # If clicking the same menu, just close it
        if self.active_menu == menu_name:
            self.active_menu = None
            return

        # Set new active button with highlight
        self.active_menu = menu_name
        self.menu_buttons[menu_name].configure(
            bg=self.get_color('primary_light'),
            fg="white"
        )

        # Show the submenu
        self.submenu_frames[menu_name].pack(fill=tk.X, pady=2)
    
    def __del__(self):
        # Cerrar la conexión a la base de datos de forma segura
        if hasattr(self, 'db_connection') and self.db_connection:
            self.db_connection.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = BotApp(root)
    root.mainloop()