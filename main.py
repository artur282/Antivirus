import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import sqlite3
import os
from threading import Thread
import matplotlib.pyplot as plt # type: ignore
from concurrent.futures import ThreadPoolExecutor
import platform
from reportlab.lib.pagesizes import letter # type: ignore
from reportlab.pdfgen import canvas # type: ignore
import csv
from cryptography.fernet import Fernet # type: ignore

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus Python")
        self.root.geometry("700x500")
        self.root.resizable(True, True)

        # Estilo moderno
        self.style = ttk.Style()
        self.set_theme("light")  # Tema por defecto

        # Configuración de la interfaz
        self.frame = ttk.Frame(root, padding=20)
        self.frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Menú
        self.menu = tk.Menu(self.root)
        self.root.config(menu=self.menu)
        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Archivo", menu=self.file_menu)
        self.file_menu.add_command(label="Salir", command=self.root.quit)

        self.view_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Ver", menu=self.view_menu)
        self.view_menu.add_command(label="Historial de Escaneos", command=self.show_scan_history)
        self.view_menu.add_command(label="Dashboard Estadístico", command=self.show_dashboard)

        self.theme_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Tema", menu=self.theme_menu)
        self.theme_menu.add_command(label="Claro", command=lambda: self.set_theme("light"))
        self.theme_menu.add_command(label="Oscuro", command=lambda: self.set_theme("dark"))

        # Menú de Reportes y Registros
        self.report_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Reportes y Registros", menu=self.report_menu)
        self.report_menu.add_command(label="Generar Reporte PDF", command=self.generate_pdf_report)
        self.report_menu.add_command(label="Generar Reporte CSV", command=self.generate_csv_report)
        self.report_menu.add_command(label="Limpiar Registros", command=self.clear_scan_history)

        # Botones
        self.btn_scan_file = ttk.Button(self.frame, text="📄 Escanear Archivo", command=self.scan_file)
        self.btn_scan_file.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.btn_scan_dir = ttk.Button(self.frame, text="📁 Escanear Directorio", command=self.scan_directory)
        self.btn_scan_dir.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.btn_quick_scan = ttk.Button(self.frame, text="⚡ Escaneo Rápido", command=self.quick_scan)
        self.btn_quick_scan.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.btn_full_scan = ttk.Button(self.frame, text="🌍 Escaneo Completo", command=self.full_scan)
        self.btn_full_scan.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.btn_start_scan = ttk.Button(self.frame, text="▶️ Iniciar Escaneo", command=self.start_scan, state="disabled")
        self.btn_start_scan.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.btn_stop_scan = ttk.Button(self.frame, text="⏹️ Detener Escaneo", command=self.stop_scan, state="disabled")
        self.btn_stop_scan.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Barra de progreso
        self.progress = ttk.Progressbar(self.frame, orient="horizontal", length=300, mode="determinate")
        self.progress.grid(row=2, column=0, columnspan=4, pady=10, sticky="ew")

        # Resultados
        self.txt_result = tk.Text(self.frame, height=15, wrap="word")
        self.txt_result.grid(row=3, column=0, columnspan=4, sticky="nsew")

        self.scroll = ttk.Scrollbar(self.frame, orient="vertical", command=self.txt_result.yview)
        self.scroll.grid(row=3, column=4, sticky="ns")
        self.txt_result.configure(yscrollcommand=self.scroll.set)

        # Ajustar tamaño dinámico
        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)
        self.frame.columnconfigure(2, weight=1)
        self.frame.columnconfigure(3, weight=1)
        self.frame.rowconfigure(3, weight=1)

        # Conexión a la base de datos
        try:
            self.db_connection = sqlite3.connect("virus_data.db")
            self.create_tables()
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"No se pudo conectar a la base de datos: {e}")
            self.db_connection = None

        # Variable para almacenar la lista de archivos a escanear
        self.file_list = []
        self.stop_scan = False

        # Generar una clave de cifrado (esto debe hacerse una vez y guardarse de forma segura)
        self.LOG_KEY = Fernet.generate_key()
        self.cipher = Fernet(self.LOG_KEY)

    def create_tables(self):
        # Crear tablas necesarias en la base de datos con manejo de errores
        try:
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
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("INSERT INTO scan_history (file_path, is_infected) VALUES (?, ?)", (file_path, is_infected))
            self.db_connection.commit()
        except sqlite3.Error as e:
            print(f"Error al registrar el resultado del escaneo: {e}")

    def show_scan_history(self):
        # Mostrar el historial de escaneos con manejo de errores
        try:
            history_window = tk.Toplevel(self.root)
            history_window.title("Historial de Escaneos")
            history_window.geometry("600x400")

            tree = ttk.Treeview(history_window, columns=("Archivo", "Infectado", "Fecha"), show="headings")
            tree.heading("Archivo", text="Archivo")
            tree.heading("Infectado", text="Infectado")
            tree.heading("Fecha", text="Fecha")
            tree.pack(fill=tk.BOTH, expand=True)

            cursor = self.db_connection.cursor()
            cursor.execute("SELECT file_path, is_infected, scan_date FROM scan_history")
            for row in cursor.fetchall():
                tree.insert("", tk.END, values=(row[0], "Sí" if row[1] else "No", row[2]))
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"No se pudo cargar el historial de escaneos: {e}")

    def show_heatmap(self):
        # Crear una nueva ventana para el Mapa de Calor
        heatmap_window = tk.Toplevel(self.root)
        heatmap_window.title("Mapa de Calor de Infecciones")
        heatmap_window.geometry("800x600")

        # Obtener datos de la base de datos
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT file_path FROM scan_history WHERE is_infected = 1")
        infected_files = cursor.fetchall()

        print("Archivos infectados obtenidos de la base de datos:", infected_files)  # Depuración

        if not infected_files:
            messagebox.showinfo("Sin datos", "No hay datos disponibles para generar el mapa de calor.")
            heatmap_window.destroy()
            return

        # Contar infecciones por directorio
        directory_counts = {}
        for file_path, in infected_files:
            directory = os.path.dirname(file_path)
            directory_counts[directory] = directory_counts.get(directory, 0) + 1

        print("Conteo de infecciones por directorio:", directory_counts)  # Depuración

        directories = list(directory_counts.keys())
        counts = list(directory_counts.values())

        # Crear el gráfico
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh(directories, counts, color="red")
        ax.set_xlabel("Número de Infecciones")
        ax.set_ylabel("Directorios")
        ax.set_title("Mapa de Calor de Infecciones")
        plt.tight_layout()

        # Integrar el gráfico en la ventana de Tkinter
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg # type: ignore
        canvas = FigureCanvasTkAgg(fig, master=heatmap_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Botón para cerrar la ventana
        ttk.Button(heatmap_window, text="Cerrar", command=heatmap_window.destroy).pack(pady=10)

    def show_dashboard(self):
        # Crear una nueva ventana para el Dashboard
        dashboard_window = tk.Toplevel(self.root)
        dashboard_window.title("Dashboard Estadístico")
        dashboard_window.geometry("800x600")

        # Obtener datos de la base de datos
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        total_scanned = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE is_infected = 1")
        total_infected = cursor.fetchone()[0]

        # Evitar división por cero
        if total_scanned == 0:
            messagebox.showinfo("Sin datos", "No hay datos disponibles para mostrar en el Dashboard.")
            dashboard_window.destroy()  # Cerrar la ventana del Dashboard
            return

        # Datos para el gráfico
        labels = ['Seguros', 'Infectados']
        values = [total_scanned - total_infected, total_infected]
        colors = ['green', 'red']

        # Crear un marco para los controles
        control_frame = ttk.Frame(dashboard_window)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        # Menú desplegable para seleccionar el tipo de gráfico
        chart_type_var = tk.StringVar(value="Gráfico de Cono")  # Valor inicial válido
        chart_types = [
            "Gráfico Circular",  # Asegúrate de que esta opción esté incluida
            "Gráfico de Línea",
            "Gráfico de Área",
            "Gráfico de Cono"
        ]
        ttk.Label(control_frame, text="Seleccionar tipo de gráfico:").pack(side=tk.LEFT, padx=5)
        chart_type_menu = ttk.OptionMenu(control_frame, chart_type_var, *chart_types)
        chart_type_menu.pack(side=tk.LEFT, padx=5)

        # Contenedor para el gráfico
        chart_frame = ttk.Frame(dashboard_window)
        chart_frame.pack(fill=tk.BOTH, expand=True)

        def draw_chart():
            # Limpiar el marco del gráfico
            for widget in chart_frame.winfo_children():
                widget.destroy()

            # Crear el gráfico según el tipo seleccionado
            fig, ax = plt.subplots(figsize=(6, 4))
            chart_type = chart_type_var.get()

            if chart_type == "Gráfico Circular":
                ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
                ax.set_title("Distribución de Archivos Escaneados")
            elif chart_type == "Gráfico de Línea":
                ax.plot(labels, values, marker='o', color='blue')
                ax.set_title("Distribución de Archivos Escaneados")
                ax.set_ylabel("Cantidad")
            elif chart_type == "Gráfico de Área":
                ax.fill_between(labels, values, color='skyblue', alpha=0.5)
                ax.set_title("Distribución de Archivos Escaneados")
                ax.set_ylabel("Cantidad")
            elif chart_type == "Gráfico de Cono":
                ax.bar(labels, values, color='orange', edgecolor='black', linewidth=1.5)
                ax.set_title("Gráfico de Cono (Representación)")
                ax.set_ylabel("Cantidad")
            else:
                # Manejo explícito de gráficos no implementados
                ax.text(0.5, 0.5, "Tipo de gráfico no implementado", ha='center', va='center', fontsize=12)
                ax.axis('off')

            # Mostrar el gráfico en la ventana
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg # type: ignore
            canvas = FigureCanvasTkAgg(fig, master=chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Dibujar el gráfico inicial automáticamente
        chart_type_var.trace_add("write", lambda *args: draw_chart())
        draw_chart()

        # Botón para cerrar el Dashboard
        ttk.Button(dashboard_window, text="Cerrar", command=dashboard_window.destroy).pack(pady=10)

    def set_theme(self, theme):
        # Cambiar entre tema claro y oscuro
        if theme == "light":
            self.style.theme_use("clam")
            self.style.configure("TButton", font=("Arial", 12), background="white")
            self.style.configure("TLabel", font=("Arial", 12), background="white")
            self.style.configure("TFrame", background="white")
        elif theme == "dark":
            self.style.theme_use("clam")
            self.style.configure("TButton", font=("Arial", 12), background="gray")
            self.style.configure("TLabel", font=("Arial", 12), background="gray")
            self.style.configure("TFrame", background="gray")

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
        try:
            cursor = self.db_connection.cursor()
            
            # Verificar si el hash MD5 está en la tabla de virus
            cursor.execute("SELECT COUNT(*) FROM virus_md5 WHERE hash = ?", (hashes['md5'],))
            md5_count = cursor.fetchone()[0]
            
            # Verificar si el hash SHA1 está en la tabla de virus
            cursor.execute("SELECT COUNT(*) FROM virus_sha1 WHERE hash = ?", (hashes['sha1'],))
            sha1_count = cursor.fetchone()[0]
            
            # Verificar si el hash SHA256 está en la tabla de virus
            cursor.execute("SELECT COUNT(*) FROM virus_sha256 WHERE hash = ?", (hashes['sha256'],))
            sha256_count = cursor.fetchone()[0]
            
            # Retornar True si alguno de los hashes coincide con un registro en la base de datos
            return md5_count > 0 or sha1_count > 0 or sha256_count > 0
        except sqlite3.Error as e:
            # Manejo de errores en caso de problemas con la base de datos
            print(f"Error en base de datos: {e}")
            return False

    # Método para escanear un archivo seleccionado por el usuario
    def scan_file(self):
        # Abrir un cuadro de diálogo para seleccionar un archivo
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_list = [file_path]
            self.btn_start_scan.config(state="normal")  # Habilitar el botón "Iniciar"

    # Método para escanear todos los archivos de un directorio seleccionado por el usuario
    def scan_directory(self):
        # Abrir un cuadro de diálogo para seleccionar un directorio
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.file_list = [os.path.join(root, f) for root, _, files in os.walk(dir_path) for f in files]
            self.btn_start_scan.config(state="normal")  # Habilitar el botón "Iniciar"

    def start_scan(self):
        # Iniciar el escaneo con manejo de excepciones
        if self.file_list:
            self.btn_start_scan.config(state="disabled")  # Deshabilitar el botón "Iniciar"
            self.btn_stop_scan.config(state="normal")  # Habilitar el botón "Detener"
            self.txt_result.delete(1.0, tk.END)  # Limpiar resultados
            self.stop_scan = False  # Reiniciar la bandera de detener

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
        self.stop_scan = True  # Activar la bandera para detener el escaneo
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
            messagebox.showinfo("Escaneo rápido", "No se encontraron archivos para escanear en las zonas críticas.")

    # Método para realizar el escaneo de una lista de archivos con multithreading avanzado
    def perform_scan(self, file_list):
        # Realizar el escaneo con manejo de errores y optimización
        try:
            # Deshabilitar los botones al iniciar el escaneo
            self.toggle_buttons("disabled")
            self.progress['value'] = 0
            self.progress_label = ttk.Label(self.frame, text="Escaneando...")
            self.progress_label.grid(row=1, column=2, padx=5, pady=5, sticky="ew")

            total_files = len(file_list)  # Número total de archivos a escanear
            infected_count = 0  # Contador de archivos infectados
            infected_files = []  # Lista de archivos infectados

            def scan_file(file_path):
                nonlocal infected_count
                nonlocal infected_files

                # Verificar si se solicitó detener el escaneo
                if self.stop_scan:
                    return

                # Crear una conexión local a la base de datos para este hilo
                db_connection = sqlite3.connect("virus_data.db")
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
                    if self.stop_scan:
                        break

                    # Actualizar el progreso en la barra de progreso
                    self.update_progress((i / total_files) * 100)

            # Restablecer la barra de progreso al finalizar
            self.update_progress(0)
            self.progress_label.destroy()

            # Habilitar los botones al finalizar el escaneo
            self.toggle_buttons("normal")
            self.btn_stop_scan.config(state="disabled")  # Deshabilitar el botón "Detener"

            if not self.stop_scan:
                if infected_count > 0:
                    self.handle_infected_files(infected_files, infected_count, total_files)
                else:
                    messagebox.showinfo("Escanéo completado", 
                                        f"Archivos escaneados: {total_files}\n"
                                        f"Archivos infectados: {infected_count}")
            else:
                messagebox.showinfo("Escaneo detenido", "El escaneo fue detenido por el usuario.")
        except Exception as e:
            print(f"Error durante el escaneo: {e}")
        finally:
            # Asegurar que los botones se habiliten al finalizar
            self.toggle_buttons("normal")
            self.btn_stop_scan.config(state="disabled")

    def handle_infected_files(self, infected_files, infected_count, total_files):
        # Mostrar opciones para manejar archivos infectados
        response = messagebox.askyesnocancel(
            "Archivos infectados detectados",
            f"Se encontraron {infected_count} archivos infectados de {total_files}.\n"
            "¿Desea moverlos a cuarentena (Sí) o eliminarlos (No)?"
        )
        
        if response is None:
            return
        
        quarantine_dir = "cuarentena"
        if response:  # Mover a cuarentena
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)
            for file in infected_files:
                try:
                    base_name = os.path.basename(file)
                    quarantine_path = os.path.join(quarantine_dir, base_name)
                    if os.path.exists(quarantine_path):
                        quarantine_path = os.path.join(quarantine_dir, f"{base_name}_{int(time.time())}")
                    os.rename(file, quarantine_path)
                except Exception as e:
                    print(f"Error al mover {file} a cuarentena: {e}")
            messagebox.showinfo("Cuarentena", f"Archivos movidos a la carpeta '{quarantine_dir}'.")
        else:  # Eliminar archivos
            for file in infected_files:
                try:
                    os.remove(file)
                except Exception as e:
                    print(f"Error al eliminar {file}: {e}")
            messagebox.showinfo("Eliminación", "Archivos infectados eliminados.")
    
    # Método para realizar el escaneo completo
    def full_scan(self):
        # Escanear todos los archivos del sistema
        self.file_list = []
        for root, _, files in os.walk("/"):
            for file in files:
                self.file_list.append(os.path.join(root, file))

        if self.file_list:
            self.start_scan()
        else:
            messagebox.showinfo("Escaneo completo", "No se encontraron archivos para escanear en el sistema.")
    
    def generate_pdf_report(self):
        # Generar un reporte PDF con manejo de errores
        try:
            # Crear un archivo PDF
            pdf_file = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
            if not pdf_file:
                return

            # Obtener datos estadísticos de la base de datos
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
            c.drawString(100, 750, "Reporte Estadístico de Escaneos - Antivirus Python")
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
            cursor = self.db_connection.cursor()
            cursor.execute("DELETE FROM scan_history")
            self.db_connection.commit()

            messagebox.showinfo("Éxito", "Todos los registros de escaneos han sido eliminados.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron eliminar los registros: {e}")

    def __del__(self):
        # Cerrar la conexión a la base de datos de forma segura
        if self.db_connection:
            self.db_connection.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()