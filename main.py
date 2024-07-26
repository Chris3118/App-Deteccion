import psutil
import threading
from tkinter import *
from scapy.all import sniff, TCP, IP
import socket
from plyer import notification
import time

# Puerto específico que queremos monitorear (443 para esta prueba)
target_port = 443

# Intervalo de tiempo para notificaciones (en segundos)
NOTIFICATION_INTERVAL = 600  # 10 minutos

# Flag global para controlar la captura de paquetes
continue_sniffing = True

# Variable global para indicar si hay un diálogo abierto
dialog_open = False

# Variable para indicar si el puerto está cerrado
port_closed = False

# Función de callback para manejar los paquetes capturados
def packet_callback(packet):
    global port_closed
    if port_closed:
        return  # Si el puerto está cerrado, no procesar más paquetes
    
    try:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Imprimir todos los paquetes capturados para depuración
            print(f"Paquete capturado - IP Origen: {src_ip}, IP Destino: {dst_ip}, Puerto Origen: {src_port}, Puerto Destino: {dst_port}, Flags: {flags}")
            
            # Verificar si el puerto de destino es el puerto objetivo
            if dst_port == target_port:
                # Detectar flags SYN (0x02)
                if flags & 0x02:  # SYN
                    print(f"Intento de conexión - IP Origen: {src_ip}, IP Destino: {dst_ip}, Puerto Origen: {src_port}, Puerto Destino: {dst_port}")
                    send_notification(f"Intento de conexión detectado en el puerto {dst_port}", src_ip, dst_ip, dst_port)
                
    except Exception as e:
        print(f"Error capturando paquete: {e}")

# Función para enviar una notificación
def send_notification(message, src_ip, dst_ip, dst_port):
    global dialog_open
    try:
        print(f"Enviando notificación: {message}")  # Mensaje de depuración
        notification.notify(
            title="Alerta de Seguridad",
            message=message,
            timeout=10,
            app_name="Security App"
        )
        # Mostrar diálogo con información de la alerta solo si no hay otro diálogo abierto
        if not dialog_open:
            show_alert_dialog(src_ip, dst_ip, dst_port)
    except Exception as e:
        print(f"Error enviando notificación: {e}")

# Función para mostrar cuadro de diálogo con opciones
def show_alert_dialog(src_ip, dst_ip, dst_port):
    global dialog_open
    dialog_open = True

    dialog = Tk()
    dialog.title("Alerta de Seguridad")

    label = Label(dialog, text=f"Actividad sospechosa detectada:\nIP Origen: {src_ip}\nIP Destino: {dst_ip}\nPuerto: {dst_port}")
    label.pack(pady=10)

    def ignore_action():
        global dialog_open
        dialog_open = False
        dialog.destroy()

    def close_connection():
        global dialog_open
        global port_closed
        close_connections_on_port(target_port)
        port_closed = True  # Marcar el puerto como cerrado
        dialog_open = False
        dialog.destroy()

    ignore_button = Button(dialog, text="Ignorar", command=ignore_action, width=20)
    ignore_button.pack(pady=5)

    close_button = Button(dialog, text="Cerrar Conexión", command=close_connection, width=20)
    close_button.pack(pady=5)

    dialog.mainloop()

# Función para cerrar todas las conexiones en un puerto específico
def close_connections_on_port(port):
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port:
                conn_pid = conn.pid
                if conn_pid:
                    p = psutil.Process(conn_pid)
                    p.terminate()
                    print(f"Proceso {conn_pid} terminado, cerrando conexión en el puerto {port}")
    except Exception as e:
        print(f"Error cerrando conexiones en el puerto {port}: {e}")

# Función para capturar los paquetes en un hilo separado
def start_sniffing():
    global continue_sniffing
    try:
        print("Iniciando captura de paquetes")  # Mensaje de depuración
        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not continue_sniffing)
    except Exception as e:
        print(f"Error en la captura de paquetes: {e}")

# Función para iniciar la captura de paquetes y mostrar notificación
def start_capture():
    global continue_sniffing
    continue_sniffing = True
    capture_thread = threading.Thread(target=start_sniffing)
    capture_thread.daemon = True
    capture_thread.start()
    print("Captura de paquetes iniciada en segundo plano")  # Mensaje de depuración

# Función para detener la captura de paquetes
def stop_capture():
    global continue_sniffing
    continue_sniffing = False
    print("Captura de paquetes detenida")  # Mensaje de depuración
    # No enviar notificación al detener la captura

# Ventana de elección de modo
def show_mode_choice_window():
    def on_background_choice():
        start_capture()
    
    def on_gui_choice():
        start_gui()

    main_window = Tk()
    main_window.title("Control de Ejecución")
    main_window.geometry("400x200")

    label = Label(main_window, text="¿Cómo desea ejecutar la aplicación?")
    label.pack(pady=20)

    button_background = Button(main_window, text="Segundo Plano", command=on_background_choice, height=2, width=20)
    button_background.pack(pady=10)

    button_gui = Button(main_window, text="Interfaz de Usuario", command=on_gui_choice, height=2, width=20)
    button_gui.pack(pady=10)

    def on_closing():
        stop_capture()
        main_window.destroy()

    main_window.protocol("WM_DELETE_WINDOW", on_closing)
    main_window.mainloop()

# Iniciar la ventana de elección de modo
if _name_ == "_main_":
    show_mode_choice_window()