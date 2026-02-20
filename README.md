# Portal de Certificados WiFi

Aplicacion web para gestionar solicitud, aprobacion y entrega de certificados WiFi (.p12) para autenticacion EAP-TLS. Se integra con PacketFence v15 via REST API.

## Prerrequisitos

- Docker y Docker Compose
- PacketFence v15 con API REST habilitada y PKI configurado
- Un perfil de certificado PKI creado en PacketFence
- (Opcional) Certificado raiz CA de PacketFence para que los clientes confien en la red

## Configuracion rapida

### 1. Generar FERNET_KEY

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Crear archivo .env

```bash
cp .env.example .env
```

Editar `.env` con tus valores:
- `SECRET_KEY`: clave secreta para JWT (minimo 32 caracteres)
- `FERNET_KEY`: clave generada en el paso anterior
- `SUPERADMIN_USERNAME` / `SUPERADMIN_PASSWORD`: credenciales del primer administrador
- `PF_HOST`: URL de PacketFence (ej: `https://pf.midominio.com:9999`)
- `PF_USERNAME` / `PF_PASSWORD`: credenciales API de PacketFence
- `PF_CERT_PROFILE`: nombre del perfil PKI en PacketFence

### 3. Desplegar

```bash
docker-compose up -d --build
```

La aplicacion estara disponible en `http://localhost:8000`.

## Despliegue en Coolify

1. Crear nuevo servicio desde repositorio Git
2. Configurar las variables de entorno en la seccion "Environment"
3. Montar volumenes persistentes:
   - `./data` -> `/app/data` (base de datos SQLite)
   - `./certs` -> `/app/certs` (archivos .p12)
4. Configurar puerto expuesto: `8000`
5. Deploy

## Primer login

1. Acceder a `http://tu-dominio:8000`
2. Iniciar sesion con las credenciales de superadmin configuradas en `.env`
3. Ir a **Configuracion** para verificar la conexion con PacketFence
4. Ir a **Usuarios** para crear cuentas de empleados y alumnos

## Flujo completo

1. **Alumno** inicia sesion y solicita un certificado desde su panel
2. **Empleado** ve la solicitud pendiente en su panel y la aprueba o rechaza
3. Al aprobar, el sistema:
   - Genera una contrasena de 16 caracteres
   - Llama a PacketFence para crear el certificado
   - Guarda el archivo .p12 y cifra la contrasena con Fernet
   - Genera un token de descarga unico
4. **Alumno** ve el estado "Aprobada" y accede al enlace de descarga
5. En la pagina de descarga:
   - Se muestra la contrasena del certificado (copiar antes de descargar)
   - Se descarga el archivo .p12 (la descarga solo funciona una vez)
6. **Empleado** puede revocar certificados en cualquier momento

## Certificado raiz CA

Para que los dispositivos confien en la red WiFi con EAP-TLS, es necesario distribuir el certificado raiz CA de PacketFence. Este se puede descargar desde la interfaz de administracion de PacketFence en la seccion PKI.

## Estructura del proyecto

```
cert-portal/
  app/
    __init__.py
    config.py          # Settings con pydantic-settings
    database.py        # SQLAlchemy async
    models.py          # User, CertRequest, ActivityLog, AppSetting
    schemas.py         # Modelos Pydantic
    auth.py            # JWT, bcrypt, Fernet
    main.py            # FastAPI app + lifespan
    routes/
      auth.py          # Login/logout
      student.py       # Panel alumno + descarga
      employee.py      # Aprobar/rechazar/revocar + usuarios
      superadmin.py    # Config PF + logs
    services/
      device_detection.py  # Deteccion OS/movil
      packetfence.py       # Cliente async PF
    templates/
      base.html
      login.html
      student/
        dashboard.html
        download.html
      employee/
        dashboard.html
        users.html
        settings.html
        logs.html
  data/               # SQLite (volumen)
  certs/              # Archivos .p12 (volumen)
  Dockerfile
  docker-compose.yml
  requirements.txt
  .env.example
```
