# PacketFence API - Referencia para el Portal de Certificados WiFi

Documentacion basada en pruebas reales contra PacketFence en `192.168.90.20:9999`.

## Conexion

- **Base URL**: `https://{host}:9999/api/v1`
- **SSL**: El servidor usa certificado autofirmado, requiere `verify=False`
- **Proxy**: La API pasa por Caddy (reverse proxy)

## Autenticacion

### Login

```
POST /api/v1/login
Content-Type: application/json

{"username": "admin", "password": "..."}
```

**Response:**
```json
{"token": "571f079098aefe5ea3e4315408db6ef83b9086942e695b5b992f51ac739a1cd2"}
```

El token se usa en todas las requests posteriores:
```
Authorization: Bearer {token}
```

El token se renueva automaticamente (la cookie `Set-Cookie: token=...` con `Max-Age=90000` lo confirma).
Si una request devuelve 401, hacer login de nuevo.

---

## PKI - Certificados

### Listar perfiles PKI

```
GET /api/v1/pki/profiles
```

**Response:**
```json
{
  "status": 0,
  "items": [
    {
      "ID": 1,
      "name": "Radius-Server",
      "ca_id": "1",
      "ca_name": "Tec-Ser-Root-CA",
      "validity": "3650",
      "key_size": "4096",
      ...
    },
    {
      "ID": 4,
      "name": "radius-client-2",
      "ca_id": "1",
      "validity": "1095",
      "key_size": "2048",
      "allow_duplicated_cn": 1,
      ...
    }
  ],
  "total_count": 4
}
```

**Perfiles disponibles:**

| ID | Nombre | Uso | Key Size | Validez |
|----|--------|-----|----------|---------|
| 1 | Radius-Server | Certificados de servidor RADIUS | 4096 | 3650 dias |
| 2 | wifi-client | Certificados de clientes WiFi | 4096 | 3650 dias |
| 3 | radius-server-2 | Servidor RADIUS (alternativo) | 2048 | 1095 dias |
| 4 | radius-client-2 | Clientes WiFi (alternativo, permite CN duplicado) | 2048 | 1095 dias |

Para el portal usamos **`radius-client-2` (ID: 4)** porque permite CN duplicado y usa keys mas livianas.

### Crear certificado (2 pasos)

#### Paso 1: Crear el cert

```
POST /api/v1/pki/certs
Content-Type: application/json

{
  "cn": "nombre-unico",
  "mail": "usuario@ejemplo.com",
  "profile_id": "4",
  "p12_password": "password-para-el-p12"
}
```

> **IMPORTANTE**: `profile_id` debe ser un **string**, no un entero. Si se envia como int, PF devuelve error 500.

**Response (status HTTP 200, campo status 422 — quirk de PF):**
```json
{
  "status": 422,
  "items": [
    {
      "ID": 12,
      "cn": "nombre-unico",
      "mail": "usuario@ejemplo.com",
      "ca_id": 1,
      "ca_name": "Tec-Ser-Root-CA",
      "cert": "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----\n",
      "profile_id": "4",
      "profile_name": "radius-client-2",
      "valid_until": "2029-02-22T22:54:04.16-03:00",
      "serial_number": "12"
    }
  ],
  "serial": "12"
}
```

> **Nota**: El `status: 422` en el JSON es un quirk — el certificado SI se crea correctamente. Verificar que `items` contenga al menos un elemento con `ID`.

**Campos clave del response:**
- `items[0].ID` — ID del certificado en PF (usar para descargar y revocar)
- `items[0].cert` — Certificado en formato PEM (no incluye clave privada)
- `items[0].serial_number` — Numero de serie
- `serial` — Igual al serial_number (nivel top)

**Campos que NO devuelve:**
- No devuelve `p12`, `pkcs12`, `key`, ni `private_key`
- El .p12 se obtiene en un paso separado

#### Paso 2: Descargar el .p12

```
GET /api/v1/pki/cert/{ID}/download/p12
```

> **IMPORTANTE**: Usar `/cert/` (singular), no `/certs/` (plural). El endpoint plural devuelve 200 con body vacio.

**Response:** Binario PKCS#12 directo (Content-Type: application/json pero el body es binario).

Los primeros bytes son `30 82` (firma ASN.1 de PKCS#12).

**Ejemplo de tamanio tipico:** ~4375 bytes.

### Consultar un certificado

```
GET /api/v1/pki/cert/{ID}
```

**Response:**
```json
{
  "status": 0,
  "items": [
    {
      "ID": 4,
      "cn": "test-portal-001",
      "mail": "test@cert.local",
      "cert": "-----BEGIN CERTIFICATE-----\n...",
      "profile_id": 4,
      "valid_until": "2029-02-22T22:54:04.16-03:00",
      "not_before": "2026-02-23T22:54:04.16-03:00",
      "serial_number": "4",
      "scep": false,
      "csr": false,
      "alert": false
    }
  ]
}
```

### Listar todos los certificados

```
GET /api/v1/pki/certs
```

Devuelve todos los certs activos con `total_count`.

### Revocar certificado

> **Estado actual: NO FUNCIONA via API** en esta version de PF.

Endpoints probados que devuelven 200 pero no revocan:

```
DELETE /api/v1/pki/cert/{ID}              con {"reason": 2}
POST   /api/v1/pki/cert/{ID}/revoke      con {"reason": 2}
POST   /api/v1/pki/certs/{ID}/revoke     con {"reason": "cessationOfOperation"}
PATCH  /api/v1/pki/cert/{ID}             con {"revoked": true}
```

Todos devuelven `HTTP 200` con `Content-Length: 0` pero el certificado no aparece en `/api/v1/pki/revokedcerts`.

**Workaround:** El portal marca el certificado como revocado localmente, elimina el .p12 del servidor, e intenta el DELETE como best-effort. La revocacion real debe hacerse desde la interfaz web de PF.

### Listar certificados revocados

```
GET /api/v1/pki/revokedcerts
```

### Listar CAs

```
GET /api/v1/pki/cas
GET /api/v1/pki/ca/{ID}
```

**CA configurada:**
- ID: 1, CN: `Tec-Ser-Root-CA`, Org: `Tec-Ser`, Validez: 3650 dias

---

## Roles (Categorias)

Los roles en PF definen categorias que se asignan a nodos (dispositivos). Cada role se mapea a una VLAN en la configuracion del switch.

### Listar roles

```
GET /api/v1/config/roles
```

**Response:**
```json
{
  "items": [
    {
      "id": "default",
      "notes": "Placeholder role/category, feel free to edit",
      "inherit_vlan": "disabled",
      "max_nodes_per_pid": "0",
      ...
    }
  ]
}
```

**Roles actuales:**

| ID (nombre) | Descripcion |
|---|---|
| default | Role por defecto |
| guest | Invitados |
| gaming | Dispositivos gaming |
| voice | Dispositivos VoIP |
| REJECT | Bloquear acceso |
| User | Role de usuario |
| Machine | Role de maquina |

### Crear role

```
POST /api/v1/config/roles
Content-Type: application/json

{"id": "nombre-del-role", "notes": "Descripcion"}
```

**Response:**
```json
{"id": "nombre-del-role", "message": "'nombre-del-role' created", "status": 201}
```

> Al crear un role, PF automaticamente crea una `node_category` asociada con un `category_id` numerico.

### Eliminar role

```
DELETE /api/v1/config/role/{id}
```

**Response:**
```json
{"message": "Deleted nombre-del-role successfully", "status": 200}
```

### Node Categories

Las node categories son la representacion interna de los roles con IDs numericos.

```
GET /api/v1/node_categories
```

**Response:**
```json
{
  "items": [
    {"category_id": "1", "name": "default"},
    {"category_id": "2", "name": "guest"},
    {"category_id": "5", "name": "REJECT"}
  ]
}
```

El `category_id` es lo que se usa al registrar nodos.

---

## Users (Personas)

Los users en PF representan personas (identificadas por `pid`). No confundir con los usuarios del portal.

### Listar users

```
GET /api/v1/users
```

### Crear user

```
POST /api/v1/users
Content-Type: application/json

{
  "pid": "identificador-unico",
  "email": "email@ejemplo.com",
  "firstname": "Nombre",
  "lastname": "Apellido"
}
```

> **Nota**: El campo `category` en la creacion de users NO se asigna correctamente via API. La categoria se controla a nivel de **nodo**, no de user.

### Eliminar user

```
DELETE /api/v1/user/{pid}
```

### Actualizar user

> **NO FUNCIONA**: `PATCH /api/v1/user/{pid}` y `PUT /api/v1/user/{pid}` devuelven 404 con "Cannot update". Para cambiar datos, borrar y recrear.

---

## Nodos (Dispositivos)

Los nodos son dispositivos identificados por MAC address. La asignacion de VLAN se hace a nivel de nodo via `category_id`.

### Listar nodos

```
GET /api/v1/nodes?limit=10
```

**Campos clave de un nodo:**
```json
{
  "mac": "00:11:22:33:44:55",
  "pid": "usuario-asociado",
  "category_id": 8,
  "status": "reg",
  "bypass_role_id": null,
  "bypass_vlan": "",
  "computername": "LAPTOP-NOMBRE"
}
```

### Registrar nodo

```
POST /api/v1/nodes
Content-Type: application/json

{
  "mac": "00:11:22:33:44:55",
  "pid": "identificador-usuario",
  "category_id": "8",
  "status": "reg",
  "notes": "Registrado desde portal"
}
```

- `category_id`: ID numerico de la node_category (role)
- `status`: `"reg"` para registrado, `"unreg"` para no registrado
- `pid`: Referencia al user PF

### Eliminar nodo

```
DELETE /api/v1/node/{mac}
```

---

## Switches - Mapeo Role a VLAN

El mapeo de roles a VLANs se configura por switch.

### Ver configuracion de switch

```
GET /api/v1/config/switch/{id}
GET /api/v1/config/switch/default
```

**Campos relevantes:**
```json
{
  "id": "default",
  "type": "...",
  "VlanMap": "Y",
  "VlanMapping": [
    {"role": "REJECT", "vlan": "-1"},
    {"role": "normal", "vlan": "1"},
    {"role": "registration", "vlan": "2"},
    {"role": "isolation", "vlan": "3"},
    {"role": "voice", "vlan": "5"},
    {"role": "inline", "vlan": "6"}
  ],
  "RoleMap": "N",
  "ControllerRoleMapping": [...]
}
```

### Switches configurados

| ID | Tipo | Uso |
|----|------|-----|
| default | (base) | Configuracion por defecto |
| 192.168.0.1 | Cisco::Cisco_IOS_15_0 | Switch/Router |
| 192.168.88.176 | PacketFence::Standard | PF Standard |
| 192.168.1.0/24 | Cisco::Cisco_WLC_AireOS | Wireless LAN Controller |

---

## Flujo completo: Certificado + Grupo + VLAN

```
1. Crear role en PF           POST /config/roles        {"id": "alumnos-lab"}
2. Obtener category_id        GET  /node_categories     -> category_id: 8
3. Mapear role->VLAN en switch PATCH /config/switch/X    VlanMapping += {"role": "alumnos-lab", "vlan": "90"}
4. Crear user PF               POST /users              {"pid": "alumno-001", ...}
5. Crear certificado           POST /pki/certs           {"cn": "alumno-001-1", "profile_id": "4", ...}
6. Descargar .p12              GET  /pki/cert/{ID}/download/p12
7. Registrar nodo con role     POST /nodes              {"mac": "...", "pid": "alumno-001", "category_id": "8"}
```

Cuando el alumno se conecta al WiFi con el certificado:
- RADIUS valida el cert contra PF
- PF identifica el nodo por MAC
- PF ve que el nodo tiene `category_id: 8` (role: `alumnos-lab`)
- El switch mapea el role a VLAN 90
- El alumno queda en la VLAN correcta

---

## Endpoints que NO funcionan en esta version

| Endpoint | Problema |
|---|---|
| `DELETE /pki/cert/{id}` | Devuelve 200 pero no revoca ni elimina |
| `POST /pki/cert/{id}/revoke` | Devuelve 200 con body vacio, no revoca |
| `PATCH /user/{pid}` | Devuelve 404 "Cannot update" |
| `PUT /user/{pid}` | Devuelve 404 "Cannot update" |
| `GET /pki/certs/{id}/download/p12` (plural) | Devuelve 200 con body vacio |

## Notas importantes

- Los IDs de profile (`profile_id`) deben enviarse como **string**, no como int
- El endpoint de download usa `/cert/` (singular): `/api/v1/pki/cert/{ID}/download/p12`
- La creacion de certs devuelve `status: 422` en el JSON pero el cert SI se crea
- La revocacion debe hacerse manualmente desde la interfaz web de PF
- Los updates de users PF no funcionan; para modificar hay que borrar y recrear
