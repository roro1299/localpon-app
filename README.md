# LocalPON

- Web / servidor: `npm install` y `npm start` -> http://localhost:3000
- MySQL: variables DB_HOST, DB_USER, DB_PASS, DB_NAME. Sin MySQL la app solo puede usarse en "modo local" (un solo dispositivo).
- Android: `npm run sync` y `npm run android` (abre Android Studio). Después Build > Generate App Bundles or APKs > Generate APKs.
- Publicar en internet: definir JWT_SECRET y las variables de MySQL en el servidor. Entrar con el administrador por defecto y cambiar su contraseña de inmediato (o definir ADMIN_EMAIL y ADMIN_PASSWORD).
- Para que la APK use el servidor publicado: poner la URL en PROD_URL (public/index.html) y ejecutar `npm run sync`.

## Cuentas
- No existe el registro público: nadie puede crear una cuenta por su cuenta. Solo el administrador crea o elimina cuentas de empleados, dentro de la app (Cuenta > Cuentas del negocio > + Nueva cuenta).
- Administrador por defecto: cuando el servidor arranca con la base vacía crea la cuenta `admin@localpon.app` con contraseña `LocalPON#2026` (constante `DEFAULT_ADMIN` en server.js). Como esas credenciales están en el código, la app obliga a cambiar la contraseña en el primer inicio de sesión y el servidor bloquea todo lo demás hasta que se cambie.
- Para usar tus propios datos en lugar de los de por defecto, define ADMIN_EMAIL y ADMIN_PASSWORD (y opcionalmente ADMIN_NAME) en el servidor; esa cuenta no pide cambio obligatorio.
- Si un empleado olvida su contraseña, el administrador la cambia en Cuenta > Contraseña. Al cambiarla se cierran sus sesiones abiertas.
- Cualquier cuenta puede cambiar su propia contraseña en Cuenta > Cambiar mi contraseña (cierra las demás sesiones).
- Si el administrador olvida la suya: "¿Olvidaste tu contraseña?" en el login, con el código secreto del servidor (ADMIN_CODE o el que imprime la terminal al iniciar). Tras 5 intentos incorrectos se bloquea 15 minutos.
- Los empleados ven y registran el mismo inventario que el administrador, pero solo ven sus propias ventas.
- Si ya tenías cuentas de pruebas anteriores en MySQL, el administrador por defecto no se crea (solo se crea con la base vacía). Para empezar de cero: `DROP DATABASE localpon;`

## Bloqueo con biometría
- Cuenta > "Activar bloqueo con huella o rostro". La app se bloquea al abrirse y al volver tras 30 segundos en segundo plano.
- Android (APK): huella, rostro o PIN del celular. Web / iPhone (PWA): Face ID, Touch ID o Windows Hello vía WebAuthn.

## Cuenta del propietario sin registrarse (.env)
1. Copia `.env.example` como `.env` y llena `ADMIN_EMAIL`, `ADMIN_PASSWORD` y `JWT_SECRET`.
2. Arranca el servidor con la base vacía: el propietario se crea solo. No hace falta registro.
3. Si ya hay cuentas en la base, estas variables no hacen nada (no se pisa a nadie). Para empezar de cero: `DROP DATABASE localpon;`.
4. Al publicar en un hosting (por ejemplo Railway) pon las mismas variables en su panel de "Variables" en lugar de usar `.env`. El servidor queda encendido siempre; la app solo apunta a su dirección (`PROD_URL`).
5. `.env` es secreto: no lo subas a GitHub. El zip no lo incluye.

## Ventas por vendedor
- Cada venta guarda quién la registró (tomado de la sesión, no editable desde la app).
- El administrador ve en Reportes las ventas de todo su equipo, el total por vendedor y puede filtrar por persona.
- Cada empleado ve únicamente sus propias ventas. El CSV incluye la columna vendedor.

## Aviso de privacidad
- Se muestra en el login, en Cuenta y como pantalla de aceptación después de iniciar sesión (se guarda por cuenta, en el servidor y en el dispositivo).
- Es una plantilla basada en la LFPDPPP. Antes de usarla con clientes: llena `PRIVACY` (responsable, domicilio, correo) al inicio de la sección "aviso de privacidad" en `public/index.html` y que lo revise alguien con conocimiento legal.
- Si cambias el texto, sube `PRIV_VER` y todos tendrán que aceptarlo otra vez.
