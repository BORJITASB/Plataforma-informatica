// Archivo: login.js (manejo de formulario de inicio de sesión)
// Envía credenciales vía fetch a controllers/login.php y procesa la respuesta JSON.

const form = document.getElementById('loginForm'); // Referencia al formulario.
const mensajeDiv = document.getElementById('mensaje'); // Contenedor de mensajes.

form.addEventListener('submit', async (e) => { // Escucha envío del formulario.
  e.preventDefault(); // Evita recarga de página.

  const correo = document.getElementById('correo').value.trim(); // Obtiene correo.
  const password = document.getElementById('password').value; // Obtiene password.

  if (!correo || !password) { // Validación mínima.
    mensajeDiv.textContent = 'Complete todos los campos.'; // Mensaje error.
    mensajeDiv.className = 'text-danger'; // Estiliza.
    return; // Detiene flujo.
  }

  try { // Manejo de errores.
    const resp = await fetch('../controllers/login.php', { // Llamada fetch.
      method: 'POST', // Método.
      headers: { 'Content-Type': 'application/json' }, // Cabecera JSON.
      body: JSON.stringify({ correo, password }) // Cuerpo JSON.
    });

    const data = await resp.json(); // Parse JSON respuesta.

    if (data.status === 'ok') { // Si autenticado.
      mensajeDiv.textContent = 'Acceso correcto, redirigiendo...'; // Mensaje éxito.
      mensajeDiv.className = 'text-success'; // Estilo.
      // Redirige según rol.
      if (data.rol === 'admin') { // Rol admin.
        window.location.href = 'admin_dashboard.php'; // Dashboard.
      } else { // Otro rol.
        window.location.href = 'catalogo.php'; // Catálogo.
      }
    } else { // Error credenciales.
      mensajeDiv.textContent = data.message || 'Credenciales inválidas.'; // Mensaje servidor.
      mensajeDiv.className = 'text-danger'; // Estilo.
    }
  } catch (err) { // Error de red.
    mensajeDiv.textContent = 'Error de red o servidor.'; // Mensaje genérico.
    mensajeDiv.className = 'text-danger'; // Estilo.
  }
});
