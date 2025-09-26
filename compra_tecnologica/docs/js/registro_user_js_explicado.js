// Archivo: registro_user.js (registro de cuentas de usuario)
// Envía datos del formulario a controllers/registro_usuario.php y gestiona respuestas.

const formUsuario = document.getElementById('registroUsuarioForm'); // Form user.
const mensajeUser = document.getElementById('mensaje'); // Div mensajes.

formUsuario.addEventListener('submit', async (e) => { // Evento submit.
  e.preventDefault(); // Evita recarga.

  const correo = document.getElementById('correo').value.trim(); // Correo.
  const nombre = document.getElementById('nombre').value.trim(); // Nombre.
  const password = document.getElementById('password').value; // Password.
  const confirm_password = document.getElementById('confirm_password').value; // Confirm.

  if (!correo || !nombre || !password || !confirm_password) { // Validación vacíos.
    mensajeUser.textContent = 'Complete todos los campos.'; // Mensaje error.
    mensajeUser.className = 'text-danger'; // Estilo.
    return; // Fin.
}

  if (password !== confirm_password) { // Coincidencia.
    mensajeUser.textContent = 'Las contraseñas no coinciden.'; // Mensaje.
    mensajeUser.className = 'text-danger'; // Estilo.
    return; // Fin.
}

  try { // Bloque try.
    const resp = await fetch('../controllers/registro_usuario.php', { // Fetch.
      method: 'POST', // POST.
      headers: { 'Content-Type': 'application/json' }, // Cabecera.
      body: JSON.stringify({ correo, nombre, password, confirm_password }) // Datos JSON.
    });

    const data = await resp.json(); // Respuesta JSON.

    if (data.status === 'ok') { // Éxito.
      mensajeUser.textContent = data.message + ' Redirigiendo a login...'; // Mensaje.
      mensajeUser.className = 'text-success'; // Estilo.
      setTimeout(() => { // Espera breve.
        window.location.href = 'login.php'; // Redirige.
      }, 1500); // 1.5s.
    } else { // Error lógico.
      mensajeUser.textContent = data.message || 'Error en el registro.'; // Mensaje.
      mensajeUser.className = 'text-danger'; // Estilo.
    }
  } catch (err) { // Error red.
    mensajeUser.textContent = 'Error de red o servidor.'; // Mensaje genérico.
    mensajeUser.className = 'text-danger'; // Estilo.
}
});
