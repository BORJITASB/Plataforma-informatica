// Archivo: registro.js (registro de productos vía AJAX)
// Envía datos de producto a controllers/registro.php y muestra respuesta.

const formProducto = document.getElementById('registroForm'); // Formulario producto.
const mensaje = document.getElementById('mensaje'); // Contenedor mensajes.

formProducto.addEventListener('submit', async (e) => { // Escucha submit.
  e.preventDefault(); // Evita recarga.

  const nombre = document.getElementById('nombre').value.trim(); // Nombre.
  const descripcion = document.getElementById('descripcion').value.trim(); // Descripción.
  const id_categoria = document.getElementById('id_categoria').value.trim(); // ID categoría.

  if (!nombre || !descripcion || !id_categoria) { // Validación simple.
    mensaje.textContent = 'Complete todos los campos.'; // Error.
    mensaje.className = 'text-danger'; // Estilo.
    return; // Fin.
  }

  try { // Bloque try.
    const resp = await fetch('../controllers/registro.php', { // Fetch.
      method: 'POST', // Método POST.
      headers: { 'Content-Type': 'application/json' }, // Cabecera JSON.
      body: JSON.stringify({ nombre, descripcion, id_categoria }) // Datos producto.
    });

    const data = await resp.json(); // Respuesta JSON.

    if (data.status === 'ok') { // Si éxito.
      mensaje.textContent = data.message; // Mensaje.
      mensaje.className = 'text-success'; // Estilo.
      formProducto.reset(); // Limpia formulario.
    } else { // Si error.
      mensaje.textContent = data.message || 'Error al registrar.'; // Mensaje error.
      mensaje.className = 'text-danger'; // Estilo.
    }
  } catch (err) { // Error red.
    mensaje.textContent = 'Error de red o servidor.'; // Mensaje genérico.
    mensaje.className = 'text-danger'; // Estilo.
  }
});
