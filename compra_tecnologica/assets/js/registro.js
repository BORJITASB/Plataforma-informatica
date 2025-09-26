// --- FUNCIÓN PRINCIPAL DE INICIALIZACIÓN ---
// Al cargar la página, se inicializa el registro y se asigna el evento submit al formulario.
window.addEventListener('DOMContentLoaded', inicializarRegistro);

// --- FUNCIÓN PARA INICIALIZAR EL EVENTO DEL FORMULARIO ---
function inicializarRegistro() {
    // Asigna la función enviarFormulario al evento submit del formulario de registro
    document.getElementById('formRegistro').addEventListener('submit', enviarFormulario);
}

// --- FUNCIÓN PARA OBTENER LOS DATOS DEL FORMULARIO ---
function obtenerDatosFormulario() {
    // Retorna un objeto con los valores de los campos del formulario
    return {
        nombre: document.getElementById('nombre').value.trim(),
        descripcion: document.getElementById('descripcion').value.trim(),
        id_categoria: document.getElementById('categoria').value
    };
}

// --- FUNCIÓN PARA MOSTRAR MENSAJES AL USUARIO ---
function mostrarMensaje(mensaje, tipo = 'success') {
    // Busca el div donde se mostrarán los mensajes, o lo crea si no existe
    let div = document.getElementById('mensaje');
    if (!div) {
        div = document.createElement('div');
        div.id = 'mensaje';
        div.className = 'mt-3';
        document.getElementById('formRegistro').appendChild(div);
    }
    // Asigna el mensaje y la clase de Bootstrap según el tipo (success, danger, etc.)
    div.textContent = mensaje;
    div.className = `alert alert-${tipo} mt-3`;
}

// --- FUNCIÓN PRINCIPAL PARA ENVIAR EL FORMULARIO ---
async function enviarFormulario(event) {
    event.preventDefault(); // Previene el envío tradicional del formulario

    const datos = obtenerDatosFormulario(); // Obtiene los datos del formulario

    // Validación básica: verifica que todos los campos estén completos
    if (!datos.nombre || !datos.descripcion || !datos.id_categoria) {
        mostrarMensaje('Todos los campos son obligatorios.', 'danger');
        return;
    }

    try {
        // Envía los datos al backend usando fetch y formato JSON
        const respuesta = await fetch('../controllers/registro.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(datos)
        });
        const resultado = await respuesta.json(); // Espera la respuesta en formato JSON

        // Muestra el mensaje recibido del backend
        if (resultado.status === 'ok') {
            mostrarMensaje(resultado.message, 'success');
            document.getElementById('formRegistro').reset(); // Limpia el formulario si fue exitoso
        } else {
            mostrarMensaje(resultado.message, 'danger');
        }
    } catch (error) {
        // Si ocurre un error en la petición, muestra un mensaje de error
        mostrarMensaje('Error al registrar el producto.', 'danger');
    }
}

