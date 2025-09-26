window.addEventListener('DOMContentLoaded', () => {
    document.getElementById('formRegistroUsuario').addEventListener('submit', enviarRegistroUsuario);
});

function mostrarMensajeRegistro(mensaje, tipo = 'danger') {
    const div = document.getElementById('mensaje');
    div.textContent = mensaje;
    div.className = `alert alert-${tipo} mt-3`;
}

async function enviarRegistroUsuario(event) {
    event.preventDefault();

    const nombre = document.getElementById('nombre').value.trim();
    const correo = document.getElementById('correo').value.trim();
    const contrasena = document.getElementById('contrasena').value;
    const confirmar = document.getElementById('confirmar').value;

    if (!nombre || !correo || !contrasena || !confirmar) {
        mostrarMensajeRegistro('Todos los campos son obligatorios.');
        return;
    }
    if (contrasena !== confirmar) {
        mostrarMensajeRegistro('Las contraseñas no coinciden.');
        return;
    }
    if (!/\S+@\S+\.\S+/.test(correo)) {
        mostrarMensajeRegistro('Correo no válido.');
        return;
    }

    try {
        const res = await fetch('../controllers/registro_usuario.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nombre, correo, contrasena })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            mostrarMensajeRegistro(data.message, 'success');
            document.getElementById('formRegistroUsuario').reset();
        } else {
            mostrarMensajeRegistro(data.message, 'danger');
        }
    } catch (err) {
        mostrarMensajeRegistro('Error en el registro.', 'danger');
    }
}