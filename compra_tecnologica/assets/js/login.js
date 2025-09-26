window.addEventListener('DOMContentLoaded', () => {
    document.getElementById('formLogin').addEventListener('submit', enviarLogin);
});

function mostrarMensajeLogin(mensaje, tipo = 'danger') {
    const div = document.getElementById('mensaje');
    div.textContent = mensaje;
    div.className = `alert alert-${tipo} mt-3`;
}

async function enviarLogin(event) {
    event.preventDefault();

    const correo = document.getElementById('correo').value.trim();
    const contrasena = document.getElementById('contrasena').value;

    if (!correo || !contrasena) {
        mostrarMensajeLogin('Todos los campos son obligatorios.');
        return;
    }

    try {
        const res = await fetch('../controllers/login.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ correo, contrasena })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            mostrarMensajeLogin('Ingreso exitoso. Redirigiendo...', 'success');
            setTimeout(() => {
                if (data.rol === 'admin') {
                    window.location.href = '../views/admin_dashboard.php';
                } else {
                    // Redirigir a catálogo para usuarios no administradores
                    window.location.href = '../views/catalogo.php';
                }
            }, 1200);
        } else {
            mostrarMensajeLogin(data.message, 'danger');
        }
    } catch (err) {
        mostrarMensajeLogin('Error al iniciar sesión.', 'danger');
    }
}