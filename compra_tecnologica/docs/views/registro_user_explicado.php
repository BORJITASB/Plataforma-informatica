<?php
// Vista: registro_user.php (formulario de creación de cuenta de usuario)
// Recolecta correo, nombre y contraseña + confirmación. Usa fetch hacia registro_usuario.php.

session_start(); // Puede usarse para mensajes o manejo de estado.
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro Usuario</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"> <!-- Bootstrap -->
    <link rel="stylesheet" href="../assets/css/app.css"> <!-- Tema global -->
</head>
<body class="app-body">
<div class="overlay"></div> <!-- Fondo animado -->
<main class="container py-5 position-relative" style="z-index:2;">
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-5">
            <div class="glass-card p-4">
                <h1 class="text-center mb-4">Crear Cuenta</h1>
                <form id="registroUsuarioForm" novalidate> <!-- Form manejado por JS -->
                    <div class="mb-3">
                        <label for="correo" class="form-label">Correo</label>
                        <input type="email" class="form-control" id="correo" required>
                    </div>
                    <div class="mb-3">
                        <label for="nombre" class="form-label">Nombre</label>
                        <input type="text" class="form-control" id="nombre" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Contraseña</label>
                        <input type="password" class="form-control" id="password" required>
                    </div>
                    <div class="mb-3">
                        <label for="confirm_password" class="form-label">Confirmar Contraseña</label>
                        <input type="password" class="form-control" id="confirm_password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Registrar</button>
                </form>
                <div id="mensaje" class="mt-3 text-center small"></div> <!-- Mensajes -->
                <hr class="border-light">
                <div class="text-center">
                    <a href="login.php" class="link-light">Volver al Login</a>
                </div>
            </div>
        </div>
    </div>
</main>
<script src="../assets/js/registro_user.js"></script> <!-- Lógica fetch registro usuario -->
</body>
</html>
