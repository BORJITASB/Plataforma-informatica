<?php
// Vista: registro.php (formulario para registrar productos vía AJAX)
// Permite ingresar nombre, descripción y categoría (ID numérico simple).

session_start(); // Sesión (podría usarse para CSRF o auth futura).
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro Producto</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/css/app.css"> <!-- Tema global -->
</head>
<body class="app-body">
<div class="overlay"></div> <!-- Fondo visual -->
<main class="container py-5 position-relative" style="z-index:2;">
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-5">
            <div class="glass-card p-4">
                <h1 class="text-center mb-4">Registrar Producto</h1>
                <form id="registroForm" novalidate> <!-- JS controla envío -->
                    <div class="mb-3">
                        <label for="nombre" class="form-label">Nombre</label>
                        <input type="text" class="form-control" id="nombre" required>
                    </div>
                    <div class="mb-3">
                        <label for="descripcion" class="form-label">Descripción</label>
                        <textarea class="form-control" id="descripcion" rows="3" required></textarea>
                    </div>
                    <div class="mb-3">
                        <label for="id_categoria" class="form-label">ID Categoría</label>
                        <input type="number" class="form-control" id="id_categoria" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Guardar</button>
                </form>
                <div id="mensaje" class="mt-3 text-center small"></div> <!-- Mensajes -->
                <hr class="border-light">
                <div class="text-center">
                    <a href="login.php" class="link-light">Ir a Login</a>
                </div>
            </div>
        </div>
    </div>
</main>
<script src="../assets/js/registro.js"></script> <!-- Lógica fetch producto -->
</body>
</html>
