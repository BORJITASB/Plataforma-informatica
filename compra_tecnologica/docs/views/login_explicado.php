<?php
// Vista: login.php (formulario de autenticación de usuarios)
// Presenta formulario de acceso y enlaces a registro. Usa estilos unificados (app.css).

session_start(); // Inicia sesión para manejar mensajes o redirecciones futuras.

// Si ya está autenticado, podríamos redirigir (opcional no implementado aquí).
?>
<!DOCTYPE html> <!-- Declara documento HTML5 -->
<html lang="es"> <!-- Idioma español para accesibilidad y SEO -->
<head>
    <meta charset="UTF-8"> <!-- Codificación UTF-8 -->
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> <!-- Responsive -->
    <title>Login</title> <!-- Título pestaña -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"> <!-- Bootstrap 5 -->
    <link rel="stylesheet" href="../assets/css/app.css"> <!-- Estilos globales -->
</head>
<body class="app-body"> <!-- Clase base del tema -->
<div class="overlay"></div> <!-- Capa decorativa (no bloquea eventos) -->
<main class="container py-5 position-relative" style="z-index:2;"> <!-- Contenedor central -->
    <div class="row justify-content-center"> <!-- Centra contenido -->
        <div class="col-md-5"> <!-- Ancho medio -->
            <div class="glass-card p-4"> <!-- Tarjeta con efecto glass -->
                <h1 class="text-center mb-4">Iniciar Sesión</h1> <!-- Encabezado -->
                <form id="loginForm" novalidate> <!-- Form sin validación HTML5 por fetch -->
                    <div class="mb-3"> <!-- Grupo campo -->
                        <label for="correo" class="form-label">Correo</label> <!-- Etiqueta -->
                        <input type="email" class="form-control" id="correo" required> <!-- Input correo -->
                    </div>
                    <div class="mb-3"> <!-- Grupo password -->
                        <label for="password" class="form-label">Contraseña</label> <!-- Etiqueta -->
                        <input type="password" class="form-control" id="password" required> <!-- Input password -->
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Entrar</button> <!-- Botón enviar -->
                </form>
                <div id="mensaje" class="mt-3 text-center small"></div> <!-- Área mensajes -->
                <hr class="border-light"> <!-- Separador -->
                <div class="text-center"> <!-- Enlaces inferiores -->
                    <a href="registro.php" class="link-light d-block mb-2">Registrar Producto</a> <!-- Link registro producto -->
                    <a href="registro_user.php" class="link-light">Crear Cuenta Usuario</a> <!-- Link registro usuario -->
                </div>
            </div>
        </div>
    </div>
</main>
<script src="../assets/js/login.js"></script> <!-- Lógica fetch login -->
</body>
</html>
