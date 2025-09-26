<?php
// Punto de entrada del proyecto
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Compra Tecnológica - Tu Guía de Productos</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="../assets/css/index.css" rel="stylesheet">
</head>
<body>
    <div class="background-overlay"></div>
    
    <!-- Módulo login fijo en la esquina superior derecha -->
    <div class="login-fixed">
        <h5>¿Eres administrador?</h5>
        <a href="../views/login.php" class="btn btn-tech">Ir al panel de inicio de sesión</a>
    </div>
    
    <div class="container d-flex justify-content-center align-items-center main-content">
        <div class="col-lg-8">
            <section class="hero-section text-center glass h-100 d-flex flex-column justify-content-center">
                <h1 class="tech-title mb-4">Compra Tecnológica</h1>
                <p class="lead mb-4">
                    Descubre, compara y aprende sobre los mejores productos tecnológicos.<br>
                    Nuestra misión es ayudarte a tomar decisiones inteligentes y evitar compras innecesarias.<br>
                    ¡Explora nuestro catálogo y encuentra la mejor opción para ti!
                </p>
                <a href="../views/catalogo.php" class="btn btn-tech btn-lg px-5 mb-3">Ver Catálogo de Productos</a>
            </section>
        </div>
    </div>
    <div class="mt-5 text-center text-muted" style="position:relative;z-index:1;">
        <small>&copy; <?= date('Y') ?> Compra Tecnológica. Todos los derechos reservados-Jean Saavedra.</small>
    </div>
</body>
</html>
