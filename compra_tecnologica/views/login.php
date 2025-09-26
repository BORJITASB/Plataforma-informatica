
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Iniciar Sesión</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="../assets/css/app.css" rel="stylesheet">
</head>
<body class="app-body">
    <div class="app-wrapper container">
        <div class="nav-top">
            <div class="brand-mini">Compra Tecnológica</div>
            <a href="../public/index.php">Inicio</a>
            <a href="catalogo.php">Catálogo</a>
            <a class="active" href="login.php">Login</a>
        </div>
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-5">
                <div class="glass-box">
                    <h1 class="glass-title">Acceso Administrador</h1>
                    <form id="formLogin" novalidate>
                        <div class="mb-3">
                            <label for="correo" class="form-label">Correo</label>
                            <input type="email" class="form-control" id="correo" name="correo" required>
                        </div>
                        <div class="mb-3">
                            <label for="contrasena" class="form-label">Contraseña</label>
                            <input type="password" class="form-control" id="contrasena" name="contrasena" required>
                        </div>
                        <button type="submit" class="btn btn-soft w-100">Ingresar</button>
                        <div id="mensaje" class="mt-3"></div>
                        <p class="mt-3 mb-0 small">¿No tienes cuenta? <a class="link-light-mini" href="registro_user.php">Regístrate aquí</a></p>
                    </form>
                </div>
            </div>
        </div>
        <div class="footer-simple">&copy; <?= date('Y') ?> Compra Tecnológica</div>
    </div>
    <script src="../assets/js/login.js"></script>
</body>
</html>