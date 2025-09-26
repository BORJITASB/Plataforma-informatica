
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Registro de Usuario</title>
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
            <a href="login.php">Login</a>
            <a class="active" href="registro_user.php">Registro</a>
        </div>
        <div class="row justify-content-center">
            <div class="col-md-7 col-lg-6 col-xl-5">
                <div class="glass-box">
                    <h1 class="glass-title">Crear Cuenta</h1>
                    <form id="formRegistroUsuario" novalidate>
                        <div class="mb-3">
                            <label for="nombre" class="form-label">Nombre</label>
                            <input type="text" class="form-control" id="nombre" name="nombre" required>
                        </div>
                        <div class="mb-3">
                            <label for="correo" class="form-label">Correo</label>
                            <input type="email" class="form-control" id="correo" name="correo" required>
                        </div>
                        <div class="mb-3">
                            <label for="contrasena" class="form-label">Contraseña</label>
                            <input type="password" class="form-control" id="contrasena" name="contrasena" required>
                        </div>
                        <div class="mb-4">
                            <label for="confirmar" class="form-label">Confirmar</label>
                            <input type="password" class="form-control" id="confirmar" name="confirmar" required>
                        </div>
                        <button type="submit" class="btn btn-soft w-100">Registrarse</button>
                        <div id="mensaje" class="mt-3"></div>
                        <p class="mt-3 mb-0 small">¿Ya tienes cuenta? <a class="link-light-mini" href="login.php">Inicia sesión</a></p>
                    </form>
                </div>
            </div>
        </div>
        <div class="footer-simple">&copy; <?= date('Y') ?> Compra Tecnológica</div>
    </div>
    <script src="../assets/js/registro_user.js"></script>
</body>
</html>