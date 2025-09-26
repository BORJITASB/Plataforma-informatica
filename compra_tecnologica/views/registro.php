<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Registrar Producto (AJAX)</title>
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
        <a class="active" href="registro.php">Registrar Producto</a>
    </div>
<?php
require_once("../config/config.php");
try {
    $stmt = $pdo->query("SELECT id_categoria, nombre FROM categorias ORDER BY nombre ASC");
    $categorias = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    $categorias = [];
}
?>
    <div class="row justify-content-center">
        <div class="col-lg-7 col-xl-6">
            <div class="glass-box">
                <h1 class="glass-title">Registrar Producto (AJAX)</h1>
                <form id="formRegistro" novalidate>
                    <div class="mb-3">
                        <label for="nombre" class="form-label">Nombre del producto</label>
                        <input type="text" class="form-control" id="nombre" name="nombre" required>
                    </div>
                    <div class="mb-3">
                        <label for="descripcion" class="form-label">Descripción</label>
                        <textarea class="form-control" id="descripcion" name="descripcion" rows="4" required></textarea>
                    </div>
                    <div class="mb-4">
                        <label for="categoria" class="form-label">Categoría</label>
                        <select class="form-select" id="categoria" name="id_categoria" required>
                            <option value="">Seleccione una categoría</option>
                            <?php foreach ($categorias as $cat): ?>
                                <option value="<?= htmlspecialchars($cat['id_categoria']) ?>"><?= htmlspecialchars($cat['nombre']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-soft w-100">Registrar</button>
                    <div id="mensaje" class="mt-3"></div>
                </form>
            </div>
        </div>
    </div>
    <div class="footer-simple">&copy; <?= date('Y') ?> Compra Tecnológica</div>
</div>
<script src="../assets/js/registro.js"></script>
</body>
</html>

