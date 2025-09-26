<?php
require_once("../config/config.php");
$stmt = $pdo->query("SELECT p.nombre, p.descripcion, p.imagen, c.nombre AS categoria
FROM productos p
JOIN categorias c ON p.id_categoria = c.id_categoria
ORDER BY p.id_producto DESC");
$productos = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Catálogo de Productos</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="../assets/css/app.css" rel="stylesheet">
</head>
<body class="app-body">
    <div class="app-wrapper container">
        <div class="nav-top">
            <div class="brand-mini">Compra Tecnológica</div>
            <a href="../public/index.php">Inicio</a>
            <a class="active" href="catalogo.php">Catálogo</a>
            <a href="login.php">Login</a>
            <a href="registro_user.php">Registro</a>
        </div>
        <h1 class="glass-title mb-4">Catálogo de Productos</h1>
        <div class="row">
            <?php foreach($productos as $prod): ?>
            <div class="col-sm-6 col-lg-4 mb-4">
                <div class="card-product">
                    <?php if (!empty($prod['imagen'])): ?>
                        <img src="../assets/img/<?= htmlspecialchars($prod['imagen']) ?>" alt="<?= htmlspecialchars($prod['nombre']) ?>">
                    <?php else: ?>
                        <img src="../assets/img/fondo_tecnologico.jpg" alt="Sin imagen">
                    <?php endif; ?>
                    <div class="card-body">
                        <h5 class="mb-2" style="font-size:1.05rem; font-weight:600; color:#fff;"><?= htmlspecialchars($prod['nombre']) ?></h5>
                        <p class="mb-2 small" style="color:#d0d6dd;"><?= htmlspecialchars(mb_strimwidth($prod['descripcion'],0,120,'…')) ?></p>
                        <span class="badge badge-soft"><?= htmlspecialchars($prod['categoria']) ?></span>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <div class="footer-simple">&copy; <?= date('Y') ?> Compra Tecnológica</div>
    </div>
</body>
</html>