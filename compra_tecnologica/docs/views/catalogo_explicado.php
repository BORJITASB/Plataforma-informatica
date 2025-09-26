<?php
// Vista: catalogo.php (listado público o autenticado de productos)
// Muestra una tabla simple de productos obtenidos desde la base de datos.

session_start(); // Para usar variables de sesión si se requiere (ej. mostrar usuario).
require_once '../config/config.php'; // Conexión BD.

// Consulta básica de productos con su categoría (si existe la relación).
$stmt = $pdo->query("SELECT p.id, p.nombre, p.descripcion, p.id_categoria FROM productos p ORDER BY p.id DESC"); // Obtiene productos.
$productos = $stmt->fetchAll(PDO::FETCH_ASSOC); // Arreglo asociativo con filas.
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Catálogo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/css/app.css"> <!-- Estilos globales -->
</head>
<body class="app-body">
<div class="overlay"></div> <!-- Capa decorativa -->
<main class="container py-5 position-relative" style="z-index:2;">
    <div class="glass-card p-4">
        <div class="d-flex justify-content-between align-items-center mb-3"> <!-- Header -->
            <h1 class="h3 mb-0">Catálogo de Productos</h1> <!-- Título -->
            <div>
                <a href="login.php" class="btn btn-sm btn-outline-light">Login</a> <!-- Botón Login -->
                <a href="registro.php" class="btn btn-sm btn-primary">Registrar Producto</a> <!-- Botón Registrar -->
            </div>
        </div>
        <div class="table-responsive"> <!-- Tabla responsive -->
            <table class="table table-dark table-hover align-middle mb-0"> <!-- Tabla estilizada -->
                <thead>
                    <tr>
                        <th>ID</th> <!-- Encabezado ID -->
                        <th>Nombre</th> <!-- Encabezado Nombre -->
                        <th>Descripción</th> <!-- Encabezado Descripción -->
                        <th>ID Categoría</th> <!-- Encabezado Categoría -->
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($productos as $p): ?> <!-- Iteración productos -->
                    <tr>
                        <td><?= htmlspecialchars($p['id']) ?></td> <!-- ID -->
                        <td><?= htmlspecialchars($p['nombre']) ?></td> <!-- Nombre -->
                        <td><?= htmlspecialchars($p['descripcion']) ?></td> <!-- Descripción -->
                        <td><?= htmlspecialchars($p['id_categoria']) ?></td> <!-- Categoría -->
                    </tr>
                <?php endforeach; ?>
                <?php if (empty($productos)): ?> <!-- Si no hay productos -->
                    <tr>
                        <td colspan="4" class="text-center text-muted">Sin productos registrados.</td> <!-- Mensaje vacío -->
                    </tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</main>
</body>
</html>
