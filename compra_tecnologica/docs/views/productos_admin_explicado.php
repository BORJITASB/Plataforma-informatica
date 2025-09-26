<?php
// Vista explicada: productos_admin.php (gestión de productos con tema glass)
// Funcionalidades: listar, agregar y editar productos con protección CSRF.

session_start(); // Sesión para auth / CSRF.
if (!isset($_SESSION['id_usuario']) || ($_SESSION['rol'] ?? '') !== 'admin') { // Verificación de rol admin.
    header('Location: login.php'); // Redirige a login si no autorizado.
    exit; // Detiene ejecución.
}
if (empty($_SESSION['csrf_token'])) { // Genera token CSRF si no existe.
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // 64 chars hex.
}
require_once("../config/config.php"); // Conexión BD.

// Consulta productos con nombre de categoría (JOIN) y categoría id para selects.
$stmt = $pdo->query("SELECT p.id_producto, p.nombre, p.descripcion, c.nombre AS categoria, p.id_categoria FROM productos p JOIN categorias c ON p.id_categoria = c.id_categoria ORDER BY p.id_producto DESC");
$productos = $stmt->fetchAll(PDO::FETCH_ASSOC); // Array productos.

// Categorías para selects.
$stmtCat = $pdo->query("SELECT id_categoria, nombre FROM categorias ORDER BY nombre ASC");
$categorias = $stmtCat->fetchAll(PDO::FETCH_ASSOC); // Array categorías.

// Producto en edición si corresponde.
$prodEdit = null; // Inicial.
if (isset($_GET['editar'])) { // Si parámetro editar.
    $idEdit = intval($_GET['editar']); // Normaliza.
    $stmtE = $pdo->prepare("SELECT * FROM productos WHERE id_producto=?"); // Sentencia.
    $stmtE->execute([$idEdit]); // Ejecuta.
    $prodEdit = $stmtE->fetch(PDO::FETCH_ASSOC) ?: null; // Resultado.
}
?>
<!DOCTYPE html> <!-- Documento HTML5 -->
<html lang="es"> <!-- Idioma -->
<head>
    <meta charset="UTF-8"> <!-- Codificación -->
    <meta name="viewport" content="width=device-width,initial-scale=1"> <!-- Responsive -->
    <title>Productos | Admin</title> <!-- Título -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"> <!-- Bootstrap -->
    <link href="../assets/css/app.css" rel="stylesheet"> <!-- Tema glass -->
</head>
<body class="app-body"> <!-- Fondo unificado -->
<div class="app-wrapper container"> <!-- Wrapper -->
    <div class="nav-top mb-4"> <!-- Barra nav -->
        <div class="brand-mini">⚙️ Admin</div> <!-- Logo/brand -->
        <a href="admin_dashboard.php">Dashboard</a> <!-- Link dashboard -->
        <a href="productos_admin.php" class="active">Productos</a> <!-- Link activo -->
        <a href="catalogo.php" target="_blank">Catálogo Público</a> <!-- Catálogo -->
        <a href="../controllers/logout.php" class="ms-auto text-danger" style="font-weight:600;">Salir</a> <!-- Logout -->
    </div>

    <?php if (isset($_GET['mensaje'])): ?> <!-- Alerta condicional -->
        <div class="alert alert-<?= htmlspecialchars($_GET['tipo'] ?? 'success') ?> alert-dismissible fade show glass-box p-3" role="alert" style="background:rgba(0,0,0,0.35);">
            <?= htmlspecialchars($_GET['mensaje']) ?> <!-- Mensaje -->
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Cerrar"></button> <!-- Cerrar -->
        </div>
    <?php endif; ?>

    <div class="row g-4"> <!-- Grid principal -->
        <div class="col-lg-5"> <!-- Col formulario -->
            <div class="glass-box h-100 d-flex flex-column"> <!-- Caja formulario -->
                <h2 class="glass-title mb-2 fs-5">Agregar Producto</h2> <!-- Título -->
                <form method="POST" action="../controllers/productos_crud.php" class="mt-1"> <!-- Form alta -->
                    <input type="hidden" name="accion" value="agregar"> <!-- Acción alta -->
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"> <!-- Token CSRF -->
                    <div class="mb-3"> <!-- Campo nombre -->
                        <label for="nombre" class="form-label">Nombre</label> <!-- Etiqueta -->
                        <input type="text" id="nombre" name="nombre" class="form-control" required> <!-- Input nombre -->
                    </div>
                    <div class="mb-3"> <!-- Campo descripción -->
                        <label for="descripcion" class="form-label">Descripción</label> <!-- Etiqueta -->
                        <textarea id="descripcion" name="descripcion" class="form-control" rows="3" required></textarea> <!-- Textarea -->
                    </div>
                    <div class="mb-3"> <!-- Campo categoría -->
                        <label for="id_categoria" class="form-label">Categoría</label> <!-- Etiqueta -->
                        <select id="id_categoria" name="id_categoria" class="form-select" required> <!-- Select -->
                            <option value="">Seleccione...</option> <!-- Placeholder -->
                            <?php foreach($categorias as $cat): ?> <!-- Itercategorías -->
                                <option value="<?= $cat['id_categoria'] ?>"><?= htmlspecialchars($cat['nombre']) ?></option> <!-- Opción -->
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="d-grid"> <!-- Botón -->
                        <button class="btn btn-soft">➕ Agregar</button> <!-- Botón alta -->
                    </div>
                </form>
            </div>
        </div>
        <div class="col-lg-7"> <!-- Col listado -->
            <div class="glass-box"> <!-- Caja listado -->
                <div class="d-flex justify-content-between align-items-center mb-3"> <!-- Header listado -->
                    <h2 class="glass-title fs-5 mb-0">Listado de Productos</h2> <!-- Título -->
                    <span class="badge badge-soft"><?= count($productos) ?> total</span> <!-- Conteo -->
                </div>
                <div class="table-responsive" style="max-height:520px;"> <!-- Scroll -->
                    <table class="table table-sm table-glass align-middle mb-0"> <!-- Tabla productos -->
                        <thead> <!-- Encabezados -->
                            <tr>
                                <th style="width:17%">Nombre</th>
                                <th style="width:43%">Descripción</th>
                                <th style="width:20%">Categoría</th>
                                <th style="width:20%" class="text-center">Acciones</th>
                            </tr>
                        </thead>
                        <tbody> <!-- Cuerpo tabla -->
                        <?php if($productos): foreach($productos as $prod): ?> <!-- Loop productos -->
                            <tr>
                                <td class="fw-semibold"><?= htmlspecialchars($prod['nombre']) ?></td> <!-- Nombre -->
                                <td class="text-truncate" style="max-width:260px;"> <?= htmlspecialchars($prod['descripcion']) ?> </td> <!-- Descripción -->
                                <td><?= htmlspecialchars($prod['categoria']) ?></td> <!-- Categoría -->
                                <td class="text-center"> <!-- Acciones -->
                                    <a href="?editar=<?= $prod['id_producto'] ?>" class="btn btn-outline-light btn-sm">Editar</a> <!-- Editar -->
                                    <a href="../controllers/productos_crud.php?eliminar=<?= $prod['id_producto'] ?>" class="btn btn-outline-danger btn-sm" onclick="return confirm('¿Eliminar este producto?')">✖</a> <!-- Eliminar -->
                                </td>
                            </tr>
                        <?php endforeach; else: ?> <!-- Sin productos -->
                            <tr><td colspan="4" class="text-center text-muted">Sin productos registrados.</td></tr> <!-- Mensaje vacío -->
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <?php if($prodEdit): ?> <!-- Panel edición condicional -->
    <div class="glass-box mt-5"> <!-- Caja edición -->
        <div class="d-flex justify-content-between align-items-center mb-2"> <!-- Header edición -->
            <h2 class="glass-title fs-5 mb-0">Editar: <?= htmlspecialchars($prodEdit['nombre']) ?></h2> <!-- Título -->
            <a href="productos_admin.php" class="btn btn-sm btn-outline-light">Cancelar</a> <!-- Cancelar -->
        </div>
        <form method="POST" action="../controllers/productos_crud.php" class="row g-3"> <!-- Form edición -->
            <input type="hidden" name="accion" value="editar"> <!-- Acción editar -->
            <input type="hidden" name="id_producto" value="<?= $prodEdit['id_producto'] ?>"> <!-- ID product -->
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"> <!-- Token CSRF -->
            <div class="col-md-4"> <!-- Campo nombre -->
                <label class="form-label" for="edit_nombre">Nombre</label> <!-- Etiqueta -->
                <input type="text" id="edit_nombre" name="nombre" class="form-control" value="<?= htmlspecialchars($prodEdit['nombre']) ?>" required> <!-- Input -->
            </div>
            <div class="col-md-4"> <!-- Campo categoría -->
                <label class="form-label" for="edit_categoria">Categoría</label> <!-- Etiqueta -->
                <select id="edit_categoria" name="id_categoria" class="form-select" required> <!-- Select -->
                    <?php foreach($categorias as $cat): ?> <!-- Loop categorías -->
                        <option value="<?= $cat['id_categoria'] ?>" <?= $cat['id_categoria']==$prodEdit['id_categoria']?'selected':'' ?>><?= htmlspecialchars($cat['nombre']) ?></option> <!-- Opción -->
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-12"> <!-- Campo descripción -->
                <label class="form-label" for="edit_descripcion">Descripción</label> <!-- Etiqueta -->
                <textarea id="edit_descripcion" name="descripcion" class="form-control" rows="3" required><?= htmlspecialchars($prodEdit['descripcion']) ?></textarea> <!-- Textarea -->
            </div>
            <div class="col-12 d-flex gap-2"> <!-- Botones -->
                <button class="btn btn-soft">💾 Guardar Cambios</button> <!-- Guardar -->
                <a href="productos_admin.php" class="btn btn-outline-light">Cancelar</a> <!-- Cancelar -->
            </div>
        </form>
    </div>
    <?php endif; ?>

    <div class="footer-simple">&copy; <?= date('Y') ?> Compra Tecnológica · Gestión de Productos</div> <!-- Pie -->
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script> <!-- JS Bootstrap -->
</body>
</html>
