<?php
// Script: productos_crud.php (controlador CRUD sincrónico para productos)
// Maneja agregar, editar y eliminar productos usando formularios POST tradicionales.

session_start(); // Inicia/continúa sesión para validar auth, rol y CSRF.

require_once '../config/config.php'; // Incluye conexión a BD (PDO $pdo).

// Verificación de autenticación.
if (!isset($_SESSION['usuario_id'])) { // Si no hay usuario logueado.
    header('Location: ../views/login.php'); // Redirige a login.
    exit; // Detiene ejecución.
}

// Verificación de rol administrador.
if (empty($_SESSION['usuario_rol']) || $_SESSION['usuario_rol'] !== 'admin') { // Rol distinto a admin.
    header('HTTP/1.1 403 Forbidden'); // Respuesta prohibida.
    echo 'Acceso denegado'; // Mensaje simple.
    exit; // Termina.
}

// Validación de token CSRF en formularios sensibles.
if ($_SERVER['REQUEST_METHOD'] === 'POST') { // Solo en envíos POST.
    if (!isset($_POST['csrf_token'], $_SESSION['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) { // Compara tokens.
        header('HTTP/1.1 400 Bad Request'); // Indica solicitud inválida.
        echo 'Token CSRF inválido'; // Mensaje.
        exit; // Detiene ejecución.
    }
}

$accion = isset($_POST['accion']) ? $_POST['accion'] : ''; // Determina acción solicitada.

// Ruta principal por acción.
if ($accion === 'agregar_producto') { // Agregar nuevo producto.
    $nombre = trim($_POST['nombre']); // Nombre limpio.
    $descripcion = trim($_POST['descripcion']); // Descripción limpia.
    $categoria = intval($_POST['categoria']); // Categoría a entero.

    $stmt = $pdo->prepare("INSERT INTO productos (nombre, descripcion, id_categoria) VALUES (?, ?, ?)"); // Sentencia preparada.
    $stmt->execute([$nombre, $descripcion, $categoria]); // Ejecuta inserción.

    header('Location: ../views/productos_admin.php'); // Regresa a panel de productos.
    exit; // Finaliza.
} elseif ($accion === 'editar_producto') { // Edición de producto existente.
    $id = intval($_POST['id']); // ID a entero.
    $nombre = trim($_POST['nombre']); // Nombre limpio.
    $descripcion = trim($_POST['descripcion']); // Descripción limpia.
    $categoria = intval($_POST['categoria']); // Categoría a entero.

    $stmt = $pdo->prepare("UPDATE productos SET nombre = ?, descripcion = ?, id_categoria = ? WHERE id = ?"); // Sentencia update.
    $stmt->execute([$nombre, $descripcion, $categoria, $id]); // Ejecuta actualización.

    header('Location: ../views/productos_admin.php'); // Redirige al listado.
    exit; // Termina.
} elseif ($accion === 'eliminar_producto') { // Eliminación de producto.
    $id = intval($_POST['id']); // ID a entero.

    $stmt = $pdo->prepare("DELETE FROM productos WHERE id = ?"); // Sentencia delete.
    $stmt->execute([$id]); // Ejecuta.

    header('Location: ../views/productos_admin.php'); // Regresa a listado.
    exit; // Cierra.
} else { // Acción desconocida o vacía.
    header('HTTP/1.1 400 Bad Request'); // Respuesta 400.
    echo 'Acción no válida'; // Mensaje.
    exit; // Termina.
}
?>
