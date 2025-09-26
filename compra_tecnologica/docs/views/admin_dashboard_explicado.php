<?php
// Vista: admin_dashboard.php (panel principal de administración)
// Muestra métricas, tablas de últimos registros y gráfico de tendencias.

session_start(); // Control de sesión.

// Bloquea acceso a no autenticados.
if (!isset($_SESSION['usuario_id'])) {
    header('Location: login.php');
    exit;
}

// Bloquea acceso a roles no admin.
if (empty($_SESSION['usuario_rol']) || $_SESSION['usuario_rol'] !== 'admin') {
    header('HTTP/1.1 403 Forbidden');
    echo 'Acceso denegado';
    exit;
}

require_once '../config/config.php'; // Conexión BD.

// Obtención de métricas simples.
$totalProductos = $pdo->query("SELECT COUNT(*) FROM productos")->fetchColumn(); // Cuenta total productos.
$totalUsuarios = $pdo->query("SELECT COUNT(*) FROM usuarios")->fetchColumn(); // Cuenta total usuarios.

// Top 5 categorías (asumiendo id_categoria numérico) contando productos.
$topCategoriasStmt = $pdo->query("SELECT id_categoria, COUNT(*) total FROM productos GROUP BY id_categoria ORDER BY total DESC LIMIT 5");
$topCategorias = $topCategoriasStmt->fetchAll(PDO::FETCH_ASSOC); // Array de categorías.

// Últimos 5 productos recientes.
$ultimosProductosStmt = $pdo->query("SELECT id, nombre, descripcion FROM productos ORDER BY id DESC LIMIT 5");
$ultimosProductos = $ultimosProductosStmt->fetchAll(PDO::FETCH_ASSOC); // Array productos.

// Últimos 5 usuarios registrados.
$ultimosUsuariosStmt = $pdo->query("SELECT id, nombre, correo FROM usuarios ORDER BY id DESC LIMIT 5");
$ultimosUsuarios = $ultimosUsuariosStmt->fetchAll(PDO::FETCH_ASSOC); // Array usuarios.

// Datos simulados para gráfico (ejemplo: conteos por mes). Sustituir por consulta real.
$chartLabels = json_encode(['Ene','Feb','Mar','Abr','May','Jun']); // Etiquetas meses.
$chartData = json_encode([5,8,6,12,9,14]); // Valores ficticios.
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8"> <!-- UTF-8 -->
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> <!-- Responsive -->
    <title>Dashboard Admin</title> <!-- Título -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"> <!-- Bootstrap -->
    <link rel="stylesheet" href="../assets/css/app.css"> <!-- Estilos globales -->
    <link rel="stylesheet" href="../assets/css/dashboard.css"> <!-- Estilos dashboard -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script> <!-- Librería Chart.js -->
</head>
<body class="app-body">
<div class="overlay"></div> <!-- Fondo animado -->
<div class="dashboard-layout"> <!-- Grid principal -->
    <aside class="sidebar"> <!-- Barra lateral -->
        <div class="sidebar-header"> <!-- Encabezado -->
            <h2 class="h5 mb-0">Admin Panel</h2> <!-- Título sidebar -->
        </div>
        <nav class="sidebar-nav"> <!-- Navegación -->
            <a href="admin_dashboard.php" class="active">Dashboard</a> <!-- Link activo -->
            <a href="productos_admin.php">Productos</a> <!-- Link productos -->
            <a href="catalogo.php" target="_blank">Catálogo Público</a> <!-- Link externo -->
            <a href="logout.php" class="text-danger">Salir</a> <!-- Logout -->
        </nav>
        <div class="sidebar-footer small"> <!-- Pie -->
            Sesión: <?= htmlspecialchars($_SESSION['usuario_nombre'] ?? '') ?> <!-- Usuario -->
        </div>
    </aside>
    <main class="dashboard-main"> <!-- Contenido principal -->
        <header class="dashboard-header"> <!-- Encabezado -->
            <h1 class="h3 mb-0">Dashboard</h1> <!-- Título -->
            <div class="header-actions"> <!-- Acciones -->
                <a href="productos_admin.php" class="btn btn-sm btn-primary">Gestionar Productos</a> <!-- Botón -->
            </div>
        </header>
        <section class="metrics-grid"> <!-- Métricas -->
            <div class="metric-card"> <!-- Tarjeta métrica -->
                <div class="metric-label">Productos</div> <!-- Etiqueta -->
                <div class="metric-value"><?= htmlspecialchars($totalProductos) ?></div> <!-- Valor -->
            </div>
            <div class="metric-card"> <!-- Tarjeta -->
                <div class="metric-label">Usuarios</div>
                <div class="metric-value"><?= htmlspecialchars($totalUsuarios) ?></div>
            </div>
            <div class="metric-card"> <!-- Tarjeta -->
                <div class="metric-label">Categorías (Top)</div>
                <div class="metric-value"><?= count($topCategorias) ?></div> <!-- Conteo top -->
            </div>
            <div class="metric-card"> <!-- Tarjeta -->
                <div class="metric-label">Sesión</div>
                <div class="metric-value small">OK</div> <!-- Estado -->
            </div>
        </section>
        <section class="data-sections"> <!-- Secciones de datos -->
            <div class="data-card"> <!-- Tarjeta top categorías -->
                <h2 class="h6 mb-3">Top Categorías</h2> <!-- Título -->
                <div class="table-responsive"> <!-- Tabla -->
                    <table class="table table-sm table-dark table-borderless align-middle mb-0"> <!-- Tabla -->
                        <thead>
                            <tr>
                                <th>Categoría</th> <!-- Encabezado -->
                                <th>Total</th> <!-- Encabezado -->
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($topCategorias as $c): ?> <!-- Loop -->
                            <tr>
                                <td><?= htmlspecialchars($c['id_categoria']) ?></td> <!-- ID categoría -->
                                <td><?= htmlspecialchars($c['total']) ?></td> <!-- Total -->
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($topCategorias)): ?> <!-- Sin datos -->
                            <tr><td colspan="2" class="text-center text-muted">No hay datos</td></tr>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="data-card"> <!-- Tarjeta gráfico -->
                <h2 class="h6 mb-3">Tendencia Productos</h2> <!-- Título -->
                <canvas id="productosChart" height="160"></canvas> <!-- Lienzo Chart -->
            </div>
            <div class="data-card last-products-table"> <!-- Tarjeta últimos productos -->
                <h2 class="h6 mb-3">Últimos Productos</h2> <!-- Título -->
                <div class="table-responsive"> <!-- Tabla -->
                    <table class="table table-sm table-borderless align-middle mb-0"> <!-- Tabla -->
                        <thead>
                            <tr>
                                <th>ID</th> <!-- Encabezado -->
                                <th>Nombre</th> <!-- Encabezado -->
                                <th>Descripción</th> <!-- Encabezado -->
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($ultimosProductos as $p): ?> <!-- Loop -->
                            <tr>
                                <td><?= htmlspecialchars($p['id']) ?></td> <!-- ID -->
                                <td><?= htmlspecialchars($p['nombre']) ?></td> <!-- Nombre -->
                                <td class="text-truncate" style="max-width:160px;"> <!-- Columna truncada -->
                                    <?= htmlspecialchars($p['descripcion']) ?> <!-- Descripción -->
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($ultimosProductos)): ?> <!-- Sin datos -->
                            <tr><td colspan="3" class="text-center text-muted">No hay productos</td></tr>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="data-card"> <!-- Tarjeta últimos usuarios -->
                <h2 class="h6 mb-3">Últimos Usuarios</h2> <!-- Título -->
                <div class="table-responsive"> <!-- Tabla -->
                    <table class="table table-sm table-dark table-borderless align-middle mb-0"> <!-- Tabla -->
                        <thead>
                            <tr>
                                <th>ID</th> <!-- Encabezado -->
                                <th>Nombre</th> <!-- Encabezado -->
                                <th>Correo</th> <!-- Encabezado -->
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($ultimosUsuarios as $u): ?> <!-- Loop -->
                            <tr>
                                <td><?= htmlspecialchars($u['id']) ?></td> <!-- ID -->
                                <td><?= htmlspecialchars($u['nombre']) ?></td> <!-- Nombre -->
                                <td class="text-truncate" style="max-width:160px;"> <!-- Columna truncada -->
                                    <?= htmlspecialchars($u['correo']) ?> <!-- Correo -->
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($ultimosUsuarios)): ?> <!-- Sin datos -->
                            <tr><td colspan="3" class="text-center text-muted">No hay usuarios</td></tr>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>
    </main>
</div>
<script>
// Inicializa gráfico Chart.js (línea simple)
const ctx = document.getElementById('productosChart').getContext('2d'); // Contexto lienzo.
new Chart(ctx, { // Crea nueva instancia Chart.
    type: 'line', // Tipo línea.
    data: { // Datos.
        labels: <?= $chartLabels ?>, // Etiquetas X.
        datasets: [{ // Conjunto.
            label: 'Productos', // Título dataset.
            data: <?= $chartData ?>, // Valores.
            borderColor: '#4dabf7', // Color línea.
            backgroundColor: 'rgba(77,171,247,0.15)', // Relleno.
            tension: 0.3, // Curva.
            fill: true, // Rellenar bajo línea.
            pointRadius: 4, // Radio puntos.
            pointBackgroundColor: '#4dabf7' // Color puntos.
        }]
    },
    options: { // Opciones.
        plugins: { // Plugins.
            legend: { labels: { color: '#fff' } } // Color texto leyenda.
        },
        scales: { // Escalas.
            x: { ticks: { color: '#ddd' }, grid: { color: 'rgba(255,255,255,0.08)' } }, // Eje X.
            y: { ticks: { color: '#ddd' }, grid: { color: 'rgba(255,255,255,0.08)' } } // Eje Y.
        }
    }
});
</script>
</body>
</html>
