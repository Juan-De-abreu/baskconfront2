const db = require('../config/db');

const getDashboardResumen = async (req, res) => {
    try {
        // 1. Ventas totales del mes
        const [ventasTotales] = await db.query(`
            SELECT SUM(total) as total 
            FROM pedidos 
            WHERE estado = 'completado' 
             # AND MONTH(fecha) = MONTH(CURDATE()) 
             # AND YEAR(fecha) = YEAR(CURDATE())
        `);
        const totalVentas = ventasTotales[0].total || 0;

        // 2. Total de juegos vendidos
        const [juegosVendidos] = await db.query(`
            SELECT SUM(cantidad) as total 
            FROM detalle_pedido dp
            JOIN pedidos p ON dp.idpedido = p.idpedido
            WHERE p.estado = 'completado'
        `);
        const totalJuegos = juegosVendidos[0].total || 0;

         // 2.1 Total de juegos en pendiente
        const [juegosPendientes] = await db.query(`
            SELECT SUM(cantidad) as total 
            FROM detalle_pedido dp
            JOIN pedidos p ON dp.idpedido = p.idpedido
            WHERE p.estado = 'pendiente'
        `);
        const totalPendientes = juegosPendientes[0].total || 0;

        // 3. Nuevos usuarios en los últimos 30 días
        const [nuevosUsuarios] = await db.query(`
            SELECT COUNT(*) as total 
            FROM usuarios 
            WHERE fechacreacion >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        `);
        const nuevos = nuevosUsuarios[0].total || 0;

        

        // 4. Juegos más vendidos
        const [juegosMasVendidos] = await db.query(`
            SELECT j.nombre, SUM(dp.cantidad) as unidades_vendidas
            FROM detalle_pedido dp
            JOIN juegos j ON dp.idjuego = j.idjuego
            JOIN pedidos p ON dp.idpedido = p.idpedido
            WHERE p.estado = 'completado'
            GROUP BY j.idjuego
            ORDER BY unidades_vendidas DESC
            LIMIT 5
        `);

        // 5. Géneros más populares
        const [generosPopulares] = await db.query(`
            SELECT g.nombre as genero, SUM(dp.cantidad) as total_vendido
            FROM detalle_pedido dp
            JOIN juegos j ON dp.idjuego = j.idjuego
            JOIN generos g ON j.idgenero = g.idgenero
            JOIN pedidos p ON dp.idpedido = p.idpedido
            WHERE p.estado = 'completado'
            GROUP BY g.idgenero
            ORDER BY total_vendido DESC
            LIMIT 5
        `);

        // 6. Pedidos recientes (últimos 5)
        const [pedidosRecientes] = await db.query(`
            SELECT p.idpedido, u.nombre, p.total, p.fecha
            FROM pedidos p
            JOIN usuarios u ON p.idusuario = u.idusuario
            WHERE p.estado = 'completado'
            ORDER BY p.fecha DESC
            LIMIT 6
        `);

       

       
        const resumen = {
            ventasTotales: parseFloat(totalVentas),
            juegosVendidos: totalJuegos,
            juegosPendientes: totalPendientes,
            nuevosUsuarios: nuevos,
            juegosMasVendidos,
            generosPopulares,
            pedidosRecientes
  
        };

        res.json({ resumen });

    } catch (err) {
        console.error('Error en dashboard:', err);
        res.status(500).json({
            error: 'Ocurrió un error al obtener el resumen del dashboard'
        });
    }
};

module.exports = {
    getDashboardResumen
};