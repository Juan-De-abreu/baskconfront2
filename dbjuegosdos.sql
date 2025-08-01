-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: localhost:3306
-- Tiempo de generación: 01-08-2025 a las 18:23:32
-- Versión del servidor: 8.0.30
-- Versión de PHP: 8.2.18

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `dbjuegosdos`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `carrito`
--

CREATE TABLE `carrito` (
  `idcarrito` int NOT NULL,
  `idusuario` int NOT NULL,
  `idjuego` int NOT NULL,
  `cantidad` int DEFAULT '1',
  `fechacreacion` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ;

--
-- Volcado de datos para la tabla `carrito`
--

INSERT INTO `carrito` (`idcarrito`, `idusuario`, `idjuego`, `cantidad`, `fechacreacion`) VALUES
(1, 1, 2, 1, '2025-07-29 15:26:49'),
(2, 1, 3, 1, '2025-07-29 15:26:49'),
(3, 3, 5, 1, '2025-07-29 15:26:49'),
(4, 7, 1, 2, '2025-07-29 15:26:49'),
(5, 10, 4, 1, '2025-07-29 15:26:49'),
(6, 12, 6, 1, '2025-07-29 15:26:49');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `detalle_pedido`
--

CREATE TABLE `detalle_pedido` (
  `iddetalle` int NOT NULL,
  `idpedido` int NOT NULL,
  `idjuego` int NOT NULL,
  `cantidad` int NOT NULL,
  `precio` decimal(10,2) NOT NULL
) ;

--
-- Volcado de datos para la tabla `detalle_pedido`
--

INSERT INTO `detalle_pedido` (`iddetalle`, `idpedido`, `idjuego`, `cantidad`, `precio`) VALUES
(1, 1, 1, 1, 59.99),
(2, 2, 4, 1, 69.99),
(3, 2, 5, 1, 59.99),
(4, 3, 2, 1, 69.99),
(5, 4, 3, 1, 59.99),
(6, 5, 4, 1, 69.99),
(7, 5, 1, 1, 59.99),
(8, 6, 2, 1, 69.99),
(9, 7, 6, 1, 59.99),
(10, 8, 4, 1, 69.99),
(11, 8, 3, 1, 59.99),
(12, 9, 2, 1, 69.99),
(13, 10, 5, 1, 59.99),
(14, 11, 1, 1, 59.99),
(15, 11, 4, 1, 69.99),
(16, 12, 2, 1, 69.99),
(17, 13, 7, 1, 59.99),
(18, 14, 4, 1, 69.99),
(19, 14, 5, 1, 59.99),
(20, 15, 2, 1, 69.99),
(21, 16, 2, 6, 69.62);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `estatus`
--

CREATE TABLE `estatus` (
  `idestatus` int NOT NULL,
  `nombre` varchar(25) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `estatus`
--

INSERT INTO `estatus` (`idestatus`, `nombre`) VALUES
(1, 'Activo'),
(2, 'Inactivo');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `generos`
--

CREATE TABLE `generos` (
  `idgenero` int NOT NULL,
  `idestatus` int DEFAULT NULL,
  `nombre` varchar(100) DEFAULT NULL,
  `descripcion` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `generos`
--

INSERT INTO `generos` (`idgenero`, `idestatus`, `nombre`, `descripcion`) VALUES
(1, 1, 'Acción', 'Juegos que se centran en la acción y el combate.WW'),
(2, 1, 'Aventura', 'Juegos enfocados en la exploración y la narrativa.'),
(3, 1, 'RPG', 'Juegos de rol donde los jugadores asumen personajes.'),
(4, 1, 'Deportes', 'Juegos que simulan diversas disciplinas deportivas.'),
(5, 1, 'Estrategia', 'Juegos que requieren planificación y pensamiento táctico.'),
(6, 1, 'Puzzle', 'Juegos que desafían la lógica y la resolución de problemas.'),
(7, 1, 'Tiro', 'Juegos centrados en la acción con armas de fuego.'),
(8, 2, 'Simulador', 'Juegos que simulan actividades de la vida real.'),
(9, 1, 'Plataformas', 'Juegos donde el personaje salta entre plataformas.'),
(10, 1, 'Terror', 'Juegos diseñados para provocar miedo y tensión.'),
(11, 2, 'MMORPG', 'Juegos de rol multijugador masivos en línea.'),
(12, 1, 'Sandbox', 'Juegos que permiten la creación libre y la exploración.'),
(13, 1, 'Carreras', 'Juegos centrados en competiciones de velocidad.'),
(14, 1, 'Roguelike', 'Juegos que presentan elementos de aleatoriedad y permadeath.'),
(15, 1, 'Battle Royale', 'Juegos donde muchos jugadores compiten hasta que solo uno queda.'),
(16, 2, 'Metroidvania', 'Juegos que combinan exploración y mejoras de habilidades.'),
(17, 1, 'Visual Novel', 'Juegos centrados en la narrativa y las decisiones del jugador.'),
(18, 1, 'Horror de supervivencia', 'Juegos enfocados en sobrevivir a situaciones de terror.'),
(19, 1, 'Idle', 'Juegos que progresan con poca o ninguna interacción del jugador.'),
(20, 2, 'Fighting 2', 'Juegos centrados en combates entre personajes.');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `juegos`
--

CREATE TABLE `juegos` (
  `idjuego` int NOT NULL,
  `idestatus` int NOT NULL,
  `idgenero` int NOT NULL,
  `nombre` varchar(200) NOT NULL,
  `descripcion` text,
  `fechapublicacion` date DEFAULT NULL,
  `precio` decimal(10,2) DEFAULT NULL,
  `valoracion` int DEFAULT NULL,
  `imagen` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `juegos`
--

INSERT INTO `juegos` (`idjuego`, `idestatus`, `idgenero`, `nombre`, `descripcion`, `fechapublicacion`, `precio`, `valoracion`, `imagen`) VALUES
(1, 1, 1, 'Call of Duty: Modern Warfare', 'Juego de disparos en primera persona con una historia intensa.', '2019-10-25', 59.99, 5, 'call-of-duty-modern-warfare-2-remastered_cjat.jpg'),
(2, 1, 1, 'Grand Theft Auto V', 'Juego de mundo abierto con misiones de acción y crimen.', '2013-09-17', 29.99, 2, 'HD-wallpaper-pin-de-lord-tyler-em-gta-art-gta-online-grand-theft-auto-gta-gta-5-money.jpg'),
(3, 1, 1, 'DOOM Eternal', 'Juego de acción rápida con demonios y armas poderosas.', '2020-03-20', 49.99, 4, 'E-DKRE1XMAE_jvC.jpg'),
(4, 1, 2, 'The Legend of Zelda: Breath of the Wild', 'Explora un vasto mundo abierto lleno de secretos.', '2017-03-03', 59.99, 5, '8437192-the-legend-of-zelda-breath-of-the-wild-nintendo-switch-front-cov.jpg'),
(5, 1, 2, 'Uncharted 4: A Thief\'s End', 'Aventura narrativa con exploración y combate.', '2016-05-10', 19.99, 1, '10095064-uncharted-4-a-thiefs-end-playstation-4-front-cover.jpg'),
(6, 1, 2, 'Red Dead Redemption 2', 'Historia épica del viejo oeste con un mundo abierto detallado.', '2018-10-26', 39.99, 3, '358976.jpg'),
(7, 1, 3, 'The Witcher 3: Wild Hunt', 'RPG de mundo abierto con una historia profunda.', '2015-05-19', 29.99, 4, 'the-witcher-3-wild-hunt-blood-and-wine_wzqf.jpg'),
(8, 1, 3, 'Final Fantasy VII Remake', 'Remake del clásico RPG con gráficos modernos.', '2020-04-10', 59.99, 5, 'final-fantasy-vii-remake_ye81.jpg'),
(9, 1, 3, 'Cyberpunk 2077', 'RPG futurista con un mundo abierto detallado.', '2020-12-10', 49.99, 2, 'dg2emwc-77b883c9-3b8a-4e74-a70f-bd377b552c1d.jpg'),
(10, 1, 4, 'FIFA 23', 'Simulador de fútbol con equipos reales y jugadores.', '2022-09-30', 69.99, 1, 'HD-wallpaper-fifa-23-paris-saint-germain-games-fifa23.jpg'),
(11, 1, 4, 'NBA 2K23', 'Simulador de baloncesto con jugadores profesionales.', '2022-09-09', 59.99, 4, '11107059-nba-2k23-arcade-edition-iphone-front-cover.jpg'),
(12, 1, 4, 'Rocket League', 'Combina deportes de coches con fútbol.', '2015-07-07', 26.00, 2, 'rocket-league_csqn.jpg'),
(13, 1, 5, 'Civilization VI', 'Construye un imperio y domina el mundo.', '2016-10-21', 39.99, 1, 'sid-meiers-civilization-vi_h5wc.jpg'),
(14, 1, 5, 'Starcraft II', 'Estrategia en tiempo real con razas únicas.', '2010-07-27', 5.00, 5, 'd1eh8uv-870d132f-3bd4-4850-a37b-c7bb8dc3911a.jpg'),
(15, 1, 5, 'Age of Empires IV', 'Estrategia histórica con civilizaciones icónicas.', '2021-10-28', 49.99, 2, 'AgeofEmpiresIV.png'),
(16, 1, 6, 'Portal 2', 'Resuelve puzzles con portales en un laboratorio.', '2011-04-19', 9.99, 1, 'Portal2.png'),
(17, 1, 6, 'Tetris Effect', 'Versión moderna del clásico Tetris.', '2018-11-09', 29.99, 5, 'TetrisEffect.png'),
(18, 1, 6, 'The Witness', 'Explora una isla llena de puzzles desafiantes.', '2016-01-26', 39.99, 3, 'TheWitness.png'),
(19, 1, 7, 'Counter-Strike: Global Offensive', 'Juego de disparos tácticos en equipo.', '2012-08-21', 8.00, 2, 'Counter-StrikeGlobalOffensive.png'),
(20, 1, 7, 'Rainbow Six Siege', 'Tácticas de equipo en un entorno destructible.', '2015-12-01', 19.99, 4, ''),
(21, 1, 7, 'Apex Legends', 'Battle Royale con héroes únicos.', '2019-02-04', 0.00, 1, ''),
(22, 1, 8, 'The Sims 4', 'Simulador de vida donde creas y controlas personas.', '2014-09-02', 39.99, 1, ''),
(23, 1, 8, 'Microsoft Flight Simulator', 'Simulador de vuelo ultrarrealista.', '2020-08-18', 59.99, 5, 'MicrosoftFlightSimulator.png'),
(24, 1, 8, 'Euro Truck Simulator 2', 'Simula conducir camiones por Europa.', '2012-10-19', 19.99, 5, 'EuroTruckSimulator2.png'),
(25, 1, 9, 'Super Mario Odyssey', 'Aventura de plataformas con Mario.', '2017-10-27', 49.99, 4, ''),
(26, 1, 9, 'Hollow Knight', 'Metroidvania con plataformas y combate.', '2017-02-24', 14.99, 2, ''),
(27, 1, 9, 'Celeste', 'Plataformas desafiantes con una historia emocional.', '2018-01-25', 19.99, 4, ''),
(28, 1, 10, 'Resident Evil Village', 'Supervivencia en un pueblo lleno de horrores.', '2021-05-07', 59.99, 1, ''),
(29, 1, 10, 'Outlast', 'Explora un asilo abandonado mientras escapas de peligros.', '2013-09-04', 19.99, 3, ''),
(30, 1, 10, 'Alien: Isolation', 'Supervivencia en una nave espacial infestada de alienígenas.', '2014-10-07', 29.99, 4, ''),
(31, 1, 11, 'World of Warcraft', 'MMORPG masivo con un mundo persistente.', '2004-11-23', 14.99, 1, ''),
(32, 1, 11, 'Final Fantasy XIV Online', 'MMORPG con una historia épica y expansiva.', '2010-09-30', 12.99, 5, 'FinalFantasyXIVOnline.png'),
(33, 1, 11, 'Guild Wars 2', 'MMORPG gratuito con eventos dinámicos.', '2012-08-28', 0.00, 4, ''),
(34, 1, 12, 'Minecraft', 'Crea y explora mundos generados proceduralmente.', '2011-11-18', 29.99, 2, ''),
(35, 1, 12, 'Terraria', 'Explora y construye en un mundo 2D inspirado en Minecraft.', '2011-05-16', 9.99, 3, ''),
(36, 1, 12, 'No Man\'s Sky', 'Explora un universo infinito con planetas únicos.', '2016-08-09', 29.99, 5, 'NoMansSky.png'),
(37, 1, 13, 'Forza Horizon 5', 'Carreras en un mundo abierto de México.', '2021-11-09', 59.99, 4, ''),
(38, 1, 13, 'Gran Turismo 7', 'Simulador de carreras con coches reales.', '2022-03-04', 69.99, 2, ''),
(39, 1, 13, 'Mario Kart 8 Deluxe', 'Carreras divertidas con personajes de Nintendo.', '2017-04-28', 59.99, 3, ''),
(40, 1, 14, 'Hades', 'Roguelike con una narrativa rica y mecánicas fluidas.', '2020-09-17', 24.99, 4, ''),
(41, 1, 14, 'Dead Cells', 'Roguelike con plataformas y combate rápido.', '2018-08-07', 24.99, 4, ''),
(42, 1, 14, 'Slay the Spire', 'Roguelike mezclado con cartas estratégicas.', '2019-01-23', 24.99, 4, ''),
(43, 1, 15, 'Fortnite', 'Battle Royale con construcción y personalización.', '2017-07-25', 3.00, 1, ''),
(44, 1, 15, 'PUBG: Battlegrounds', 'Battle Royale táctico con supervivencia.', '2017-12-20', 29.99, 3, ''),
(45, 1, 15, 'Fall Guys', 'Battle Royale estilo minijuegos.', '2020-08-04', 19.99, 5, 'FallGuys.png'),
(46, 1, 16, 'Ori and the Blind Forest', 'Explora un mundo hermoso con plataformas.', '2015-03-11', 19.99, 1, ''),
(47, 1, 16, 'Guacamelee!', 'Metroidvania con humor y lucha.', '2013-04-09', 14.99, 1, ''),
(48, 1, 16, 'Axiom Verge', 'Explora un mundo retro con mecánicas modernas.', '2015-03-31', 19.99, 3, ''),
(49, 1, 17, 'Doki Doki Literature Club! 2', 'Visual novel con giros inesperados.', '2017-09-22', 2.50, 4, ''),
(50, 1, 17, 'Phoenix Wright: Ace Attorney', 'Resuelve casos legales como abogado.', '2001-10-12', 29.99, 5, 'PhoenixWrightAceAttorney.png'),
(51, 1, 17, 'Steins;Gate', 'Visual novel de ciencia ficción con viajes en el tiempo.', '2009-10-15', 29.99, 3, ''),
(52, 1, 18, 'Resident Evil 2 Remake', 'Remake del clásico de supervivencia.', '2019-01-25', 39.99, 1, ''),
(53, 1, 18, 'Dead by Daylight', 'Supervivencia asimétrica con un asesino.', '2016-06-14', 19.99, 1, ''),
(54, 1, 18, 'The Evil Within', 'Horror psicológico con recursos limitados.', '2014-10-14', 19.99, 4, ''),
(55, 1, 19, 'AdVenture Capitalist', 'Juego idle donde administras negocios.', '2015-04-01', 10.00, 3, ''),
(56, 1, 19, 'Clicker Heroes', 'Juego idle con héroes y monstruos.', '2014-06-10', 3.00, 1, ''),
(57, 1, 19, 'Cookie Clicker', 'Haz clic para hornear galletas infinitamente.', '2013-08-08', 5.00, 2, ''),
(58, 1, 20, 'Street Fighter V', 'Combates uno contra uno con personajes icónicos.', '2016-02-16', 39.99, 5, 'StreetFighterV.png'),
(59, 1, 20, 'Mortal Kombat 11', 'Combates brutales con fatalities.', '2019-04-23', 59.99, 2, ''),
(60, 1, 20, 'Tekken 7', 'Combates 3D con una historia épica.', '2015-03-18', 49.99, 2, ''),
(61, 1, 2, 'God of War', 'Aventura de acción con mitología nórdica.', '2018-04-20', 49.99, 1, ''),
(62, 1, 2, 'Horizon Zero Dawn', 'Explora un mundo post-apocalíptico lleno de máquinas.', '2017-02-28', 39.99, 5, ''),
(63, 1, 3, 'Dark Souls III', 'RPG de acción desafiante.', '2016-03-24', 59.99, 2, ''),
(64, 1, 3, 'Elden Ring', 'RPG de acción y mundo abierto.', '2022-02-25', 59.99, 4, ''),
(65, 1, 4, 'F1 2023', 'Simulador oficial de Fórmula 1.', '2023-06-16', 69.99, 4, 'F12023.png'),
(66, 1, 4, 'Tony Hawk\'s Pro Skater 1 + 2', 'Colección remasterizada de los clásicos de skateboarding.', '2020-09-04', 39.99, 1, 'TonyHawksProSkater1+2.png'),
(67, 1, 8, 'Stardew Valley', 'Simulador de granja y vida rural.', '2016-02-26', 14.99, 2, ''),
(68, 1, 20, 'Among Us', 'Juego multijugador de deducción social.', '2018-11-16', 3.50, 3, ''),
(69, 1, 16, 'Hollow Knight: Silksong', 'Secuela del popular Metroidvania Hollow Knight.', '2024-01-01', 24.99, 5, ''),
(70, 1, 1, 'Sekiro: Shadows Die Twice', 'Acción y sigilo en el Japón feudal.', '2019-03-22', 59.99, 4, 'SekiroShadowsDieTwice.png'),
(71, 1, 3, 'Monster Hunter: World', 'Caza monstruos gigantes en un mundo abierto.', '2018-01-26', 49.99, 5, ''),
(72, 1, 7, 'Overwatch 2', 'Hero shooter en equipo con héroes únicos.', '2022-10-04', 2.80, 4, ''),
(73, 1, 2, 'Assassin\'s Creed Valhalla', 'Explora la era vikinga en Inglaterra.', '2020-11-10', 59.99, 3, ''),
(74, 1, 1, 'Borderlands 3', 'Looter shooter con tono humorístico.', '2019-09-13', 59.99, 1, 'Borderlands3.png'),
(75, 1, 1, 'Minecraft Dungeons', 'Acción y aventuras inspiradas en Minecraft.', '2020-05-26', 19.99, 1, 'MinecraftDungeons.png'),
(76, 1, 10, 'Little Nightmares II', 'Plataformas y terror en un mundo oscuro.', '2021-02-11', 29.99, 3, ''),
(77, 1, 2, 'It Takes Two', 'Aventura cooperativa con mecánicas únicas.', '2021-03-26', 39.99, 5, ''),
(78, 1, 1, 'Control', 'Acción y poderes sobrenaturales en un edificio misterioso.', '2019-08-27', 29.99, 5, 'control.png'),
(79, 1, 2, 'Death Stranding', 'Entrega paquetes en un mundo post-apocalíptico.', '2019-11-08', 59.99, 1, ''),
(80, 1, 2, 'Ghost of Tsushima', 'Conviértete en un samurái en la isla de Tsushima.', '2020-07-17', 59.99, 2, ''),
(81, 1, 3, 'Persona 5 Royal', 'RPG de turno con elementos sociales.', '2019-10-31', 49.99, 4, ''),
(82, 1, 7, 'Halo Infinite', 'Regresa a la saga Halo con un nuevo capítulo.', '2021-12-08', 59.99, 2, ''),
(83, 1, 14, 'Returnal', 'Roguelike con mecánicas de disparos.', '2021-04-30', 69.99, 4, ''),
(84, 1, 1, 'Spider-Man: Miles Morales', 'Asume el papel de Miles Morales como Spider-Man.', '2020-11-12', 49.99, 4, 'Spider-ManMilesMorales.png'),
(85, 1, 2, 'Immortals Fenyx Rising', 'Aventura inspirada en la mitología griega.', '2020-12-03', 59.99, 3, ''),
(86, 1, 1, 'Watch Dogs: Legion', 'Hackea y lucha en una versión futurista de Londres.', '2020-10-29', 59.99, 5, 'WatchDogsLegion.png'),
(87, 1, 17, 'Life is Strange: True Colors', 'Aventura narrativa con poderes emocionales.', '2021-09-10', 39.99, 1, ''),
(88, 1, 1, 'Far Cry 6', 'Rebélde contra un dictador en un mundo abierto.', '2021-10-07', 59.99, 5, 'FarCry6.png'),
(89, 1, 7, 'Back 4 Blood', 'Cooperativo de zombies con mecánicas tácticas.', '2021-10-12', 59.99, 1, ''),
(90, 1, 10, 'Resident Evil Village', 'Supervivencia en un pueblo lleno de horrores.', '2021-05-07', 59.99, 3, ''),
(91, 1, 7, 'Hitman 3', 'Sigilo y asesinatos en ubicaciones icónicas.', '2021-01-20', 59.99, 5, ''),
(92, 1, 9, 'Ratchet & Clank: Rift Apart', 'Aventura interdimensional con plataformas.', '2021-06-11', 69.99, 3, ''),
(93, 1, 2, 'Kena: Bridge of Spirits', 'Acción y aventura con espíritus y combate.', '2021-09-21', 39.99, 1, ''),
(94, 1, 20, 'Chivalry 2', 'Combates medievales multijugador.', '2021-06-08', 39.99, 1, ''),
(95, 1, 9, 'Psychonauts 2', 'Plataformas y aventuras en un mundo mental.', '2021-08-25', 39.99, 4, ''),
(96, 1, 3, 'Diablo II: Resurrected', 'Remake del clásico RPG de acción.', '2021-09-23', 39.99, 1, ''),
(97, 1, 5, 'Age of Empires II: Definitive Edition', 'Estrategia histórica con civilizaciones icónicas.', '2019-11-14', 19.99, 4, ''),
(98, 1, 8, 'Microsoft Flight Simulator', 'Simulador de vuelo ultrarrealista.', '2020-08-18', 59.99, 2, ''),
(99, 1, 12, 'Valheim con img', 'Supervivencia y exploración en un mundo vikingo.', '2021-02-02', 19.99, 2, 'img_67f7ed56434ec3.66535265.png'),
(103, 1, 12, 'Valheim con img wewewew', NULL, '2021-02-02', 19.99, 2, 'img_67f7ed56434ec3.66535265.png');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `juegos_plataformas`
--

CREATE TABLE `juegos_plataformas` (
  `idjuego_plataforma` int UNSIGNED NOT NULL,
  `idjuego` int NOT NULL,
  `idplataforma` int NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Volcado de datos para la tabla `juegos_plataformas`
--

INSERT INTO `juegos_plataformas` (`idjuego_plataforma`, `idjuego`, `idplataforma`) VALUES
(1, 1, 1),
(2, 2, 1),
(3, 3, 1),
(4, 4, 1),
(5, 5, 1),
(6, 6, 1),
(7, 7, 1),
(8, 8, 1),
(9, 9, 1),
(10, 10, 1),
(11, 11, 1),
(12, 12, 1),
(13, 13, 1),
(14, 14, 1),
(15, 15, 1),
(16, 16, 1),
(17, 17, 1),
(18, 18, 1),
(19, 19, 1),
(20, 20, 1),
(21, 21, 1),
(22, 22, 1),
(23, 23, 1),
(24, 24, 1),
(25, 25, 1),
(26, 26, 1),
(27, 27, 1),
(28, 28, 1),
(29, 29, 1),
(30, 30, 1),
(31, 31, 1),
(32, 32, 1),
(33, 33, 1),
(34, 34, 1),
(35, 35, 1),
(36, 36, 1),
(37, 37, 1),
(38, 39, 1),
(39, 40, 1),
(40, 41, 1),
(41, 42, 1),
(42, 43, 1),
(43, 44, 1),
(44, 45, 1),
(45, 46, 1),
(46, 47, 1),
(47, 48, 1),
(48, 49, 1),
(49, 50, 1),
(50, 51, 1),
(51, 52, 1),
(52, 53, 1),
(53, 54, 1),
(54, 55, 1),
(55, 56, 1),
(56, 57, 1),
(57, 58, 1),
(58, 59, 1),
(59, 60, 1),
(60, 1, 2),
(61, 2, 2),
(62, 3, 2),
(63, 5, 2),
(64, 6, 2),
(65, 7, 2),
(66, 8, 2),
(67, 9, 2),
(68, 10, 2),
(69, 11, 2),
(70, 12, 2),
(71, 13, 2),
(72, 15, 2),
(73, 16, 2),
(74, 17, 2),
(75, 18, 2),
(76, 19, 2),
(77, 20, 2),
(78, 21, 2),
(79, 24, 2),
(80, 26, 2),
(81, 27, 2),
(82, 28, 2),
(83, 29, 2),
(84, 30, 2),
(85, 35, 2),
(86, 36, 2),
(87, 37, 2),
(88, 38, 2),
(89, 40, 2),
(90, 41, 2),
(91, 42, 2),
(92, 43, 2),
(93, 44, 2),
(94, 45, 2),
(95, 46, 2),
(96, 47, 2),
(97, 48, 2),
(98, 49, 2),
(99, 50, 2),
(100, 51, 2),
(101, 52, 2),
(102, 53, 2),
(103, 54, 2),
(104, 58, 2),
(105, 59, 2),
(106, 60, 2),
(107, 1, 3),
(108, 2, 3),
(109, 3, 3),
(110, 5, 3),
(111, 6, 3),
(112, 7, 3),
(113, 8, 3),
(114, 9, 3),
(115, 10, 3),
(116, 11, 3),
(117, 12, 3),
(118, 13, 3),
(119, 15, 3),
(120, 16, 3),
(121, 17, 3),
(122, 18, 3),
(123, 19, 3),
(124, 20, 3),
(125, 21, 3),
(126, 24, 3),
(127, 26, 3),
(128, 27, 3),
(129, 28, 3),
(130, 29, 3),
(131, 30, 3),
(132, 35, 3),
(133, 36, 3),
(134, 37, 3),
(135, 38, 3),
(136, 40, 3),
(137, 41, 3),
(138, 42, 3),
(139, 43, 3),
(140, 44, 3),
(141, 45, 3),
(142, 46, 3),
(143, 47, 3),
(144, 48, 3),
(145, 49, 3),
(146, 50, 3),
(147, 51, 3),
(148, 52, 3),
(149, 53, 3),
(150, 54, 3),
(151, 58, 3),
(152, 59, 3),
(153, 60, 3),
(154, 1, 4),
(155, 2, 4),
(156, 4, 4),
(157, 7, 4),
(158, 10, 4),
(159, 12, 4),
(160, 16, 4),
(161, 22, 4),
(162, 25, 4),
(163, 34, 4),
(164, 39, 4),
(165, 55, 6),
(166, 56, 6),
(167, 57, 6),
(168, 55, 7),
(169, 56, 7),
(170, 57, 7);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `metodos_pago`
--

CREATE TABLE `metodos_pago` (
  `idmetodo` int NOT NULL,
  `nombre` varchar(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `metodos_pago`
--

INSERT INTO `metodos_pago` (`idmetodo`, `nombre`) VALUES
(1, 'Tarjeta de Crédito'),
(2, 'PayPal'),
(3, 'Transferencia Bancaria');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `pagos`
--

CREATE TABLE `pagos` (
  `idpago` int NOT NULL,
  `idpedido` int NOT NULL,
  `idmetodo` int NOT NULL,
  `monto` decimal(10,2) NOT NULL,
  `fecha` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `estado` enum('éxito','fallido','pendiente') DEFAULT 'pendiente'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `pagos`
--

INSERT INTO `pagos` (`idpago`, `idpedido`, `idmetodo`, `monto`, `fecha`, `estado`) VALUES
(1, 1, 1, 59.99, '2024-06-01 14:35:00', 'éxito'),
(2, 2, 2, 129.98, '2024-06-02 18:25:00', 'éxito'),
(3, 3, 1, 69.99, '2024-06-03 20:50:00', 'éxito'),
(4, 4, 3, 59.99, '2024-06-04 13:20:00', 'éxito'),
(5, 5, 1, 119.98, '2024-06-05 15:05:00', 'éxito'),
(6, 6, 2, 69.99, '2024-06-06 17:35:00', 'éxito'),
(7, 7, 1, 59.99, '2024-06-07 21:25:00', 'éxito'),
(8, 8, 3, 129.98, '2024-06-08 14:05:00', 'éxito'),
(9, 9, 1, 69.99, '2024-06-09 19:50:00', 'éxito'),
(10, 10, 2, 59.99, '2024-06-10 12:35:00', 'éxito'),
(11, 11, 1, 119.98, '2024-06-11 16:20:00', 'éxito'),
(12, 12, 3, 69.99, '2024-06-12 18:05:00', 'éxito'),
(13, 13, 1, 59.99, '2024-06-13 20:35:00', 'éxito'),
(14, 14, 2, 129.98, '2024-06-14 13:50:00', 'éxito'),
(15, 15, 1, 69.99, '2024-06-15 17:25:00', 'éxito');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `pedidos`
--

CREATE TABLE `pedidos` (
  `idpedido` int NOT NULL,
  `idusuario` int NOT NULL,
  `total` decimal(10,2) NOT NULL,
  `estado` enum('pendiente','completado','cancelado') DEFAULT 'pendiente',
  `fecha` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `pedidos`
--

INSERT INTO `pedidos` (`idpedido`, `idusuario`, `total`, `estado`, `fecha`) VALUES
(1, 1, 59.99, 'completado', '2024-06-01 14:30:00'),
(2, 3, 129.98, 'pendiente', '2024-06-02 18:20:00'),
(3, 5, 69.99, 'completado', '2024-06-03 20:45:00'),
(4, 2, 59.99, 'completado', '2024-06-04 13:15:00'),
(5, 7, 119.98, 'pendiente', '2024-06-05 15:00:00'),
(6, 4, 69.99, 'completado', '2024-06-06 17:30:00'),
(7, 9, 59.99, 'completado', '2024-06-07 21:20:00'),
(8, 6, 129.98, 'completado', '2024-06-08 14:00:00'),
(9, 8, 69.99, 'pendiente', '2024-06-09 19:45:00'),
(10, 10, 59.99, 'completado', '2024-06-10 12:30:00'),
(11, 12, 119.98, 'completado', '2024-06-11 16:15:00'),
(12, 11, 69.99, 'completado', '2024-06-12 18:00:00'),
(13, 14, 59.99, 'completado', '2024-06-13 20:30:00'),
(14, 13, 129.98, 'pendiente', '2024-06-14 13:45:00'),
(15, 15, 69.99, 'completado', '2024-06-15 17:20:00'),
(16, 16, 58.00, 'completado', '2025-07-29 17:54:55');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `plataformas`
--

CREATE TABLE `plataformas` (
  `idplataforma` int NOT NULL,
  `idestatus` int NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `descripcion` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `plataformas`
--

INSERT INTO `plataformas` (`idplataforma`, `idestatus`, `nombre`, `descripcion`) VALUES
(1, 1, 'PC', 'Computadoras personales'),
(2, 1, 'PlayStation 5', 'Consola de Sony lanzada en 2020'),
(3, 1, 'Xbox Series X', 'Consola de Microsoft lanzada en 2020'),
(4, 1, 'Nintendo Switch', 'Consola híbrida de Nintendo lanzada en 2017'),
(5, 1, 'PlayStation 4', 'Consola de Sony lanzada en 2013'),
(6, 1, 'Xbox One', 'Consola de Microsoft lanzada en 2013'),
(7, 1, 'iOS', 'Sistema operativo móvil de Apple'),
(8, 1, 'Android', 'Sistema operativo móvil de Google'),
(9, 1, 'Mac', 'Computadoras de Apple'),
(10, 1, 'Linux', 'Sistema operativo de código abierto');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios`
--

CREATE TABLE `usuarios` (
  `idusuario` int NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `rol` enum('cliente','admin') DEFAULT 'cliente',
  `fechacreacion` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `activo` tinyint(1) DEFAULT '1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Volcado de datos para la tabla `usuarios`
--

INSERT INTO `usuarios` (`idusuario`, `nombre`, `email`, `password`, `rol`, `fechacreacion`, `activo`) VALUES
(1, 'Ana García', 'ana.garcia@admin.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'admin', '2025-07-29 15:15:48', 1),
(2, 'Carlos Mendoza', 'carlos.mendoza@admin.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'admin', '2025-07-29 15:15:48', 1),
(3, 'Luis Pérez', 'luis.perez@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(4, 'María López', 'maria.lopez@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(5, 'Jorge Ramírez', 'jorge.ramirez@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(6, 'Sofía Torres', 'sofia.torres@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(7, 'Diego Fernández', 'diego.fernandez@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(8, 'Valentina Díaz', 'valentina.diaz@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(9, 'Andrés Castro', 'andres.castro@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(10, 'Camila Ruiz', 'camila.ruiz@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(11, 'Felipe Ortega', 'felipe.ortega@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(12, 'Lucía Méndez', 'lucia.mendez@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(13, 'Mateo Silva', 'mateo.silva@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(14, 'Isabella Vargas', 'isabella.vargas@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(15, 'Nicolás Paredes', 'nicolas.paredes@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(16, 'Emilia Navarro', 'emilia.navarro@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(17, 'Tomás Jiménez', 'tomas.jimenez@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(18, 'Antonella Rojas', 'antonella.rojas@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(19, 'Sebastián Castro', 'sebastian.castro@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1),
(20, 'Renata Soto', 'renata.soto@cliente.com', '$2b$10$E6zGxM3Z7Z0eJtq.sv3p7uQ7i0Y9X1a2b3c4d5e6f7g8h9i0j1k2l3m4', 'cliente', '2025-07-29 15:15:48', 1);

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `carrito`
--
ALTER TABLE `carrito`
  ADD PRIMARY KEY (`idcarrito`),
  ADD UNIQUE KEY `unique_item_per_user` (`idusuario`,`idjuego`),
  ADD KEY `idjuego` (`idjuego`);

--
-- Indices de la tabla `detalle_pedido`
--
ALTER TABLE `detalle_pedido`
  ADD PRIMARY KEY (`iddetalle`),
  ADD KEY `idpedido` (`idpedido`),
  ADD KEY `idjuego` (`idjuego`);

--
-- Indices de la tabla `estatus`
--
ALTER TABLE `estatus`
  ADD PRIMARY KEY (`idestatus`);

--
-- Indices de la tabla `generos`
--
ALTER TABLE `generos`
  ADD PRIMARY KEY (`idgenero`);

--
-- Indices de la tabla `juegos`
--
ALTER TABLE `juegos`
  ADD PRIMARY KEY (`idjuego`);

--
-- Indices de la tabla `juegos_plataformas`
--
ALTER TABLE `juegos_plataformas`
  ADD PRIMARY KEY (`idjuego_plataforma`);

--
-- Indices de la tabla `metodos_pago`
--
ALTER TABLE `metodos_pago`
  ADD PRIMARY KEY (`idmetodo`);

--
-- Indices de la tabla `pagos`
--
ALTER TABLE `pagos`
  ADD PRIMARY KEY (`idpago`),
  ADD KEY `idpedido` (`idpedido`),
  ADD KEY `idmetodo` (`idmetodo`);

--
-- Indices de la tabla `pedidos`
--
ALTER TABLE `pedidos`
  ADD PRIMARY KEY (`idpedido`),
  ADD KEY `idusuario` (`idusuario`);

--
-- Indices de la tabla `plataformas`
--
ALTER TABLE `plataformas`
  ADD PRIMARY KEY (`idplataforma`);

--
-- Indices de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`idusuario`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `carrito`
--
ALTER TABLE `carrito`
  MODIFY `idcarrito` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `detalle_pedido`
--
ALTER TABLE `detalle_pedido`
  MODIFY `iddetalle` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `estatus`
--
ALTER TABLE `estatus`
  MODIFY `idestatus` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT de la tabla `generos`
--
ALTER TABLE `generos`
  MODIFY `idgenero` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=43;

--
-- AUTO_INCREMENT de la tabla `juegos`
--
ALTER TABLE `juegos`
  MODIFY `idjuego` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=114;

--
-- AUTO_INCREMENT de la tabla `juegos_plataformas`
--
ALTER TABLE `juegos_plataformas`
  MODIFY `idjuego_plataforma` int UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=171;

--
-- AUTO_INCREMENT de la tabla `metodos_pago`
--
ALTER TABLE `metodos_pago`
  MODIFY `idmetodo` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de la tabla `pagos`
--
ALTER TABLE `pagos`
  MODIFY `idpago` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT de la tabla `pedidos`
--
ALTER TABLE `pedidos`
  MODIFY `idpedido` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT de la tabla `plataformas`
--
ALTER TABLE `plataformas`
  MODIFY `idplataforma` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  MODIFY `idusuario` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `carrito`
--
ALTER TABLE `carrito`
  ADD CONSTRAINT `carrito_ibfk_1` FOREIGN KEY (`idusuario`) REFERENCES `usuarios` (`idusuario`) ON DELETE CASCADE,
  ADD CONSTRAINT `carrito_ibfk_2` FOREIGN KEY (`idjuego`) REFERENCES `juegos` (`idjuego`) ON DELETE CASCADE;

--
-- Filtros para la tabla `detalle_pedido`
--
ALTER TABLE `detalle_pedido`
  ADD CONSTRAINT `detalle_pedido_ibfk_1` FOREIGN KEY (`idpedido`) REFERENCES `pedidos` (`idpedido`) ON DELETE CASCADE,
  ADD CONSTRAINT `detalle_pedido_ibfk_2` FOREIGN KEY (`idjuego`) REFERENCES `juegos` (`idjuego`) ON DELETE CASCADE;

--
-- Filtros para la tabla `pagos`
--
ALTER TABLE `pagos`
  ADD CONSTRAINT `pagos_ibfk_1` FOREIGN KEY (`idpedido`) REFERENCES `pedidos` (`idpedido`) ON DELETE CASCADE,
  ADD CONSTRAINT `pagos_ibfk_2` FOREIGN KEY (`idmetodo`) REFERENCES `metodos_pago` (`idmetodo`);

--
-- Filtros para la tabla `pedidos`
--
ALTER TABLE `pedidos`
  ADD CONSTRAINT `pedidos_ibfk_1` FOREIGN KEY (`idusuario`) REFERENCES `usuarios` (`idusuario`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
