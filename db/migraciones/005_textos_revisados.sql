-- =====================================================================
-- Cirdan · db/migraciones/005_textos_revisados.sql (RC-66, #30)
-- Corrige 23 textos de scoring_rule_texts según la revisión de RC-66 del
-- 25 oct 2026 y llena reviewed_by de las 25 reglas OSINT (#14 a #20),
-- que revisa Ernesto. Las 5 de #62 a #64 siguen con reviewed_by NULL
-- hasta que las revise alguien de otra área (backlog.md fila 30).
-- No cambia la tabla, las reglas, los pesos ni los topes.
-- Un UPDATE por código con WHERE code = '...', como pide
-- docs/codigos_reglas.md, así pruebas/test_catalogo_reglas.py lee el
-- texto que queda al final. Nunca se edita la 003.
-- Corre en una sola transacción. Se puede correr otra vez sin error y
-- sin cambiar textos, pero vuelve a mover updated_at.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

BEGIN;

-- Antes de cambiar nada revisa las 29 filas. Sin los textos de la 003,
-- un UPDATE no cambiaría nada y no daría error. Si un texto no es el de
-- la 003 ni el de esta migración, o una regla OSINT la firmó otra
-- persona, alguien lo cambió después y esta migración no lo pisa.
-- antes y despues son el md5 del título, qué significa y qué hacer,
-- separados por un salto de línea.
DO $$
DECLARE
  faltan text;
  distintos text;
BEGIN
  SELECT string_agg(e.code, ', ') FILTER (WHERE t.code IS NULL),
         string_agg(e.code, ', ') FILTER (WHERE t.code IS NOT NULL AND (
           md5(t.title || E'\n' || t.meaning || E'\n' || t.recommendation) NOT IN (e.antes, e.despues)
           OR t.reviewed_by <> e.revisor))
    INTO faltan, distintos
    FROM (VALUES
      ('breach_exposure', 'dc3ebce1cc103e6f701fb216e6c04c53', '6e6be463cb92e99bb13e92c09427eac6', 'ErnestoDL'),
      ('cert_expired', '81603cf235798b119d0694e30ef2f1df', '10ce5ef8c40da02e8c11ff1001f61b36', 'ErnestoDL'),
      ('outdated_software', '835bd900d65823da54903559404afddb', '4c933e1e05689371e1762e1f4be97040', 'ErnestoDL'),
      ('exposed_rdp', '7f0774dbeffda84a64f9c5cb3a845105', 'febddd463aa1aa2e107b5848832965a6', 'ErnestoDL'),
      ('dmarc_missing', '24a9229b2d315dc2e28178271494e575', '1ad311237af2c08a8cfda7a9f567ed1a', 'ErnestoDL'),
      ('spf_missing', 'b2b56dca2b6200cf0f022cb66f3daf09', '717688b5c0965b36c3a56afc302a1436', 'ErnestoDL'),
      ('lookalike_domain', '84cbc3d84ce3b301f9b5488eac4f4ef8', '038659fed0157a563fe4bc08305bb77b', 'ErnestoDL'),
      ('cert_expiring_soon', '0a2ac71ab9463406dde3a445f8121292', 'd6cf7363b3cd2649901616798cf135bb', 'ErnestoDL'),
      ('domain_expiring_soon', '540a9e94fbc0e2d51805976c7b7b25de', '540a9e94fbc0e2d51805976c7b7b25de', 'ErnestoDL'),
      ('spf_allow_all', '48c305e835367cb96555c43524bed2f6', '48c305e835367cb96555c43524bed2f6', 'ErnestoDL'),
      ('dmarc_policy_none', 'e39ace3f5d4ac18c99ffdaa25679f614', 'b48ec79a55433d3d00e0411209cdd42f', 'ErnestoDL'),
      ('secret_in_public_repo', '3a1833b53f59eda05a15c145d109d3fa', '3a1833b53f59eda05a15c145d109d3fa', 'ErnestoDL'),
      ('email_in_public_commits', '192406672e3b7b22a68f5d0678327241', 'a1f3b277953bcded7c30ad6f19f3b613', 'ErnestoDL'),
      ('breach_exposure_old', '6f8562452ae40ceb3ee7a038075f053c', 'fd0900a2162918bb29568e3ed75a3c4e', 'ErnestoDL'),
      ('breach_exposure_no_passwords', '723e7758c2faf4f9eb5fc558594aa1de', 'da54e5ed0513185f459e1769009e87b1', 'ErnestoDL'),
      ('personal_email_exposed', 'c18d9477eefbad5809bea1f839eb6c64', 'c18d9477eefbad5809bea1f839eb6c64', 'ErnestoDL'),
      ('email_pattern_exposed', '26c24e8174a4882b1d06788e9bc32b70', '26c24e8174a4882b1d06788e9bc32b70', 'ErnestoDL'),
      ('exposed_remote_admin', '49a8cfc818ec49928171be102b594d6a', '643b88fb331a26fe4094c18bd2e2ba6c', 'ErnestoDL'),
      ('exposed_file_sharing', 'e2097bd189166b5018b3686e8995cdd2', 'e2ea47142eb06c1752b24b89c02a21b6', 'ErnestoDL'),
      ('exposed_database', '495cecd62f2ef5c0c7a0ea55d6a7b394', '7e0a68821aaa073fe34c7148f0c1abc7', 'ErnestoDL'),
      ('exposed_ot_device', '8ee624f7e9cacc7610cb2ec29b42ebea', '2fbee490988aa7d855fa72e6d5e52719', 'ErnestoDL'),
      ('exposed_iot_device', 'f0c3ab9a5ff21947973fed92261e5073', '7f40a31fc662701e9c5ef02067959175', 'ErnestoDL'),
      ('exposed_service', '3d3b7e3e7ab48486c524013eaafc67a0', '319981e59c1c334753c1e1e10a1670e2', 'ErnestoDL'),
      ('known_vulnerability', '95f80212e8175ebf6394c95a85ac2a73', '95f80212e8175ebf6394c95a85ac2a73', 'ErnestoDL'),
      ('server_version_disclosed', 'cfb25d9fe8ed10d68be1cb5463032196', '58a775947940cd04883d8ac88e5c0917', 'ErnestoDL'),
      ('public_bucket', '5c8eda0e56e741b1c4a75c6b485b28bb', '40ad96bf428a5ba3601c22fdebf2804b', NULL),
      ('subdomain_takeover_risk', '9d54f85297c9fd791c95a1e2332b811e', 'b688922c68a6897921bb55aa7fc81a9f', NULL),
      ('exposed_api_docs', '99a6f34baa18bd18329a7e0f83413ee5', 'fa31331d086fa694706ff67158e2c175', NULL),
      ('secret_in_container_image', '1b7f1aa78c604142f83fd58d68f92d25', '4f3a3b6ee76aa43037c9c6dc8f9aa088', NULL)
    ) AS e(code, antes, despues, revisor)
    LEFT JOIN scoring_rule_texts t ON t.code = e.code;
  IF faltan IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan los textos de la migración 003 para: %. Aplica primero la 003.', faltan;
  END IF;
  IF distintos IS NOT NULL THEN
    RAISE EXCEPTION 'Estos textos no son los de la 003 ni los de la 005, o los firmó otra persona: %. Revísalos antes de aplicarla.', distintos;
  END IF;
END $$;

-- En orden de id de la regla, como la 003.
UPDATE scoring_rule_texts SET
  title = 'Correos de la empresa en una filtración reciente al detectarla, con contraseñas u otros datos de acceso',
  meaning = 'Al menos un correo de la empresa aparece en una filtración de datos que incluía contraseñas, preguntas de seguridad u otros datos para entrar a cuentas y que, cuando se detectó, había ocurrido hacía menos de un año. Quien tenga esos datos puede intentar entrar a las cuentas de esas personas, también a las de la empresa si repiten la contraseña.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'breach_exposure';

UPDATE scoring_rule_texts SET
  title = 'El último certificado de seguridad publicado para un sitio de la empresa estaba vencido al detectarlo',
  recommendation = 'Pide a quien administra el sitio que renueve el certificado, si todavía no lo hizo, o que borre esa dirección de la configuración del dominio si el sitio ya no se usa. Pídele también que active la renovación automática para que no vuelva a pasar.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'cert_expired';

UPDATE scoring_rule_texts SET
  title = 'Software en una versión cuyo soporte del fabricante ya terminó',
  meaning = 'Por la versión que muestra, un sitio o equipo de la empresa usa un programa o sistema operativo cuyo fabricante ya terminó su soporte. Si nadie más le da actualizaciones de seguridad, como a veces hace el proveedor del sistema operativo, las fallas nuevas de esa versión ya no se van a corregir.',
  recommendation = 'Confirma con quien administra ese equipo si esa versión todavía recibe actualizaciones de seguridad y, si no, pídele que la cambie por una que tenga soporte. Si el reporte no dice qué programa es o no se puede actualizar pronto, pídele que limite quién puede llegar a él desde internet.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'outdated_software';

UPDATE scoring_rule_texts SET
  meaning = 'Según un buscador público de equipos en internet, un equipo de la empresa tenía abierta la entrada, o puerto, que suele usar el escritorio remoto de Windows, que permite manejarlo a distancia. Si de verdad es ese servicio, con una contraseña robada o adivinada alguien de fuera podría controlarlo.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_rdp';

UPDATE scoring_rule_texts SET
  recommendation = 'Pide a tu proveedor de correo que publique en la configuración del dominio una sola regla contra correos falsos, en modo de solo observar y con los reportes activados, y que los revise. Cuando confirme que tu correo legítimo pasa la revisión, pídele que la cambie para que los correos falsos vayan a correo no deseado o se rechacen, porque en modo de solo observar todavía no los frena.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'dmarc_missing';

UPDATE scoring_rule_texts SET
  recommendation = 'Publica en la configuración del dominio una sola lista con los servidores que de verdad envían el correo de la empresa, con los datos exactos que te dé tu proveedor de correo. Si ya publicas una, revisa que su final rechace o marque como sospechosos a los demás servidores.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'spf_missing';

UPDATE scoring_rule_texts SET
  meaning = 'Existe un dominio, o una dirección dentro de un dominio ajeno, que no figura en este portal como de la empresa, contiene o imita su nombre y tiene o tuvo hace poco un certificado de seguridad. Puede ser de la propia empresa o de alguien legítimo, pero también puede usarse para crear sitios o correos falsos que suplanten a la empresa.',
  recommendation = 'Si el dominio es de la empresa, dalo de alta en este portal. Si no, pide a tu área legal o a tu proveedor de seguridad que revise quién lo registró y qué publica, sin entrar tú al sitio, y si suplanta a la empresa, pide su baja a la empresa donde se registró o a la que lo aloja y avisa a tus clientes.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'lookalike_domain';

UPDATE scoring_rule_texts SET
  meaning = 'Según los registros públicos de certificados, cuando se detectó, al más reciente de este sitio le quedaban menos de 30 días de vigencia. Si el sitio sigue usando ese certificado y no se renueva a tiempo, los navegadores mostrarán una alerta a quien lo visite.',
  recommendation = 'Pide a quien administra el sitio que renueve el certificado, si todavía no lo hizo, y que active la renovación automática. Si el sitio ya no se usa, pídele que borre esa dirección de la configuración del dominio.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'cert_expiring_soon';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'domain_expiring_soon';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'spf_allow_all';

UPDATE scoring_rule_texts SET
  recommendation = 'Pide a tu proveedor de correo que active los reportes de la regla, si todavía no llegan, y que los revise para confirmar que tu correo legítimo pasa la revisión. Después pídele que cambie la regla para que los correos falsos vayan a correo no deseado o se rechacen.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'dmarc_policy_none';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'secret_in_public_repo';

UPDATE scoring_rule_texts SET
  meaning = 'Este correo de la empresa aparece como autor de cambios, o como quien los subió, en el código público de la organización en GitHub. Cualquiera puede verlo y usarlo para mandar correos engañosos a quien revise ese buzón.',
  recommendation = 'Pide a quienes publican en GitHub que usen en sus cambios el correo privado que GitHub les ofrece. Los cambios ya publicados se quedan, así que avisa a quien revise ese buzón para que desconfíe de correos sospechosos.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'email_in_public_commits';

UPDATE scoring_rule_texts SET
  title = 'Correos de la empresa en una filtración antigua al detectarla, con contraseñas u otros datos de acceso',
  meaning = 'Al menos un correo de la empresa aparece en una filtración de datos que incluía contraseñas, preguntas de seguridad u otros datos para entrar a cuentas y que, cuando se detectó, había ocurrido hacía más de un año. El riesgo sigue si esas personas no cambiaron esos datos o repiten la contraseña en otros servicios.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'breach_exposure_old';

UPDATE scoring_rule_texts SET
  meaning = 'Al menos un correo de la empresa aparece en una filtración o lista de datos que no incluye contraseñas, preguntas de seguridad ni otros datos para entrar a cuentas, aunque puede traer otros datos personales o de pago. Esos datos sirven para mandar correos falsos dirigidos a esas personas y, si incluyen datos de pago o de identidad, también para cometer fraudes.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'breach_exposure_no_passwords';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'personal_email_exposed';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'email_pattern_exposed';

UPDATE scoring_rule_texts SET
  title = 'Puerto de control a distancia abierto a internet',
  meaning = 'Según un buscador público de equipos en internet, un equipo de la empresa tenía abierta una entrada, o puerto, de las que suelen usar los servicios para manejarlo a distancia por comandos o viendo su pantalla, distintos del escritorio remoto de Windows. Si de verdad es uno de esos servicios, con una contraseña robada o adivinada alguien de fuera podría controlarlo.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_remote_admin';

UPDATE scoring_rule_texts SET
  meaning = 'Según un buscador público de equipos en internet, un equipo de la empresa tenía abierta una entrada, o puerto, de las que suelen usar los servicios para compartir archivos. Si de verdad es uno de esos servicios, con una contraseña robada o adivinada o una falla conocida alguien de fuera podría leer o cambiar esos archivos.',
  recommendation = 'Pide a tu proveedor de sistemas que cierre ese puerto a internet. Comparte archivos solo dentro de la red de la empresa o con una herramienta que pida verificación en dos pasos.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_file_sharing';

UPDATE scoring_rule_texts SET
  title = 'Puerto de base de datos abierto a internet',
  meaning = 'Según un buscador público de equipos en internet, un equipo de la empresa tenía abierta una entrada, o puerto, de las que suelen usar las bases de datos. Si de verdad es una, con una contraseña robada o adivinada o un error de configuración alguien de fuera podría leer o cambiar sus datos.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_database';

UPDATE scoring_rule_texts SET
  meaning = 'Según un buscador público de equipos en internet, un equipo que controla procesos industriales o de edificios respondía desde internet con un lenguaje de comunicación industrial. Esa comunicación casi nunca pide contraseña, así que cualquiera que llegue podría leer o cambiar valores del proceso.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_ot_device';

UPDATE scoring_rule_texts SET
  meaning = 'Según un buscador público de equipos en internet, un dispositivo como una cámara, un grabador de video, un módem o una impresora respondía desde internet. Con la contraseña de fábrica o una falla conocida, alguien de fuera podría tomar el control o ver lo que transmite.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_iot_device';

UPDATE scoring_rule_texts SET
  meaning = 'Según un buscador público de equipos en internet, un equipo de la empresa tenía abierta una entrada distinta de las usuales para sitios web y correo. Por sí sola no da acceso, pero cada entrada abierta es una puerta más que alguien puede intentar usar.',
  recommendation = 'Confirma con tu proveedor de sistemas si ese servicio sigue abierto a internet y si debe estarlo, porque el dato puede tener días. Si no se usa o es solo interno, pídele que lo cierre o que limite quién puede conectarse.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'exposed_service';

UPDATE scoring_rule_texts SET
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'known_vulnerability';

UPDATE scoring_rule_texts SET
  recommendation = 'Pide a quien administra el sitio que configure el servidor para que no muestre el nombre ni la versión de sus programas. Pídele también que mantenga esa versión al día aunque ya no se vea.',
  reviewed_by = 'ErnestoDL',
  updated_at = now()
WHERE code = 'server_version_disclosed';

UPDATE scoring_rule_texts SET
  recommendation = 'Pide a quien administra ese almacenamiento que quite el acceso público si no es a propósito y que revise qué archivos contiene. Si debe ser público, confirma con esa persona que no guarde datos internos ni de clientes.',
  updated_at = now()
WHERE code = 'public_bucket';

UPDATE scoring_rule_texts SET
  recommendation = 'Pide a quien administra el dominio que borre ese subdominio de su configuración si ya no se usa, o que vuelva a crear el espacio de almacenamiento a nombre de la empresa. Pídele también que revise los demás subdominios que apunten a servicios que ya no usas.',
  updated_at = now()
WHERE code = 'subdomain_takeover_risk';

UPDATE scoring_rule_texts SET
  recommendation = 'Pide a quien programa el servicio que quite la documentación de internet o que pida inicio de sesión para verla. Déjala pública solo si el servicio está pensado para usarse desde fuera.',
  updated_at = now()
WHERE code = 'exposed_api_docs';

UPDATE scoring_rule_texts SET
  recommendation = 'Cambia o anula la clave de inmediato en el servicio que la emitió. Después pide a quien programa que reconstruya la imagen sin la clave y que borre las versiones viejas que la contienen.',
  updated_at = now()
WHERE code = 'secret_in_container_image';

COMMIT;
