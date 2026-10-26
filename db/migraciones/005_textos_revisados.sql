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
-- Corre en una sola transacción y se puede correr otra vez sin error.
-- En una base que ya existe se aplica a mano (ver db/README.md).
-- =====================================================================

BEGIN;

-- Sin los textos de la 003, un UPDATE no cambiaría nada y no daría error.
DO $$
DECLARE
  faltan text;
BEGIN
  SELECT string_agg(c, ', ') INTO faltan
    FROM unnest(ARRAY[
    'breach_exposure', 'cert_expired', 'outdated_software', 'exposed_rdp',
    'dmarc_missing', 'spf_missing', 'lookalike_domain', 'cert_expiring_soon',
    'domain_expiring_soon', 'spf_allow_all', 'dmarc_policy_none', 'secret_in_public_repo',
    'email_in_public_commits', 'breach_exposure_old', 'breach_exposure_no_passwords', 'personal_email_exposed',
    'email_pattern_exposed', 'exposed_remote_admin', 'exposed_file_sharing', 'exposed_database',
    'exposed_ot_device', 'exposed_iot_device', 'exposed_service', 'known_vulnerability',
    'server_version_disclosed', 'public_bucket', 'subdomain_takeover_risk', 'exposed_api_docs',
    'secret_in_container_image']) AS c
   WHERE NOT EXISTS (SELECT 1 FROM scoring_rule_texts t WHERE t.code = c);
  IF faltan IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan los textos de la migración 003 para: %. Aplica primero la 003.', faltan;
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
