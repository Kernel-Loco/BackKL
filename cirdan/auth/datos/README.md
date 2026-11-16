# Contraseñas comunes (RC-281)

`contrasenas_comunes.txt` tiene 46 146 contraseñas comunes, una por línea, de 12 a 128 caracteres. La API rechaza
una contraseña nueva que esté aquí, sin importar mayúsculas (`is_common` en `cirdan/auth/passwords.py`). Las de menos
de 12 caracteres no hacen falta: ya las frena `MIN_LENGTH`.

## Fuente

- SecLists de Daniel Miessler: https://github.com/danielmiessler/SecLists
- Archivo: `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt` (el millón más usado de la lista
  de 10 millones de xato.net, ordenado de más a menos usado)
- Commit: `180c2d55afa7aab8b18b7552f82dd0c92cc4ede5` (15 nov 2026), bajado el 16 nov 2026
- sha256 del archivo original: `424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51`

## Filtro

Del archivo original quedan, en el mismo orden, las líneas en UTF-8 de 12 a 128 caracteres, imprimibles y sin
espacios al principio ni al final. Si dos solo cambian en mayúsculas, queda la primera. sha256 del resultado:
`b598c8021dc44336d2b76c2375ced2e75e98208d1e9b229d878c5318eadc39d3`.

## Licencia

MIT, Copyright (c) 2018 Daniel Miessler. El texto completo está en `LICENSE-SecLists`, que va junto a la lista en la
imagen de la API.
