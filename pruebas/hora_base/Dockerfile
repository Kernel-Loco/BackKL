# Solo para la prueba de la hora de la base (RC-313, punto 3b). La misma imagen de la base del compose, que llega en
# PG_IMAGE, más libfaketime. Nunca se usa en la VM ni en la pila local: la levanta pruebas/hora_base/docker-compose.yml.
ARG PG_IMAGE
FROM ${PG_IMAGE}
RUN apt-get update -q && apt-get install -y -q --no-install-recommends libfaketime \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(dpkg -L libfaketime | grep '/libfaketime\.so\.1$')" /usr/local/lib/libfaketime.so.1 \
 && test -e /usr/local/lib/libfaketime.so.1
