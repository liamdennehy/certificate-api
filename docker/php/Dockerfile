FROM php:7.3-fpm-alpine
ENV DATA_GID=1000
RUN addgroup --gid ${DATA_GID} -S certs && adduser -S certs -G certs
RUN apk add --update gmp-dev && docker-php-ext-install gmp
USER certs
