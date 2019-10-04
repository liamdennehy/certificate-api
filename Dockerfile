# RUN useradd --no-log-init -r -g $DATA_GID certs
# RUN apk add --update openssl-dev && docker-php-ext-install intl openssl mbstring
# RUN groupadd -r certs && useradd --no-log-init -r -g certs certs
# USER certs
