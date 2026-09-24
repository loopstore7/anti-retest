FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install pdo_sqlite \
    && a2enmod rewrite headers \
    && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

ENV APACHE_DOCUMENT_ROOT=/var/www/html/web

COPY web/ /var/www/html/web/

RUN mkdir -p /var/www/html/data/registros \
    && chown -R www-data:www-data /var/www/html

ENV ANTIRETEST_DB=/var/www/html/data/antiretest.db
ENV ANTIRETEST_LOG_DIR=/var/www/html/data/registros

VOLUME ["/var/www/html/data"]

EXPOSE 80
