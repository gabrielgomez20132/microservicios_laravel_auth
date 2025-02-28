FROM php:8.1-apache

RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg62-turbo-dev \
    libfreetype6-dev \
    liboning-dev \
    zip \
    unzip \
    git \
    curl \
    libxml2-dev \
    libzip-dev \
    libssl-dev \
    && docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd xml

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY . .

RUN composer install --no-dev --optimize-autoloader

EXPOSE 80

#RUN chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache
COPY default.conf /etc/apache2/sites-available/000-default.conf

RUN a2enmod rewrite