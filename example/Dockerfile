# Multi-stage Dockerfile for building Nginx with zstd-nginx-module
# 
# This Dockerfile demonstrates how to build a production-ready Nginx image
# with the zstd compression module integrated.
#
# Usage:
#   docker build -t nginx-zstd:latest .
#   docker run -d -p 80:80 nginx-zstd:latest

ARG NGINX_VERSION=1.26.0

# Build stage
FROM nginx:${NGINX_VERSION} AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    libzstd-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download and extract Nginx source
WORKDIR /build
RUN wget -q http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -xzf nginx-${NGINX_VERSION}.tar.gz

# Copy zstd-nginx-module source
COPY . /build/zstd-nginx-module

# Configure and build Nginx with zstd module
WORKDIR /build/nginx-${NGINX_VERSION}
RUN ./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=nginx \
    --group=nginx \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_sub_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_stub_status_module \
    --with-http_auth_request_module \
    --with-http_v2_module \
    --with-http_slice_module \
    --with-threads \
    --with-file-aio \
    --add-module=/build/zstd-nginx-module && \
    make -j$(nproc) && \
    make install

# Runtime stage
FROM nginx:${NGINX_VERSION}

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libzstd1 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Nginx binary with zstd module
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx

# Copy example configuration (optional)
COPY example/nginx.conf /etc/nginx/nginx.conf.example

# Verify the module is loaded
RUN nginx -V 2>&1 | grep -q zstd || (echo "zstd module not found!" && exit 1)

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
