# Examples

This directory contains example configurations and Dockerfiles for using the zstd-nginx-module.

## Contents

- `nginx.conf` - Example Nginx configuration with zstd compression enabled
- `Dockerfile` - Multi-stage Dockerfile for building Nginx with zstd module

## Using the Dockerfile

Build the Docker image:

```bash
docker build -t nginx-zstd:latest .
```

Run the container:

```bash
docker run -d -p 80:80 --name nginx-zstd nginx-zstd:latest
```

Test zstd compression:

```bash
# Request with zstd accept-encoding
curl -H "Accept-Encoding: zstd" -I http://localhost/

# You should see "Content-Encoding: zstd" in the response headers
```

## Using the nginx.conf

The example configuration demonstrates:

1. **Basic zstd compression** - Enabled globally with compression level 3
2. **Compression thresholds** - Only compress responses larger than 256 bytes
3. **MIME type filtering** - Compress specific content types
4. **Static pre-compressed files** - Serve `.zst` files when available
5. **Logging compression ratio** - Track compression efficiency with `$zstd_ratio` variable

To use this configuration:

1. Copy it to your Nginx configuration directory:
   ```bash
   cp nginx.conf /etc/nginx/nginx.conf
   ```

2. Test the configuration:
   ```bash
   nginx -t
   ```

3. Reload Nginx:
   ```bash
   nginx -s reload
   ```

## Building Nginx Manually

If you prefer to build Nginx manually without Docker:

```bash
# Install dependencies
sudo apt-get install -y build-essential libpcre3-dev zlib1g-dev libssl-dev libzstd-dev

# Download Nginx source
wget http://nginx.org/download/nginx-1.26.0.tar.gz
tar -xzf nginx-1.26.0.tar.gz
cd nginx-1.26.0

# Configure with zstd module
./configure --prefix=/usr/local/nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --add-module=/path/to/zstd-nginx-module

# Build and install
make -j$(nproc)
sudo make install
```

## Testing Compression

After setting up Nginx with zstd module, you can test compression:

```bash
# Create a test HTML file
echo "<html><body><h1>Hello World</h1>$(yes 'Test content ' | head -1000)</body></html>" > /usr/share/nginx/html/test.html

# Request without compression
curl -H "Accept-Encoding:" http://localhost/test.html -o /tmp/uncompressed.html

# Request with zstd compression
curl -H "Accept-Encoding: zstd" http://localhost/test.html --compressed -o /tmp/compressed.html

# Compare sizes
ls -lh /tmp/uncompressed.html /tmp/compressed.html
```

## Advanced Configuration

### Using Zstd Dictionary

For even better compression ratios, you can use a pre-trained dictionary:

```nginx
http {
    # Specify dictionary file
    zstd_dict_file /etc/nginx/zstd_dict.bin;
    
    # ... rest of configuration
}
```

**Warning**: Both client and server must use the same dictionary. Ensure clients support your dictionary before enabling this feature.

### Static Pre-compressed Files

To serve pre-compressed `.zst` files:

```bash
# Pre-compress static files
zstd -k -19 /usr/share/nginx/html/large-file.js

# This creates large-file.js.zst
```

Nginx will automatically serve the `.zst` version when `zstd_static on;` is configured and the client supports zstd encoding.

## Performance Tips

1. **Compression Level**: Use levels 1-3 for dynamic content, 10-19 for static files
2. **Minimum Length**: Set `zstd_min_length` to avoid compressing small files
3. **MIME Types**: Only compress compressible content types
4. **Static Pre-compression**: Pre-compress static assets at build time
5. **Buffer Size**: Adjust `zstd_buffers` based on your content size

## Browser Support

Zstd compression is supported by:
- Chrome/Edge 123+
- Firefox 126+
- Safari (partial support)

Always include fallback compression methods (gzip, brotli) for broader compatibility.
