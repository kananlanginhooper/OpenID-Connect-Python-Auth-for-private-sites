# Apache + mod_auth_openidc: puts any HTTP site behind sign-in at the provider.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends apache2 libapache2-mod-auth-openidc ca-certificates \
 && a2enmod auth_openidc proxy proxy_http headers \
 && a2dissite 000-default && rm -rf /var/lib/apt/lists/* \
 && ln -sf /dev/stdout /var/log/apache2/access.log && ln -sf /dev/stderr /var/log/apache2/error.log
COPY gate.conf /etc/apache2/sites-enabled/gate.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/80'
ENTRYPOINT ["/entrypoint.sh"]
