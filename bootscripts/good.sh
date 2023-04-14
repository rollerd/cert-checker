apt-get update -y && apt install -y nginx openssl faketime
faketime "$(date +"%Y-%m-%d %T" -d "- 1 hour")" /bin/bash -c 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 32 -nodes -subj "/C=US/ST=PA/L=Philadelphia/O=TestCert/OU=DevOps/CN=example.com"'
mv /scripts/cert.pem /etc/ssl/private
mv /scripts/key.pem /etc/ssl/private
cp nginx/default.conf /etc/nginx/conf.d/
nginx -g "daemon off;"
echo "STARTED"
