# This script will be run automatically by the Cloud Foundry Java Buildpack before the app is launched

mkdir -p "$HOME/.mysql/"


echo "$VCAP_SERVICES" | jq -r '.["csb-google-mysql"][0].credentials.sslrootcert' > "$HOME/.mysql/ca.pem"
echo "$VCAP_SERVICES" | jq -r '.["csb-google-mysql"][0].credentials.sslcert' > "$HOME/.mysql/client-cert.pem"
echo "$VCAP_SERVICES" | jq -r '.["csb-google-mysql"][0].credentials.sslkey' > "$HOME/.mysql/client-key.pem"

keytool -importcert                       \
  -alias MySQLCACert                      \
  -file "$HOME/.mysql/ca.pem"             \
  -noprompt                               \
  -keystore "$HOME/.mysql/truststore"     \
  -storepass "${KEYSTORE_PASSWORD}"

openssl pkcs12 -export                    \
  -in "$HOME/.mysql/client-cert.pem"      \
  -inkey "$HOME/.mysql/client-key.pem"    \
  -name "mysqlclient"                     \
  -passout "pass:${KEYSTORE_PASSWORD}"    \
  -out "$HOME/.mysql/client-keystore.p12"

keytool -importkeystore                           \
  -srckeystore "$HOME/.mysql/client-keystore.p12" \
  -srcstoretype pkcs12                            \
  -srcstorepass "${KEYSTORE_PASSWORD}"            \
  -destkeystore "$HOME/.mysql/keystore"           \
  -deststoretype pkcs12                           \
  -deststorepass "${KEYSTORE_PASSWORD}"

openssl pkcs8 -topk8 -inform PEM -in "$HOME/.mysql/client-key.pem" -outform DER -out "$HOME/.mysql/client.pk8" -v1 PBE-MD5-DES -nocrypt
chmod 0600 "$HOME/.mysql/client-key.pem" "/$HOME/.mysql/client.pk8"

export VCAP_SERVICES="$(echo "$VCAP_SERVICES" | jq '."csb-google-mysql"[0].credentials.jdbcUrl += "&trustCertificateKeyStoreUrl=file://\($ENV.HOME)/.mysql/truststore&trustCertificateKeyStorePassword=\($ENV.KEYSTORE_PASSWORD)&clientCertificateKeyStoreUrl=file://\($ENV.HOME)/.mysql/keystore&clientCertificateKeyStorePassword=\($ENV.KEYSTORE_PASSWORD)"')"
