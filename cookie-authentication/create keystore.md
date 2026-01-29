keytool -genkeypair \
-alias localhost \
-keyalg RSA \
-keysize 2048 \
-storetype PKCS12 \
-keystore src/main/resources/keystore.p12 \
-validity 3650 \
-storepass changeit \
-keypass changeit \
-dname "CN=localhost, OU=Dev, O=MyOrg, L=City, ST=State, C=RU"