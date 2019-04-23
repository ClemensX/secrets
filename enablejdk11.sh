export JAVA_HOME=/c/tools/openjdk11
#export JAVA_HOME=/c/tools/oraclejdk8
export PATH=${JAVA_HOME}/bin:${PATH}
export HOMEDRIVE=C:
alias sc='java --module-path  "../../Crypto/target/crypto-0.0.1-SNAPSHOT.jar;../../Crypto/target/javax.json-api-1.1.2.jar;../../Crypto/target/javax.json-1.1.2.jar;target/secrets.client-0.0.1-SNAPSHOT.jar;../secrets/target/secrets-0.0.1-SNAPSHOT.jar" --module de.fehrprice.secrets.client/de.fehrprice.secrets.client.SecretsClient "$@"'