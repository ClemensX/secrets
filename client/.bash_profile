echo found your profile .bash_profile in ~
alias go_crypto='cd /c/dev/server/docker/Crypto/'
alias go_secrets='cd /c/dev/server/docker/secrets'
alias go_client='cd /c/dev/server/docker/secrets/client'
#alias sc='java --module-path "../../../../repos/Crypto/target/crypto-0.0.1-SNAPSHOT.jar;../../../../repos/Crypto/target/javax.json-api-1.1.2.jar;../../../../repos/Crypto/target/javax.json-1.1.2.jar;target/secrets.client-0.0.1-SNAPSHOT.jar;../secrets/target/secrets-0.0.1-SNAPSHOT.jar" --module de.fehrprice.secrets.client/de.fehrprice.secrets.client.SecretsClient'
#alias sc='java --module-path "../../Crypto/target/crypto-0.0.1-SNAPSHOT.jar;../../Crypto/target/javax.json-api-1.1.2.jar;../../Crypto/target/javax.json-1.1.2.jar;target/secrets.client-0.0.1-SNAPSHOT.jar;../secrets/target/secrets-0.0.1-SNAPSHOT.jar" --module de.fehrprice.secrets.client/de.fehrprice.secrets.client.SecretsClient'
alias sc='java --module-path "./target/client-0.0.1-SNAPSHOT.jar;../crypto/target/fehrprice.crypto-0.0.1-SNAPSHOT.jar;../crypto/target/javax.json-api-1.1.2.jar;../crypto/target/javax.json-1.1.2.jar;../common/target/common-0.0.1-SNAPSHOT.jar" --module client/de.fehrprice.secrets.client.SecretsClient'
