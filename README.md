# Secrets!

## Crypto Lib

[Details of the used cryptographic algorithms can be found here](README_CRYPTO.md)

## Client Usage

Secrets! stores info snippets as key/value pairs on our server. Each pair is associated with one or more tags for organizing your snippets.

Example usage:

List all tags you have used:  

```
C:\>sc tag
Your Taglist:
connect
server
login
microsoft
pw
github
bank
```
List all keys with tag pw (values will not be shown):  

```
C:\>sc tag pw
Your Snippets for tag pw:
microsoft_pw=
login.vr.pw=
login.tennis.pw=
```
Copy your microsoft password to clipboard:  

```
C:\>sc g microsoft_pw
Getting value for key microsoft_pw
value for microsoft_pw copied to clipboard.
```
Store your github password:  

```
C:\>sc +
Enter Key:
login.github.pw
Enter Value:
geheim
Enter Tags (separate with blanks):
pw github login
login.github.pw=geheim  [ pw github login ]
save snippet? [y]

snippet added to DB
```
Show your github password in console:  

```
C:\>sc get login.github.pw
Getting value for key login.github.pw
login.github.pw=geheim
```
Full client help page:

```
sc - The Secrets! Client. See details at http://fehrprice.de:5000/secrets

usage: sc command [<options>]

Commands:

 create
 c
 +                     interactively add new snippet

 tag                   get list of all your tags (CONSOLE DISPLAY)
 tag <name>            get list of all keys with tag 'name' (CONSOLE DISPLAY)
 tagfull <name>        get list of all key/values with tag 'name' (CONSOLE DISPLAY)

 g <key>               get snippet by key (COPY to CLIPBOARD - NO DISPLAY)

 get <key>             get snippet by key (CONSOLE DISPLAY)

 del <key>
 d <key>
 - <key>               delete snippet by key

 keygen                generate and print one 256 bit private key
 keygen <n>            generate and print n 256 bit private keys

 public                show your public key

 test                  test connection to Secrets! server

 id                    get your id from Secrets! server and store in config file

 configfile            show location of you config file

 server                interactively add or change the url of the Secrets! server

 setup                 interactively setup your Secrets! client

 private               interactively set full path and name to your private key file
```


## Start Server

### Pre-Preparations

This is what you need to install and configure on a clean end fresh Ubuntu 20 Server. All instructions as root.

#### Users
```
  adduser hugo
  groups
  adduser hugo root
  usermod -aG sudo hugo
  users
```
  
#### Java

Java Development Version (JDK 14):

check with java -version. if not installed:

```
apt-get install openjdk-14-jdk openjdk-14-demo openjdk-14-doc openjdk-14-jre-headless openjdK-14-source 
```

#### Git

 User mode is enough!

```
  mkdir server
  cd server/
  mkdir docker
  cd docker/
  git config --list
  git config --global user.name "Hugo Ho"
  git config --global user.email "hugo@gmx.de"
  git config --list
  git clone https://github.com/ClemensX/secrets.git
  cd secrets
  git status
```

#### Maven

```
 apt-cache policy maven
 apt-get install maven
 In user mode:
 mvn -version

```

#### FTP

if ftp is not avilable install it:

```
check if installed:
 apt-cache policy vsftpd
 
 apt-get install vsftpd
 nano /etc/vsftpd.conf
 --> uncomment line: write_enable=YES 

```
#### Docker

Re-install docker according to https://docs.docker.com/engine/install/ubuntu/
Do not use the pre-installed version.

Do **not** use docker.io, use regular docker-ce docker-ce-cli containerd.io from docker.com

```
check if installed frong version:
 # should yield Installed: (none)
 apt-cache policy docker.io

 # should yield Installed: 5:20.10.1~3-0~ubuntu-focal
 apt-cache policy docker-ce
```
#### Nginx

Installation and configuration of nginx:

```
check if installed:
 apt-cache policy nginx
 
 apt-get install nginx
 nano /etc/vsftpd.conf
 --> uncomment line: write_enable=YES 

example configuration in /etc/nginx/sites-available/default:
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        return 301 http://$host:5000/secrets;
}

```

### Preparations

 * build 5 modules with mvn clean install in parent folder (OpenJDK 11 needed)
 * **Disable** build time tests by setting dryRun to true in top level pom.xml
 * use client to generate private keys, select one and put to ./secrets/private/keyfile_private
 * set environment vars in local .env file. Example for bash:
```
export DEFAULT_USER_PGADMIN="xxx@yyy.com"
export DEFAULT_PASSWORD_PGADMIN="pppp"
export POSTGRES_PASSWORD="zzz"
```
 * set vars with ```. .env```
 
### Run

 * Start the server in background ```docker-compose up -d --build```
 * Start the server in current shell with logs visible ```docker-compose up --build```
 * access server on port 5000, e.g. http://localhost:5000/secrets
 * Stop server ```docker-compose down```

#### Run Errors
 * Check to see if serverapp is reachable: ```curl http://localhost:5000/secrets ```
 * if this hangs (does not immediately return), use this command sequence.
   Exact reason unknown - probably has something to do with networking
```
docker network disconnect bridge server_serverapp_1
docker-compose down
sudo systemctl restart docker
docker-compose up -d --build
docker network connect bridge server_serverapp_1
```
 * then retest. Good luck!

## Maintenance

### Backup / Restore

 * start as usual
 * connect to running postgresql container: ```docker exec -it server_db_1 /bin/bash```
 * List DBs: psql -U postgres -l
 * backup secretsdb: 
```
in container:
   pg_dump -U postgres secretsdb >dump.sql
copy to host:
  docker cp 67cd18f7d5e3:/dump.sql ./d.sql
```
 * restore secretsdb: 
```
in container:
drop old tables:
list tables, drop table, quit:
  psql -U postgres secretsdb
    \dt+
    drop table config;
    \q
copy from host:
  docker cp ./dump.sql 67cd18f7d5e3:/dump.sql
import content:    
  psql -U postgres secretsdb <dump.sql
```

### Other

 * access db via pgadmin on port 5050, e.g. http://localhost:5050
 * use user name and pass you set in .env file
 * add new server: any name, then 2nd tab connection: db 5432 postgres postgres \<pw from .env\>
 * DB data is stored in docker volumes ```docker volume ls```
 * to delete all data, e.g. when you want to change passwords in .env file you have to delete the docker volumes
```
$ docker volume ls
DRIVER              VOLUME NAME
local               secrets_pgadmindata
local               secrets_pgdata

$ docker volume rm secrets_pgadmindata
secrets_pgadmindata

$ docker volume rm secrets_pgdata
secrets_pgdata

$ docker volume ls
DRIVER              VOLUME NAME
```

## TODO Profile Green (Secure Communication)
 * &#x2713; get snippet by key
 * &#x2713; get snippet by key and copy to clipboard
 * &#x2713; list tag entries without displaying keys
 * &#x2713; delete snippet by key
 * fix client exception if id is wrong in sc test
 * &#x2713; local config file
 * ? get all snippets
 * ? export all snippets to file
 * ? private / public mode: toggle display of console output for values 