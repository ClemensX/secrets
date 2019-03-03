# Secrets!

## Start Server

### Preparations

 * build crypto, server and client projects with mvn clean install (OpenJDK 11 needed)
 * use client to generate private keys, slect one and put to ./secrets/private/keyfile_private
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
 
## Maintenance

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
 * (done) get snippet by key
 * (done) get snippet by key and copy to clipboard
 * list tag entries without displaying keys
 * delete snippet by key
 * ? get all snippets
 * ? export all snippets to file
 * ? private / public mode: toggle display of console output for values 