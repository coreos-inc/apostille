FROM library/mariadb:10.1.10

ADD aposql/mysql-initdb.d /docker-entrypoint-initdb.d
