FROM library/postgres:9.5.4

ADD aposql/postgresql-initdb.d /docker-entrypoint-initdb.d
