CREATE DATABASE apostille;
CREATE DATABASE apostille_root;

REVOKE CREATE ON SCHEMA public FROM public;

CREATE USER server WITH ENCRYPTED PASSWORD '12345';
GRANT CREATE ON SCHEMA public to server_root;
GRANT ALL PRIVILEGES ON DATABASE apostille TO server;

CREATE USER server_root WITH ENCRYPTED PASSWORD '54321';
GRANT CREATE ON SCHEMA public to server_root;
GRANT ALL PRIVILEGES ON DATABASE apostille_root TO server_root;