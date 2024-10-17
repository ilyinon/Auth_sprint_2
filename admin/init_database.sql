SELECT 'CREATE DATABASE content'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'content')\gexec

\connect content

CREATE SCHEMA IF NOT EXISTS content;


ALTER SCHEMA content OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;
