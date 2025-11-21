FROM postgres:18.1-alpine
COPY 00-public-id-generator.sql /docker-entrypoint-initdb.d/00-public-id-generator.sql