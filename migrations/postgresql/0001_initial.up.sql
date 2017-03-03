CREATE TABLE "tuf_files" (
  "id" serial PRIMARY KEY,
  "created_at" timestamp NULL DEFAULT NULL,
  "updated_at" timestamp NULL DEFAULT NULL,
  "deleted_at" timestamp NULL DEFAULT NULL,
  "gun" varchar(255) NOT NULL,
  "role" varchar(255) NOT NULL,
  "version" integer NOT NULL,
  "data" bytea NOT NULL,
  "sha256" char(64) DEFAULT NULL
);

CREATE INDEX tuf_files_sha256_idx ON tuf_files(sha256);

CREATE TABLE "change_category" (
    "category" VARCHAR(20) PRIMARY KEY
);

INSERT INTO "change_category" VALUES ('update'), ('deletion');

CREATE TABLE "changefeed" (
    "id" serial PRIMARY KEY,
    "created_at" timestamp DEFAULT CURRENT_TIMESTAMP,
    "gun" varchar(255) NOT NULL,
    "version" integer NOT NULL,
    "sha256" CHAR(64) DEFAULT NULL,
    "category" VARCHAR(20) NOT NULL DEFAULT 'update' REFERENCES "change_category"
);

CREATE INDEX "idx_changefeed_gun" ON "changefeed" ("gun");

CREATE TABLE "channels" (
"id" serial PRIMARY KEY,
"name" VARCHAR(255) NOT NULL,
"created_at" timestamp NULL DEFAULT NULL,
"updated_at" timestamp NULL DEFAULT NULL,
"deleted_at" timestamp NULL DEFAULT NULL
);

INSERT INTO "channels" (id, name) VALUES (1, 'published'), (2, 'staged'), (3, 'alternate-rooted'), (4, 'quay');

CREATE TABLE "channels_tuf_files" (
"channel_id" integer NOT NULL,
"tuf_file_id" integer NOT NULL,
FOREIGN KEY (channel_id) REFERENCES channels("id") ON DELETE CASCADE,
FOREIGN KEY (tuf_file_id) REFERENCES tuf_files("id") ON DELETE CASCADE,
PRIMARY KEY (tuf_file_id, channel_id)
);