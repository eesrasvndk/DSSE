CREATE SCHEMA IF NOT EXISTS dsse;
SET search_path TO dsse;
CREATE TABLE IF NOT EXISTS cs_generations (
    generation_id uuid PRIMARY KEY, dataset_id uuid NOT NULL, scheme_id text NOT NULL,
    key_version integer NOT NULL CHECK(key_version>0), epoch bigint NOT NULL DEFAULT 0 CHECK(epoch>=0));
CREATE TABLE IF NOT EXISTS cs_entries (
    generation_id uuid REFERENCES cs_generations, address bytea NOT NULL, value bytea NOT NULL,
    PRIMARY KEY(generation_id,address));
CREATE INDEX IF NOT EXISTS cs_entries_prefix ON cs_entries
    (generation_id,substring(address from 1 for 32));
CREATE TABLE IF NOT EXISTS cs_documents (
    generation_id uuid REFERENCES cs_generations, document_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision>0), deleted boolean NOT NULL, PRIMARY KEY(generation_id,document_id));
CREATE TABLE IF NOT EXISTS cs_operations (
    generation_id uuid REFERENCES cs_generations, operation_id uuid NOT NULL,
    request_hash bytea NOT NULL, response bytea NOT NULL, PRIMARY KEY(generation_id,operation_id));
CREATE TABLE IF NOT EXISTS cs_object_cleanup (
    generation_id uuid NOT NULL REFERENCES cs_generations, document_id uuid NOT NULL,
    revision bigint NOT NULL, PRIMARY KEY(generation_id,document_id,revision));
CREATE TABLE IF NOT EXISTS cs_upload_intents (
    generation_id uuid NOT NULL, document_id uuid NOT NULL, revision bigint NOT NULL,
    PRIMARY KEY(generation_id,document_id,revision));
CREATE TABLE IF NOT EXISTS cs_opaque_blobs (
    generation_id uuid NOT NULL REFERENCES cs_generations, blob_id uuid NOT NULL,
    content_hash bytea NOT NULL, PRIMARY KEY(generation_id,blob_id));
