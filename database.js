const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const dataDirectory = process.env.APP_DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(dataDirectory, { recursive: true });
const database = new DatabaseSync(path.join(dataDirectory, "shipping-line.sqlite"));
const collections = new Map([
    ["shipments.json", "shipments"],
    ["customers.json", "customers"],
    ["invoices.json", "invoices"],
    ["containers.json", "containers"],
    ["password-reset-tokens.json", "password_reset_tokens"],
    ["shipment-documents.json", "shipment_documents"]
]);

database.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS records (
        collection TEXT NOT NULL,
        record_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY (collection, record_id)
    );
`);

function collectionFor(filePath) {
    const collection = collections.get(path.basename(filePath));
    if (!collection) {
        throw new Error(`No database collection is configured for ${filePath}.`);
    }
    return collection;
}

function recordId(record, index) {
    return String(record.id || record.tokenHash || `${index}-${crypto.randomUUID()}`);
}

function migrateCollection(fileName, collection) {
    const existing = database.prepare("SELECT COUNT(*) AS count FROM records WHERE collection = ?").get(collection);
    const sourcePath = path.join(dataDirectory, fileName);
    if (existing.count || !fs.existsSync(sourcePath)) return;

    const records = JSON.parse(fs.readFileSync(sourcePath, "utf8"));
    const insert = database.prepare("INSERT INTO records (collection, record_id, payload) VALUES (?, ?, ?)");
    database.exec("BEGIN");
    try {
        records.forEach((record, index) => insert.run(collection, recordId(record, index), JSON.stringify(record)));
        database.exec("COMMIT");
    } catch (error) {
        database.exec("ROLLBACK");
        throw error;
    }
}

for (const [fileName, collection] of collections) {
    migrateCollection(fileName, collection);
}

function read(filePath) {
    const collection = collectionFor(filePath);
    return database.prepare("SELECT payload FROM records WHERE collection = ? ORDER BY rowid").all(collection)
        .map((row) => JSON.parse(row.payload));
}

function write(filePath, records) {
    const collection = collectionFor(filePath);
    const remove = database.prepare("DELETE FROM records WHERE collection = ?");
    const insert = database.prepare("INSERT INTO records (collection, record_id, payload) VALUES (?, ?, ?)");
    database.exec("BEGIN");
    try {
        remove.run(collection);
        records.forEach((record, index) => insert.run(collection, recordId(record, index), JSON.stringify(record)));
        database.exec("COMMIT");
    } catch (error) {
        database.exec("ROLLBACK");
        throw error;
    }
}

module.exports = { read, write, databasePath: path.join(dataDirectory, "shipping-line.sqlite") };
