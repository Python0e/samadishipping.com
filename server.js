const express = require("express");
const fs = require("fs/promises");
const fsSync = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const multer = require("multer");
const database = require("./database");

const app = express();
const port = process.env.PORT || 9000;
const dataPath = path.join(__dirname, "data", "shipments.json");
const customersPath = path.join(__dirname, "data", "customers.json");
const invoicesPath = path.join(__dirname, "data", "invoices.json");
const containersPath = path.join(__dirname, "data", "containers.json");
const passwordResetTokensPath = path.join(__dirname, "data", "password-reset-tokens.json");
const shipmentDocumentsPath = path.join(__dirname, "data", "shipment-documents.json");
const uploadPath = process.env.APP_UPLOAD_DIR || path.join(__dirname, "uploads");
const statuses = new Set(["At warehouse", "On load", "In transit", "Shipped"]);
const documentFields = new Set([
    "loadNumber", "booking", "containerNumber", "size", "exportDate", "eta", "location",
    "destination", "vessel", "sealNumber", "steamshipLine", "terminal", "voyageNumber",
    "consignee", "notifyAgent", "shipper", "note"
]);
const allowedDocumentExtensions = new Set([".pdf", ".png", ".jpg", ".jpeg", ".doc", ".docx", ".xls", ".xlsx"]);
const customerSessions = new Map();
const adminSessions = new Map();
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const passwordResetLifetimeMs = 60 * 60 * 1000;

fsSync.mkdirSync(uploadPath, { recursive: true });

const upload = multer({
    storage: multer.diskStorage({
        destination: (_request, _file, callback) => callback(null, uploadPath),
        filename: (_request, file, callback) => callback(null, `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`)
    }),
    limits: { fileSize: 10 * 1024 * 1024, files: 1 },
    fileFilter: (_request, file, callback) => {
        if (!allowedDocumentExtensions.has(path.extname(file.originalname).toLowerCase())) {
            callback(new multer.MulterError("LIMIT_UNEXPECTED_FILE", "file"));
            return;
        }
        callback(null, true);
    }
});

app.use(express.json());

async function readShipments() {
    return database.read(dataPath);
}

async function readShipmentDocuments() {
    return readData(shipmentDocumentsPath);
}

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function passwordResetConfiguration() {
    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT || 587);
    const user = process.env.SMTP_USER;
    const password = process.env.SMTP_PASSWORD;
    const from = process.env.SMTP_FROM;
    const applicationUrl = process.env.APP_URL;

    if (!host || !Number.isInteger(port) || port < 1 || port > 65535 || !from || !applicationUrl || (user && !password) || (!user && password)) {
        return null;
    }

    try {
        const url = new URL(applicationUrl);
        if (url.protocol !== "http:" && url.protocol !== "https:") {
            return null;
        }
        return {
            applicationUrl: url,
            from,
            transporter: nodemailer.createTransport({
                host,
                port,
                secure: process.env.SMTP_SECURE === "true",
                auth: user ? { user, pass: password } : undefined
            })
        };
    } catch {
        return null;
    }
}

async function readData(filePath) {
    return database.read(filePath);
}

async function writeShipments(shipments) {
    await writeData(dataPath, shipments);
}

async function writeData(filePath, data) {
    database.write(filePath, data);
}

function documentUpdates(body) {
    const updates = {};
    for (const field of documentFields) {
        if (typeof body[field] === "string") {
            const value = body[field].trim();
            if (value.length > 2000) {
                return null;
            }

            updates[field] = value;
        }
    }
    return updates;
}

function toShipmentDocument(body) {
    const customerId = typeof body.customerId === "string" ? body.customerId : "";
    const loadNumber = typeof body.loadNumber === "string" ? body.loadNumber.trim() : "";
    const containerNumber = typeof body.containerNumber === "string" ? body.containerNumber.trim() : "";
    const destination = typeof body.destination === "string" ? body.destination.trim() : "";
    if (!customerId || !loadNumber || !containerNumber || !destination) {
        return null;
    }

    const document = {
        id: crypto.randomUUID(),
        customerId,
        loadNumber,
        booking: "",
        containerNumber,
        size: "",
        exportDate: "",
        eta: "",
        location: "",
        destination,
        vessel: "",
        sealNumber: "",
        steamshipLine: "",
        terminal: "",
        voyageNumber: "",
        consignee: "",
        notifyAgent: "",
        shipper: "Samadi Shipping Line Logistics",
        note: "",
        vehicles: [],
        files: []
    };
    const updates = documentUpdates(body);
    if (!updates) return null;
    return { ...document, ...updates };
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    return `${salt}:${hash}`;
}

function toCustomer(body) {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const company = typeof body.company === "string" ? body.company.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";

    if (!name || !validEmail(email) || password.length < 6) {
        return null;
    }

    return { name, company, email, password };
}

function toShipment(body) {
    const vehicle = typeof body.vehicle === "string" ? body.vehicle.trim() : "";
    const destination = typeof body.destination === "string" ? body.destination.trim() : "";
    const status = typeof body.status === "string" ? body.status : "";
    if (!vehicle || !destination || !statuses.has(status)) {
        return null;
    }
    return { vehicle, destination, status };
}

function readCookie(request, name) {
    const cookies = request.headers.cookie || "";
    const match = cookies.split(";").map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(`${name}=`));
    return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

function setCustomerSessionCookie(response, sessionId) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.setHeader("Set-Cookie", `customer_session=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetimeMs / 1000}${secure}`);
}

function clearCustomerSessionCookie(response) {
    response.setHeader("Set-Cookie", "customer_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
}

function customerSession(request, response, next) {
    const sessionId = readCookie(request, "customer_session");
    const session = sessionId ? customerSessions.get(sessionId) : null;
    if (!session || session.expiresAt < Date.now()) {
        if (sessionId) {
            customerSessions.delete(sessionId);
        }

        response.status(401).json({ error: "Please sign in to view your customer portal." });
        return;
    }
    request.customerId = session.customerId;
    next();
}

function adminConfiguration() {
    const email = typeof process.env.ADMIN_EMAIL === "string" ? process.env.ADMIN_EMAIL.trim().toLowerCase() : "";
    const password = typeof process.env.ADMIN_PASSWORD === "string" ? process.env.ADMIN_PASSWORD : "";
    return email && password ? { email, password } : null;
}

function credentialsMatch(value, expected) {
    const valueHash = crypto.createHash("sha256").update(value).digest();
    const expectedHash = crypto.createHash("sha256").update(expected).digest();
    return crypto.timingSafeEqual(valueHash, expectedHash);
}

function setAdminSessionCookie(response, sessionId) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.setHeader("Set-Cookie", `admin_session=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionLifetimeMs / 1000}${secure}`);
}

function clearAdminSessionCookie(response) {
    response.setHeader("Set-Cookie", "admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
}

function adminSession(request, response, next) {
    const sessionId = readCookie(request, "admin_session");
    const session = sessionId ? adminSessions.get(sessionId) : null;
    if (!session || session.expiresAt < Date.now()) {
        if (sessionId) {
            adminSessions.delete(sessionId);
        }
        response.status(401).json({ error: "Please sign in to access the administration hub." });
        return;
    }
    request.adminEmail = session.email;
    next();
}

function adminPage(request, response, next) {
    const sessionId = readCookie(request, "admin_session");
    const session = sessionId ? adminSessions.get(sessionId) : null;
    if (!session || session.expiresAt < Date.now()) {
        if (sessionId) {
            adminSessions.delete(sessionId);
        }
        response.redirect("/admin-login.html");
        return;
    }
    request.adminEmail = session.email;
    next();
}

function validPassword(password, storedPassword) {
    const [salt, storedHash] = storedPassword.split(":");
    const calculatedHash = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(calculatedHash, "hex"), Buffer.from(storedHash, "hex"));
}

app.post("/api/customer/password-reset", async (request, response, next) => {
    const email = typeof request.body.email === "string" ? request.body.email.trim().toLowerCase() : "";
    if (!validEmail(email)) {
        response.status(400).json({ error: "Enter a valid email address." });
        return;
    }

    const configuration = passwordResetConfiguration();
    if (!configuration) {
        response.status(503).json({ error: "Password reset email is not configured. Please contact shipping support." });
        return;
    }

    try {
        const customers = await readData(customersPath);
        const customer = customers.find((item) => item.email === email);
        if (!customer) {
            response.json({ message: "If an account exists for this email address, a password-reset link has been sent." });
            return;
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const tokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");
        const expiresAt = Date.now() + passwordResetLifetimeMs;
        const resetTokens = await readData(passwordResetTokensPath).catch((error) => {
            if (error.code === "ENOENT") {
                return [];
            }
            throw error;
        });
        const activeTokens = resetTokens.filter((item) => item.email !== email && item.expiresAt > Date.now());
        activeTokens.push({ email, tokenHash, expiresAt });
        await writeData(passwordResetTokensPath, activeTokens);

        const resetUrl = new URL("/customer-portal/reset-password.html", configuration.applicationUrl);
        resetUrl.searchParams.set("token", resetToken);
        await configuration.transporter.sendMail({
            from: configuration.from,
            to: customer.email,
            subject: "Reset your Samadi Shipping Line Logistics password",
            text: `Use this link to reset your password. It expires in one hour: ${resetUrl.href}`
        });
        response.json({ message: "If an account exists for this email address, a password-reset link has been sent." });
    } catch (error) {
        next(error);
    }
});

app.post("/api/customer/password-reset/confirm", async (request, response, next) => {
    const token = typeof request.body.token === "string" ? request.body.token : "";
    const password = typeof request.body.password === "string" ? request.body.password : "";
    if (!token || password.length < 6) {
        response.status(400).json({ error: "A valid reset link and a password of at least six characters are required." });
        return;
    }

    try {
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
        const resetTokens = await readData(passwordResetTokensPath).catch((error) => {
            if (error.code === "ENOENT") {
                return [];
            }
            throw error;
        });
        const activeTokens = resetTokens.filter((item) => item.expiresAt > Date.now());
        const resetToken = activeTokens.find((item) => item.tokenHash === tokenHash);
        if (!resetToken) {
            await writeData(passwordResetTokensPath, activeTokens);
            response.status(400).json({ error: "This password-reset link is invalid or has expired." });
            return;
        }

        const customers = await readData(customersPath);
        const customer = customers.find((item) => item.email === resetToken.email);
        if (!customer) {
            response.status(400).json({ error: "This password-reset link is invalid or has expired." });
            return;
        }

        customer.passwordHash = hashPassword(password);
        await writeData(customersPath, customers);
        await writeData(passwordResetTokensPath, activeTokens.filter((item) => item.tokenHash !== tokenHash));
        response.status(204).end();
    } catch (error) {
        next(error);
    }
});

app.post("/api/customer/login", async (request, response, next) => {
    const email = typeof request.body.email === "string" ? request.body.email.trim().toLowerCase() : "";
    const password = typeof request.body.password === "string" ? request.body.password : "";
    if (!email || !password) {
        response.status(400).json({ error: "Email and password are required." });
        return;
    }
    try {
        const customers = await readData(customersPath);
        const customer = customers.find((item) => item.email === email);
        if (!customer || !validPassword(password, customer.passwordHash)) {
            response.status(401).json({ error: "The email or password is incorrect." });
            return;
        }
        const sessionId = crypto.randomBytes(32).toString("hex");
        customerSessions.set(sessionId, { customerId: customer.id, expiresAt: Date.now() + sessionLifetimeMs });
        setCustomerSessionCookie(response, sessionId);
        response.json({ customer: { name: customer.name, company: customer.company, email: customer.email } });
    } catch (error) {
        next(error);
    }
});

app.post("/api/customer/logout", (request, response) => {
    const sessionId = readCookie(request, "customer_session");
    if (sessionId) {
        customerSessions.delete(sessionId);
    }
    clearCustomerSessionCookie(response);
    response.status(204).end();
});

app.get("/api/customer/dashboard", customerSession, async (request, response, next) => {
    try {
        const [customers, invoices, containers] = await Promise.all([
            readData(customersPath),
            readData(invoicesPath),
            readData(containersPath)
        ]);
        const customer = customers.find((item) => item.id === request.customerId);
        if (!customer) {
            response.status(401).json({ error: "Customer account not found." });
            return;
        }
        response.json({
            customer: { name: customer.name, company: customer.company, email: customer.email },
            invoices: invoices.filter((invoice) => invoice.customerId === customer.id),
            containers: containers.filter((container) => container.customerId === customer.id)
        });
    } catch (error) {
        next(error);
    }
});

app.post("/api/admin/login", (request, response) => {
    const email = typeof request.body.email === "string" ? request.body.email.trim().toLowerCase() : "";
    const password = typeof request.body.password === "string" ? request.body.password : "";
    const configuration = adminConfiguration();

    if (!configuration) {
        response.status(503).json({ error: "Administrative access is not configured. Set ADMIN_EMAIL and ADMIN_PASSWORD before signing in." });
        return;
    }

    if (!email || !password || !credentialsMatch(email, configuration.email) || !credentialsMatch(password, configuration.password)) {
        response.status(401).json({ error: "The email or password is incorrect." });
        return;
    }

    const sessionId = crypto.randomBytes(32).toString("hex");
    adminSessions.set(sessionId, { email: configuration.email, expiresAt: Date.now() + sessionLifetimeMs });
    setAdminSessionCookie(response, sessionId);
    response.json({ admin: { email: configuration.email } });
});

function logoutAdmin(request, response) {
    const sessionId = readCookie(request, "admin_session");
    if (sessionId) {
        adminSessions.delete(sessionId);
    }
    clearAdminSessionCookie(response);
    response.status(204).end();
}

app.post("/api/logout", logoutAdmin);
app.post("/api/admin/logout", logoutAdmin);

app.get("/api/admin/session", adminSession, (request, response) => {
    response.json({ admin: { email: request.adminEmail } });
});

app.get("/api/customers", adminSession, async (_request, response, next) => {
    try {
        const customers = await readData(customersPath);
        response.json({
            customers: customers.map(({ id, name, company, email }) => ({ id, name, company, email }))
        });
    } catch (error) {
        next(error);
    }
});

app.post("/api/customers", adminSession, async (request, response, next) => {
    const customer = toCustomer(request.body);
    if (!customer) {
        response.status(400).json({ error: "Name, a valid email address, and a password of at least six characters are required." });
        return;
    }

    try {
        const customers = await readData(customersPath);
        if (customers.some((item) => item.email === customer.email)) {
            response.status(409).json({ error: "An account already exists for this email address." });
            return;
        }

        const createdCustomer = {
            id: crypto.randomUUID(),
            name: customer.name,
            company: customer.company,
            email: customer.email,
            passwordHash: hashPassword(customer.password)
        };
        customers.push(createdCustomer);
        await writeData(customersPath, customers);
        response.status(201).json({ customer: { id: createdCustomer.id, name: createdCustomer.name, company: createdCustomer.company, email: createdCustomer.email } });
    } catch (error) {
        next(error);
    }
});

app.get("/api/customers/:id", adminSession, async (request, response, next) => {
    try {
        const [customers, containers, invoices, documents] = await Promise.all([
            readData(customersPath),
            readData(containersPath),
            readData(invoicesPath),
            readShipmentDocuments()
        ]);
        const customer = customers.find((item) => item.id === request.params.id);
        if (!customer) {
            response.status(404).json({ error: "Customer account was not found." });
            return;
        }
        response.json({
            customer: { id: customer.id, name: customer.name, company: customer.company, email: customer.email },
            containers: containers.filter((container) => container.customerId === customer.id),
            invoices: invoices.filter((invoice) => invoice.customerId === customer.id),
            documents: documents.filter((document) => document.customerId === customer.id)
                .map(({ id, loadNumber, containerNumber, destination, eta, files }) => ({
                    id, loadNumber, containerNumber, destination, eta, fileCount: files.length
                }))
        });
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/pipeline", adminSession, async (request, response, next) => {
    try {
        const [documents, customers, containers] = await Promise.all([
            readShipmentDocuments(),
            readData(customersPath),
            readData(containersPath)
        ]);
        const query = typeof request.query.search === "string" ? request.query.search.trim().toLowerCase() : "";
        const pipeline = documents.map((document) => {
            const customer = customers.find((item) => item.id === document.customerId);
            const container = containers.find((item) => item.customerId === document.customerId && item.containerNumber === document.containerNumber);
            return {
                id: document.id,
                clientId: document.customerId,
                bookingId: document.booking || document.loadNumber,
                clientName: customer?.company || customer?.name || "Unassigned",
                vesselName: document.vessel || container?.vessel || "Pending assignment",
                containerNumber: document.containerNumber,
                originPort: container?.origin || document.terminal || "Pending",
                destinationPort: document.destination,
                eta: document.eta,
                status: container?.status || "Documentation",
                fileCount: document.files.length
            };
        }).filter((shipment) => !query || [
            shipment.bookingId, shipment.clientName, shipment.vesselName, shipment.containerNumber,
            shipment.originPort, shipment.destinationPort, shipment.status
        ].some((value) => value.toLowerCase().includes(query)));
        response.json({ pipeline });
    } catch (error) {
        next(error);
    }
});

app.get("/api/documents", adminSession, async (_request, response, next) => {
    try {
        const [documents, customers] = await Promise.all([readShipmentDocuments(), readData(customersPath)]);
        response.json({
            documents: documents.map((document) => ({
                id: document.id,
                loadNumber: document.loadNumber,
                containerNumber: document.containerNumber,
                destination: document.destination,
                customerName: customers.find((customer) => customer.id === document.customerId)?.name || "Unassigned",
                fileCount: document.files.length
            }))
        });
    } catch (error) {
        next(error);
    }
});

app.get("/api/documents/:id", adminSession, async (request, response, next) => {
    try {
        const document = (await readShipmentDocuments()).find((item) => item.id === request.params.id);
        if (!document) {
            response.status(404).json({ error: "Shipment document was not found." });
            return;
        }
        response.json({ document });
    } catch (error) {
        next(error);
    }
});

app.post("/api/documents", adminSession, async (request, response, next) => {
    const document = toShipmentDocument(request.body);
    if (!document) {
        response.status(400).json({ error: "Client, load number, container number, and destination are required." });
        return;
    }

    try {
        const [documents, customers] = await Promise.all([readShipmentDocuments(), readData(customersPath)]);
        if (!customers.some((customer) => customer.id === document.customerId)) {
            response.status(400).json({ error: "Choose an existing customer account." });
            return;
        }
        if (documents.some((item) => item.loadNumber.toLowerCase() === document.loadNumber.toLowerCase())) {
            response.status(409).json({ error: "A shipment document already uses this load number." });
            return;
        }
        documents.unshift(document);
        await writeData(shipmentDocumentsPath, documents);
        response.status(201).json({ document });
    } catch (error) {
        next(error);
    }
});

app.put("/api/documents/:id", adminSession, async (request, response, next) => {
    const updates = documentUpdates(request.body);
    if (!updates || Object.keys(updates).length === 0) {
        response.status(400).json({ error: "Provide at least one valid document field to update." });
        return;
    }

    try {
        const documents = await readShipmentDocuments();
        const document = documents.find((item) => item.id === request.params.id);
        if (!document) {
            response.status(404).json({ error: "Shipment document was not found." });
            return;
        }
        Object.assign(document, updates);
        await writeData(shipmentDocumentsPath, documents);
        response.json({ document });
    } catch (error) {
        next(error);
    }
});

app.post("/api/documents/:id/files", adminSession, upload.single("file"), async (request, response, next) => {
    if (!request.file) {
        response.status(400).json({ error: "Choose a document file to upload." });
        return;
    }

    try {
        const documents = await readShipmentDocuments();
        const document = documents.find((item) => item.id === request.params.id);
        if (!document) {
            await fs.unlink(request.file.path);
            response.status(404).json({ error: "Shipment document was not found." });
            return;
        }
        const uploadedFile = {
            id: crypto.randomUUID(),
            originalName: path.basename(request.file.originalname),
            storedName: request.file.filename,
            mimeType: request.file.mimetype,
            size: request.file.size,
            documentType: typeof request.body.documentType === "string" ? request.body.documentType.trim().slice(0, 100) : "",
            note: typeof request.body.note === "string" ? request.body.note.trim().slice(0, 2000) : "",
            uploadedAt: new Date().toISOString()
        };
        document.files.push(uploadedFile);
        await writeData(shipmentDocumentsPath, documents);
        response.status(201).json({ file: uploadedFile });
    } catch (error) {
        if (request.file) {
            await fs.unlink(request.file.path).catch((unlinkError) => {
                if (unlinkError.code !== "ENOENT") throw unlinkError;
            });
        }
        next(error);
    }
});

app.get("/api/documents/:id/files/:fileId", adminSession, async (request, response, next) => {
    try {
        const document = (await readShipmentDocuments()).find((item) => item.id === request.params.id);
        if (!document) {
            response.status(404).json({ error: "Document file was not found." });
            return;
        }
        const file = document.files.find((item) => item.id === request.params.fileId);
        if (!file) {
            response.status(404).json({ error: "Document file was not found." });
            return;
        }
        response.download(path.join(uploadPath, file.storedName), file.originalName, (error) => {
            if (error && !response.headersSent) next(error);
        });
    } catch (error) {
        next(error);
    }
});

app.get("/api/dashboard", adminSession, async (_request, response, next) => {
    try {
        const shipments = await readShipments();
        response.json({
            metrics: {
                allVehicles: new Set(shipments.map((shipment) => shipment.vehicle)).size,
                atWarehouse: shipments.filter((shipment) => shipment.status === "At warehouse").length,
                onLoad: shipments.filter((shipment) => shipment.status === "On load").length,
                shipped: shipments.filter((shipment) => shipment.status === "Shipped").length
            }
        });
    } catch (error) {
        next(error);
    }
});

app.get("/api/shipments", adminSession, async (request, response, next) => {
    try {
        const query = typeof request.query.search === "string" ? request.query.search.trim().toLowerCase() : "";
        const shipments = await readShipments();
        const results = query
            ? shipments.filter((shipment) => [shipment.reference, shipment.vehicle, shipment.destination, shipment.status]
                .some((value) => value.toLowerCase().includes(query)))
            : shipments;
        response.json({ shipments: results });
    } catch (error) {
        next(error);
    }
});

app.post("/api/shipments", adminSession, async (request, response, next) => {
    const shipment = toShipment(request.body);
    if (!shipment) {
        response.status(400).json({ error: "Vehicle, destination, and a valid status are required." });
        return;
    }
    try {
        const shipments = await readShipments();
        const createdShipment = {
            id: crypto.randomUUID(),
            reference: `GLH-${String(10000 + shipments.length + 1)}`,
            ...shipment,
            updatedAt: new Date().toISOString()
        };
        shipments.unshift(createdShipment);
        await writeShipments(shipments);
        response.status(201).json({ shipment: createdShipment });
    } catch (error) {
        next(error);
    }
});

app.patch("/api/shipments/:id", adminSession, async (request, response, next) => {
    const status = typeof request.body.status === "string" ? request.body.status : "";
    if (!statuses.has(status)) {
        response.status(400).json({ error: "A valid shipment status is required." });
        return;
    }
    try {
        const shipments = await readShipments();
        const shipment = shipments.find((item) => item.id === request.params.id);
        if (!shipment) {
            response.status(404).json({ error: "Shipment not found." });
            return;
        }
        shipment.status = status;
        shipment.updatedAt = new Date().toISOString();
        await writeShipments(shipments);
        response.json({ shipment });
    } catch (error) {
        next(error);
    }
});

app.get("/health", (_request, response) => response.status(200).json({ status: "ok" }));
app.get("/", adminPage, (_request, response) => response.sendFile(path.join(__dirname, "index.html")));
app.get(["/containers.html", "/customers.html", "/documents.html", "/invoices.html", "/rates.html", "/towing.html", "/vehicles.html"], adminPage, (request, response) => {
    response.sendFile(path.join(__dirname, path.basename(request.path)));
});
app.get("/admin-login.html", (_request, response) => response.sendFile(path.join(__dirname, "admin-login.html")));
app.get("/customer", (_request, response) => response.sendFile(path.join(__dirname, "customer.html")));
app.get("/customer-portal/", (_request, response) => response.sendFile(path.join(__dirname, "customer-portal", "index.html")));
app.get("/customer-portal/index.html", (_request, response) => response.sendFile(path.join(__dirname, "customer-portal", "index.html")));
app.get("/customer-portal/forgot-password.html", (_request, response) => response.sendFile(path.join(__dirname, "customer-portal", "forgot-password.html")));
app.get("/customer-portal/reset-password.html", (_request, response) => response.sendFile(path.join(__dirname, "customer-portal", "reset-password.html")));
app.get("/customer-portal/styles.css", (_request, response) => response.sendFile(path.join(__dirname, "customer-portal", "styles.css")));
app.get("/customer-portal/password-reset.js", (_request, response) => response.sendFile(path.join(__dirname, "customer-portal", "password-reset.js")));
app.get("/favicon.svg", (_request, response) => response.sendFile(path.join(__dirname, "favicon.svg")));
app.get("/manifest.webmanifest", (_request, response) => response.sendFile(path.join(__dirname, "manifest.webmanifest")));
app.get("/service-worker.js", (_request, response) => response.sendFile(path.join(__dirname, "service-worker.js")));
app.get("/social-preview.svg", (_request, response) => response.sendFile(path.join(__dirname, "social-preview.svg")));
app.get("/sitemap.xml", (_request, response) => response.sendFile(path.join(__dirname, "sitemap.xml")));

app.use((error, _request, response, _next) => {
    if (error instanceof multer.MulterError) {
        const message = error.code === "LIMIT_FILE_SIZE"
            ? "Files must be 10 MB or smaller."
            : "Only PDF, image, Word, and spreadsheet files are allowed.";
        response.status(400).json({ error: message });
        return;
    }
    console.error("Request failed:", error);
    response.status(500).json({ error: "The server could not complete the request." });
});

app.listen(port, () => console.log(`Shipping dashboard is available at http://localhost:${port}`));
