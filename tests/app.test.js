import request from "supertest";
import { expect } from "chai";
import jwt from "jsonwebtoken";
import app from "../server.js";

// Helper: generate a valid JWT token for tests
const JWT_SECRET = process.env.JWT_SECRET_KEY || "testsecret";

const generateTestToken = (
    payload = { userId: "648a1b2c3d4e5f6789012345", role: "user" },
) => {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
};

const generateAdminToken = () => {
    return generateTestToken({
        userId: "648a1b2c3d4e5f6789012346",
        role: "admin",
    });
};

// ─── Root Route ───────────────────────────────────────────────────────────────
describe("GET /", () => {
    it("should return { message: 'done' } with status 200", async () => {
        const res = await request(app).get("/");
        expect(res.status).to.equal(200);
        expect(res.body).to.deep.equal({ message: "done" });
    });
});

// ─── Unknown Routes ───────────────────────────────────────────────────────────
describe("Unknown routes", () => {
    it("GET /api/auth should return 404", async () => {
        const res = await request(app).get("/api/auth");
        expect(res.status).to.equal(404);
        expect(res.body).to.deep.equal({ message: "route not found" });
    });

    it("GET /unknown-route should return 404", async () => {
        const res = await request(app).get("/unknown-route");
        expect(res.status).to.equal(404);
        expect(res.body).to.have.property("message", "route not found");
    });
});

// ─── Auth - Register ──────────────────────────────────────────────────────────
describe("POST /api/auth/register", () => {
    it("should return 400 if body is empty", async () => {
        const res = await request(app).post("/api/auth/register").send({});
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if email is invalid", async () => {
        const res = await request(app)
            .post("/api/auth/register")
            .send({ name: "Test", email: "not-an-email", password: "123456" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if password is too short", async () => {
        const res = await request(app)
            .post("/api/auth/register")
            .send({ name: "Test", email: "test@example.com", password: "123" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if name is missing", async () => {
        const res = await request(app)
            .post("/api/auth/register")
            .send({ email: "test@example.com", password: "123456" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });
});

// ─── Auth - Login ─────────────────────────────────────────────────────────────
describe("POST /api/auth/login", () => {
    it("should return 400 if body is empty", async () => {
        const res = await request(app).post("/api/auth/login").send({});
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if email is missing", async () => {
        const res = await request(app)
            .post("/api/auth/login")
            .send({ password: "123456" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if password is missing", async () => {
        const res = await request(app)
            .post("/api/auth/login")
            .send({ email: "test@example.com" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
describe("Authentication middleware", () => {
    it("GET /api/auth/profile without token should return 401", async () => {
        const res = await request(app).get("/api/auth/profile");
        expect(res.status).to.equal(401);
        expect(res.body).to.have.property("message", "No token provided");
    });

    it("GET /api/auth/profile with invalid token should return 401", async () => {
        const res = await request(app)
            .get("/api/auth/profile")
            .set("Authorization", "Bearer invalid_token");
        expect(res.status).to.equal(401);
        expect(res.body).to.have.property("message", "Invalid token");
    });

    it("GET /api/subs without token should return 401", async () => {
        const res = await request(app).get("/api/subs");
        expect(res.status).to.equal(401);
        expect(res.body).to.have.property("message", "No token provided");
    });

    it("GET /api/subs with invalid token should return 401", async () => {
        const res = await request(app)
            .get("/api/subs")
            .set("Authorization", "Bearer bad_token");
        expect(res.status).to.equal(401);
        expect(res.body).to.have.property("message", "Invalid token");
    });
});

// ─── Auth - Admin Protected Route ─────────────────────────────────────────────
describe("GET /api/auth/users (admin only)", () => {
    it("without token should return 401", async () => {
        const res = await request(app).get("/api/auth/users");
        expect(res.status).to.equal(401);
        expect(res.body).to.have.property("message", "No token provided");
    });

    it("with regular user token should return 403", async () => {
        const token = generateTestToken(); // role: "user"
        const res = await request(app)
            .get("/api/auth/users")
            .set("Authorization", `Bearer ${token}`);
        expect(res.status).to.equal(403);
    });
});

// ─── Subscriptions - Token Protection ─────────────────────────────────────────
describe("Routes /api/subs - Token protection", () => {
    it("POST /api/subs without token should return 401", async () => {
        const res = await request(app)
            .post("/api/subs")
            .send({ name: "Netflix", price: 15, billingCycle: "monthly" });
        expect(res.status).to.equal(401);
    });

    it("GET /api/subs/:id without token should return 401", async () => {
        const res = await request(app).get(
            "/api/subs/648a1b2c3d4e5f6789012345",
        );
        expect(res.status).to.equal(401);
    });

    it("PUT /api/subs/:id without token should return 401", async () => {
        const res = await request(app)
            .put("/api/subs/648a1b2c3d4e5f6789012345")
            .send({ name: "Netflix Pro" });
        expect(res.status).to.equal(401);
    });

    it("DELETE /api/subs/:id without token should return 401", async () => {
        const res = await request(app).delete(
            "/api/subs/648a1b2c3d4e5f6789012345",
        );
        expect(res.status).to.equal(401);
    });
});

// ─── Subscriptions - Validation ───────────────────────────────────────────────
describe("POST /api/subs - Validation", () => {
    it("should return 400 if body is empty", async () => {
        const token = generateTestToken();
        const res = await request(app)
            .post("/api/subs")
            .set("Authorization", `Bearer ${token}`)
            .send({});
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if name is missing", async () => {
        const token = generateTestToken();
        const res = await request(app)
            .post("/api/subs")
            .set("Authorization", `Bearer ${token}`)
            .send({ price: 15, billingCycle: "monthly" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if billingCycle is invalid", async () => {
        const token = generateTestToken();
        const res = await request(app)
            .post("/api/subs")
            .set("Authorization", `Bearer ${token}`)
            .send({ name: "Netflix", price: 15, billingCycle: "weekly" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });

    it("should return 400 if price is missing", async () => {
        const token = generateTestToken();
        const res = await request(app)
            .post("/api/subs")
            .set("Authorization", `Bearer ${token}`)
            .send({ name: "Netflix", billingCycle: "monthly" });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property("errors");
    });
});
