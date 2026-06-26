import express from "express";
import connectDB from "./config/db.js";

import authRoutes from "./rotues/auth.route.js";
import subscriptionRoutes from "./rotues/subscription.route.js";

import dotenv from "dotenv";

import {
    authMiddleware,
    protectedRoutes,
} from "./middlewares/authMiddleware.js";

dotenv.config();

const app = express();

app.use(express.json());

connectDB();

app.get("/", (req, res) => {
    res.json({ message: "done" });
});

app.use("/api/auth", authRoutes);
app.use("/api/subs", authMiddleware, subscriptionRoutes);

app.use((req, res) => {
    res.status(404).json({ message: "route not found" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("server running on", PORT);
});

export default app;
