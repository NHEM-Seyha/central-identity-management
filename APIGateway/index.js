const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());


// ===============================
// MICROservice URLs
// ===============================

const REGISTRATION_SERVICE = "http://localhost:3001";
const LOGIN_SERVICE = "http://localhost:3002";
const ADMIN_SERVICE = "http://localhost:3003";
const USER_SERVICE = "http://localhost:3004";


// ===============================
// JWT AUTHENTICATION
// ===============================

function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "No token provided"
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}


// ===============================
// ROLE AUTHORIZATION
// ===============================

function requireRole(role) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({
                message: `${role} access required`
            });
        }

        next();
    };
}


// ============================================================
// PUBLIC ROUTES
// ============================================================

// ------------------------------------------------------------
// POST /register
// External:  /register
// Internal:  /register/userregister
// ------------------------------------------------------------

app.post("/register", async (req, res) => {
    try {
        const response = await axios.post(
            `${REGISTRATION_SERVICE}/register/userregister`,
            req.body
        );

        res.status(response.status).json(response.data);

    } catch (error) {
        if (error.response) {
            return res
                .status(error.response.status)
                .json(error.response.data);
        }

        return res.status(500).json({
            message: "Registration service unavailable"
        });
    }
});


// ------------------------------------------------------------
// POST /auth/login
// External:  /auth/login
// Internal:  /auth/login
// ------------------------------------------------------------

app.post("/auth/login", async (req, res) => {
    try {
        const response = await axios.post(
            `${LOGIN_SERVICE}/auth/login`,
            req.body
        );

        res.status(response.status).json(response.data);

    } catch (error) {
        if (error.response) {
            return res
                .status(error.response.status)
                .json(error.response.data);
        }

        return res.status(500).json({
            message: "Login service unavailable"
        });
    }
});


// ============================================================
// ADMIN ROUTES
// ============================================================

// ------------------------------------------------------------
// GET /admin/users/search
// External:  /admin/users/search
// Internal:  /admin/searchuser
// ------------------------------------------------------------

app.get(
    "/admin/users/search",
    authenticateToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const response = await axios.get(
                `${ADMIN_SERVICE}/admin/searchuser`,
                {
                    params: req.query,
                    headers: {
                        Authorization: req.headers.authorization
                    }
                }
            );

            res.status(response.status).json(response.data);

        } catch (error) {
            if (error.response) {
                return res
                    .status(error.response.status)
                    .json(error.response.data);
            }

            return res.status(500).json({
                message: "Admin service unavailable"
            });
        }
    }
);


// ------------------------------------------------------------
// GET /admin/users
// External:  /admin/users
// Internal:  /admin/viewalluser
// ------------------------------------------------------------

app.get(
    "/admin/users",
    authenticateToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const response = await axios.get(
                `${ADMIN_SERVICE}/admin/viewalluser`,
                {
                    headers: {
                        Authorization: req.headers.authorization
                    }
                }
            );

            res.status(response.status).json(response.data);

        } catch (error) {
            if (error.response) {
                return res
                    .status(error.response.status)
                    .json(error.response.data);
            }

            return res.status(500).json({
                message: "Admin service unavailable"
            });
        }
    }
);


// ------------------------------------------------------------
// DELETE /admin/users
// External:  /admin/users
// Internal:  /admin/deluser
// ------------------------------------------------------------

app.delete(
    "/admin/users",
    authenticateToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const response = await axios.delete(
                `${ADMIN_SERVICE}/admin/deluser`,
                {
                    params: req.query,
                    headers: {
                        Authorization: req.headers.authorization
                    }
                }
            );

            res.status(response.status).json(response.data);

        } catch (error) {
            if (error.response) {
                return res
                    .status(error.response.status)
                    .json(error.response.data);
            }

            return res.status(500).json({
                message: "Admin service unavailable"
            });
        }
    }
);


// ============================================================
// USER ROUTES
// ============================================================

// ------------------------------------------------------------
// GET /users/me
// External:  /users/me
// Internal:  /user/viewprofile
// ------------------------------------------------------------

app.get(
    "/users/me",
    authenticateToken,
    requireRole("user"),
    async (req, res) => {
        try {
            const response = await axios.get(
                `${USER_SERVICE}/user/viewprofile`,
                {
                    headers: {
                        Authorization: req.headers.authorization
                    }
                }
            );

            res.status(response.status).json(response.data);

        } catch (error) {
            if (error.response) {
                return res
                    .status(error.response.status)
                    .json(error.response.data);
            }

            return res.status(500).json({
                message: "User service unavailable"
            });
        }
    }
);


// ------------------------------------------------------------
// PUT /users/me
// External:  /users/me
// Internal:  /user/updateprofile
// ------------------------------------------------------------

app.put(
    "/users/me",
    authenticateToken,
    requireRole("user"),
    async (req, res) => {
        try {
            const response = await axios.put(
                `${USER_SERVICE}/user/updateprofile`,
                req.body,
                {
                    headers: {
                        Authorization: req.headers.authorization
                    }
                }
            );

            res.status(response.status).json(response.data);

        } catch (error) {
            if (error.response) {
                return res
                    .status(error.response.status)
                    .json(error.response.data);
            }

            return res.status(500).json({
                message: "User service unavailable"
            });
        }
    }
);


// ============================================================
// START API GATEWAY
// ============================================================

app.listen(3000, () => {
    console.log("API Gateway running on port 3000");
});
