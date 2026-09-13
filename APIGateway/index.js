const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

app.use(express.json());

const REGISTRATION_SERVICE =
    "http://localhost:3001";

const LOGIN_SERVICE =
    "http://localhost:3002";

const ADMIN_SERVICE =
    "http://localhost:3003";

const USER_SERVICE =
    "http://localhost:3004";


/*
==================================================
JWT AUTHENTICATION
==================================================
*/

function authenticateToken(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "Access denied. No token provided."
        });
    }

    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
        return res.status(401).json({
            message: "Invalid authorization format"
        });
    }

    const token = parts[1];

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


/*
==================================================
ROLE CHECK
==================================================
*/

function requireRole(role) {

    return (req, res, next) => {

        if (!req.user) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        if (req.user.role !== role) {
            return res.status(403).json({
                message: `Access denied. ${role} role required.`
            });
        }

        next();
    };
}


/*
==================================================
REGISTRATION ROUTE
==================================================
*/

app.post("/register/userregister", async (req, res) => {

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

        res.status(500).json({
            message: "Registration service unavailable"
        });
    }
});


/*
==================================================
LOGIN ROUTE
==================================================
*/

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

        res.status(500).json({
            message: "Login service unavailable"
        });
    }
});


/*
==================================================
ADMIN SEARCH USER
==================================================
*/

app.get(
    "/admin/searchuser",
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

            res.status(500).json({
                message: "Admin service unavailable"
            });
        }
    }
);


/*
==================================================
ADMIN VIEW ALL USERS
==================================================
*/

app.get(
    "/admin/viewalluser",
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

            res.status(500).json({
                message: "Admin service unavailable"
            });
        }
    }
);


/*
==================================================
ADMIN DELETE USER
==================================================
*/

app.delete(
    "/admin/deluser",
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

            res.status(500).json({
                message: "Admin service unavailable"
            });
        }
    }
);


/*
==================================================
USER VIEW PROFILE
==================================================
*/

app.get(
    "/user/viewprofile",
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

            res.status(500).json({
                message: "User service unavailable"
            });
        }
    }
);


/*
==================================================
USER UPDATE PROFILE
==================================================
*/

app.put(
    "/user/updateprofile",
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

            res.status(500).json({
                message: "User service unavailable"
            });
        }
    }
);


app.listen(3000, () => {
    console.log("API Gateway running on port 3000");
});
