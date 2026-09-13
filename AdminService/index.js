const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();

app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Admin Service MongoDB Connected"))
    .catch(error => console.error(error));


const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    role: String,
    phone: String
}, {
    timestamps: true
});

const User = mongoose.model("User", userSchema);

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

        if (decoded.role !== "admin") {
            return res.status(403).json({
                message: "Admin access required"
            });
        }

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

/*
=========================================
SEARCH USER
=========================================
*/

app.get("/admin/searchuser", authenticateToken, async (req, res) => {

    try {

        const { name, email } = req.query;

        let query = {};

        if (name) {
            query.name = {
                $regex: name,
                $options: "i"
            };
        }

        if (email) {
            query.email = email.toLowerCase();
        }

        const users = await User.find(query)
            .select("-password");

        if (users.length === 0) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json({
            message: "User found",
            users
        });

    } catch (error) {

        res.status(500).json({
            message: "Server error"
        });
    }
});


/*
=========================================
VIEW ALL USERS
=========================================
*/

app.get("/admin/viewalluser", authenticateToken, async (req, res) => {

    try {

        const users = await User.find()
            .select("-password");

        res.json({
            message: "All users",
            users
        });

    } catch (error) {

        res.status(500).json({
            message: "Server error"
        });
    }
});


/*
=========================================
DELETE USER
=========================================
*/

app.delete("/admin/deluser",authenticateToken, async (req, res) => {

    try {

        const { email } = req.query;

        if (!email) {
            return res.status(400).json({
                message: "Email is required"
            });
        }

        const deletedUser = await User.findOneAndDelete({
            email: email.toLowerCase()
        });

        if (!deletedUser) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json({
            message: "User deleted successfully",
            email: deletedUser.email
        });

    } catch (error) {

        res.status(500).json({
            message: "Server error"
        });
    }
});


app.listen(3003, () => {
    console.log("Admin Service running on port 3003");
});
