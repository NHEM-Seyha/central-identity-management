const express = require("express");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

const connectDB = require("./DBconnect");
const User = require("./User");

dotenv.config();

const app = express();

app.use(express.json());

connectDB();

app.post("/register/userregister", async (req, res) => {
    try {
        const { name, email, password, role, phone } = req.body;

        if (!name || !email || !password || !phone) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        const existingUser = await User.findOne({
            email: email.toLowerCase()
        });

        if (existingUser) {
            return res.status(409).json({
                message: "Email already registered"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            role: role === "admin" ? "admin" : "user",
            phone
        });

        await newUser.save();

        res.status(201).json({
            message: "User registered successfully",
            user: {
                name: newUser.name,
                email: newUser.email,
                role: newUser.role,
                phone: newUser.phone
            }
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Server error"
        });
    }
});

const PORT = 3001;

app.listen(PORT, () => {
    console.log(`Registration Service running on port ${PORT}`);
});
