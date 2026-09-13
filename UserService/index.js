const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();

app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("User Service MongoDB Connected"))
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
VIEW OWN PROFILE
=========================================
*/

app.get("/user/viewprofile",  authenticateToken, async (req, res) => {

    try {

        const userId = req.user.userId;

        const user = await User.findById(userId)
            .select("-password");

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json({
            message: "Profile retrieved successfully",
            user
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Server error"
        });
    }
});


/*
=========================================
UPDATE OWN PROFILE
=========================================
*/

app.put("/user/updateprofile", authenticateToken, async (req, res) => {

    try {

        const userId = req.user.userId;

        const { name, phone } = req.body;

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            {
                name,
                phone
            },
            {
                new: true,
                runValidators: true
            }
        ).select("-password");

        if (!updatedUser) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json({
            message: "Profile updated successfully",
            user: updatedUser
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Server error"
        });
    }
});


app.listen(3004, () => {
    console.log("User Service running on port 3004");
});
