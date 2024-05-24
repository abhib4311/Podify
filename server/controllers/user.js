import { createError } from "../error.js";
import User from "../models/User.js";

// Update user information
export const update = async (req, res, next) => {
    if (req.params.id === req.user.id) {
        try {
            const updatedUser = await User.findByIdAndUpdate(
                req.params.id,
                {
                    $set: req.body,
                },
                { new: true } // Return the updated document
            );
            res.status(200).json(updatedUser);
        } catch (err) {
            next(err); // Pass error to error-handling middleware
        }
    } else {
        return next(createError(403, "You can update only your account!")); // Unauthorized update attempt
    }
};

// Get user information along with populated podcasts and favorites
export const getUser = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id)
            .populate({
                path: "podcasts",
                populate: {
                    path: "creator",
                    select: "name img", // Select only necessary fields
                },
            })
            .populate({
                path: "favorits",
                populate: {
                    path: "creator",
                    select: "name img", // Select only necessary fields
                },
            });
        
        res.status(200).json(user); // Send user data as JSON
    } catch (err) {
        console.error(err); // Log error to console
        next(err); // Pass error to error-handling middleware
    }
};
