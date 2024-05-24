import mongoose from "mongoose";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import { createError } from "../error.js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import dotenv from 'dotenv';
import otpGenerator from 'otp-generator';

dotenv.config();

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD
    },
    port: 465,
    host: 'smtp.gmail.com'
});

export const signup = async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(422).json({ message: "Email and password are required." });
    }

    try {
        const existingUser = await User.findOne({ email }).exec();
        if (existingUser) {
            return res.status(409).json({ message: "Email is already in use." });
        }

        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);
        const newUser = new User({ ...req.body, password: hashedPassword });

        const user = await newUser.save();
        const token = jwt.sign({ id: user._id }, process.env.JWT, { expiresIn: "9999 years" });

        res.status(200).json({ token, user });
    } catch (err) {
        next(err);
    }
};

export const signin = async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return next(createError(422, "Email and password are required."));
    }

    try {
        const user = await User.findOne({ email }).exec();
        if (!user) {
            return next(createError(404, "User not found"));
        }

        if (user.googleSignIn) {
            return next(createError(403, "Please sign in with Google."));
        }

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return next(createError(401, "Wrong password"));
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT, { expiresIn: "9999 years" });
        res.status(200).json({ token, user });
    } catch (err) {
        next(err);
    }
};

export const googleAuthSignIn = async (req, res, next) => {
    const { email } = req.body;

    try {
        let user = await User.findOne({ email }).exec();

        if (!user) {
            user = new User({ ...req.body, googleSignIn: true });
            await user.save();
        } else if (!user.googleSignIn) {
            return next(createError(403, "User already exists with this email. Can't sign in with Google."));
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT, { expiresIn: "9999 years" });
        res.status(200).json({ token, user });
    } catch (err) {
        next(err);
    }
};

export const logout = (req, res) => {
    res.clearCookie("access_token").json({ message: "Logged out" });
};

export const generateOTP = async (req, res, next) => {
    const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false, digits: true });
    req.app.locals.OTP = otp;

    const { email, name, reason } = req.query;

    const emailContent = reason === "FORGOTPASSWORD" ? {
        to: email,
        subject: 'PODSTREAM Reset Password Verification',
        html: `
            <div style="font-family: Poppins, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border: 1px solid #ccc; border-radius: 5px;">
                <h1 style="font-size: 22px; font-weight: 500; color: #854CE6; text-align: center; margin-bottom: 30px;">Reset Your PODSTREAM Account Password</h1>
                <div style="background-color: #FFF; border: 1px solid #e5e5e5; border-radius: 5px; box-shadow: 0px 3px 6px rgba(0,0,0,0.05);">
                    <div style="background-color: #854CE6; border-top-left-radius: 5px; border-top-right-radius: 5px; padding: 20px 0;">
                        <h2 style="font-size: 28px; font-weight: 500; color: #FFF; text-align: center; margin-bottom: 10px;">Verification Code</h2>
                        <h1 style="font-size: 32px; font-weight: 500; color: #FFF; text-align: center; margin-bottom: 20px;">${otp}</h1>
                    </div>
                    <div style="padding: 30px;">
                        <p style="font-size: 14px; color: #666; margin-bottom: 20px;">Dear ${name},</p>
                        <p style="font-size: 14px; color: #666; margin-bottom: 20px;">To reset your PODSTREAM account password, please enter the following verification code:</p>
                        <p style="font-size: 20px; font-weight: 500; color: #666; text-align: center; margin-bottom: 30px; color: #854CE6;">${otp}</p>
                        <p style="font-size: 12px; color: #666; margin-bottom: 20px;">Please enter this code in the PODSTREAM app to reset your password.</p>
                        <p style="font-size: 12px; color: #666; margin-bottom: 20px;">If you did not request a password reset, please disregard this email.</p>
                    </div>
                </div>
                <br>
                <p style="font-size: 16px; color: #666; margin-bottom: 20px; text-align: center;">Best regards,<br>The PODSTREAM Team</p>
            </div>
        `
    } : {
        to: email,
        subject: 'Account Verification OTP',
        html: `
            <div style="font-family: Poppins, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border: 1px solid #ccc; border-radius: 5px;">
                <h1 style="font-size: 22px; font-weight: 500; color: #854CE6; text-align: center; margin-bottom: 30px;">Verify Your PODSTREAM Account</h1>
                <div style="background-color: #FFF; border: 1px solid #e5e5e5; border-radius: 5px; box-shadow: 0px 3px 6px rgba(0,0,0,0.05);">
                    <div style="background-color: #854CE6; border-top-left-radius: 5px; border-top-right-radius: 5px; padding: 20px 0;">
                        <h2 style="font-size: 28px; font-weight: 500; color: #FFF; text-align: center; margin-bottom: 10px;">Verification Code</h2>
                        <h1 style="font-size: 32px; font-weight: 500; color: #FFF; text-align: center; margin-bottom: 20px;">${otp}</h1>
                    </div>
                    <div style="padding: 30px;">
                        <p style="font-size: 14px; color: #666; margin-bottom: 20px;">Dear ${name},</p>
                        <p style="font-size: 14px; color: #666; margin-bottom: 20px;">Thank you for creating a PODSTREAM account. To activate your account, please enter the following verification code:</p>
                        <p style="font-size: 20px; font-weight: 500; color: #666; text-align: center; margin-bottom: 30px; color: #854CE6;">${otp}</p>
                        <p style="font-size: 12px; color: #666; margin-bottom: 20px;">Please enter this code in the PODSTREAM app to activate your account.</p>
                        <p style="font-size: 12px; color: #666; margin-bottom: 20px;">If you did not create a PODSTREAM account, please disregard this email.</p>
                    </div>
                </div>
                <br>
                <p style="font-size: 16px; color: #666; margin-bottom: 20px; text-align: center;">Best regards,<br>The Podstream Team</p>
            </div>
        `
    };

    transporter.sendMail(emailContent, (err) => {
        if (err) {
            next(err);
        } else {
            res.status(200).json({ message: "OTP sent" });
        }
    });
};

export const verifyOTP = async (req, res, next) => {
    const { code } = req.query;

    if (parseInt(code) === parseInt(req.app.locals.OTP)) {
        req.app.locals.OTP = null;
        req.app.locals.resetSession = true;
        return res.status(200).json({ message: "OTP verified" });
    } else {
        return next(createError(400, "Wrong OTP"));
    }
};

export const createResetSession = async (req, res) => {
    if (req.app.locals.resetSession) {
        req.app.locals.resetSession = false;
        return res.status(200).json({ message: "Access granted" });
    } else {
        return res.status(440).json({ message: "Session expired" });
    }
};

export const findUserByEmail = async (req, res, next) => {
    const { email } = req.query;

    try {
        const user = await User.findOne({ email }).exec();
        if (user) {
            return res.status(200).json({ message: "User found" });
        } else {
            return res.status(404).json({ message: "User not found" });
        }
    } catch (err) {
        next(err);
    }
};

export const resetPassword = async (req, res, next) => {
    if (!req.app.locals.resetSession) {
        return res.status(440).json({ message: "Session expired" });
    }

    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email }).exec();
        if (user) {
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = bcrypt.hashSync(password, salt);
            await User.updateOne({ email }, { password: hashedPassword }).exec();

            req.app.locals.resetSession = false;
            return res.status(200).json({ message: "Password reset successful" });
        } else {
            return res.status(404).json({ message: "User not found" });
        }
    } catch (err) {
        next(err);
    }
};
