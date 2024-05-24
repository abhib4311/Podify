import mongoose from "mongoose";
import { createError } from "../error.js";
import Podcasts from "../models/Podcasts.js";
import Episodes from "../models/Episodes.js";
import User from "../models/User.js";

// Create a new podcast with episodes
export const createPodcast = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);

        const episodeList = await Promise.all(req.body.episodes.map(async (item) => {
            const episode = new Episodes({ creator: user.id, ...item });
            const savedEpisode = await episode.save();
            return savedEpisode._id;
        }));

        const podcast = new Podcasts({
            creator: user.id,
            episodes: episodeList,
            name: req.body.name,
            desc: req.body.desc,
            thumbnail: req.body.thumbnail,
            tags: req.body.tags,
            type: req.body.type,
            category: req.body.category,
        });

        const savedPodcast = await podcast.save();

        await User.findByIdAndUpdate(user.id, {
            $push: { podcasts: savedPodcast.id },
        }, { new: true });

        res.status(201).json(savedPodcast);
    } catch (err) {
        next(err);
    }
};

// Add episodes to an existing podcast
export const addepisodes = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);

        await Promise.all(req.body.episodes.map(async (item) => {
            const episode = new Episodes({ creator: user.id, ...item });
            const savedEpisode = await episode.save();

            await Podcasts.findByIdAndUpdate(req.body.podid, {
                $push: { episodes: savedEpisode.id },
            }, { new: true });
        }));

        res.status(201).json({ message: "Episodes added successfully" });
    } catch (err) {
        next(err);
    }
};

// Get all podcasts
export const getPodcasts = async (req, res, next) => {
    try {
        const podcasts = await Podcasts.find().populate("creator", "name img").populate("episodes");
        res.status(200).json(podcasts);
    } catch (err) {
        next(err);
    }
};

// Get a specific podcast by ID
export const getPodcastById = async (req, res, next) => {
    try {
        const podcast = await Podcasts.findById(req.params.id).populate("creator", "name img").populate("episodes");
        res.status(200).json(podcast);
    } catch (err) {
        next(err);
    }
};

// Add or remove a podcast from favorites
export const favoritPodcast = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        const podcast = await Podcasts.findById(req.body.id);

        if (user.id === podcast.creator.toString()) {
            return next(createError(403, "You can't favorite your own podcast!"));
        }

        const isFavorite = user.favorits.includes(req.body.id);
        const updateOperation = isFavorite ? { $pull: { favorits: req.body.id } } : { $push: { favorits: req.body.id } };
        const message = isFavorite ? "Removed from favorites" : "Added to favorites";

        await User.findByIdAndUpdate(user.id, updateOperation, { new: true });

        res.status(200).json({ message });
    } catch (err) {
        next(err);
    }
};

// Increment the view count of a podcast
export const addView = async (req, res, next) => {
    try {
        await Podcasts.findByIdAndUpdate(req.params.id, {
            $inc: { views: 1 },
        });
        res.status(200).json("The view has been increased.");
    } catch (err) {
        next(err);
    }
};

// Get random podcasts
export const random = async (req, res, next) => {
    try {
        const podcasts = await Podcasts.aggregate([{ $sample: { size: 40 } }]).populate("creator", "name img").populate("episodes");
        res.status(200).json(podcasts);
    } catch (err) {
        next(err);
    }
};

// Get most popular podcasts by view count
export const mostpopular = async (req, res, next) => {
    try {
        const podcasts = await Podcasts.find().sort({ views: -1 }).populate("creator", "name img").populate("episodes");
        res.status(200).json(podcasts);
    } catch (err) {
        next(err);
    }
};

// Get podcasts by tags
export const getByTag = async (req, res, next) => {
    const tags = req.query.tags.split(",");
    try {
        const podcasts = await Podcasts.find({ tags: { $in: tags } }).populate("creator", "name img").populate("episodes");
        res.status(200).json(podcasts);
    } catch (err) {
        next(err);
    }
};

// Get podcasts by category
export const getByCategory = async (req, res, next) => {
    const query = req.query.q;
    try {
        const podcasts = await Podcasts.find({ category: { $regex: query, $options: "i" } }).populate("creator", "name img").populate("episodes");
        res.status(200).json(podcasts);
    } catch (err) {
        next(err);
    }
};

// Search for podcasts by name
export const search = async (req, res, next) => {
    const query = req.query.q;
    try {
        const podcasts = await Podcasts.find({ name: { $regex: query, $options: "i" } }).populate("creator", "name img").populate("episodes").limit(40);
        res.status(200).json(podcasts);
    } catch (err) {
        next(err);
    }
};
