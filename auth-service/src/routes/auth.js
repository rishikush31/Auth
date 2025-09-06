const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const passport = require("../config/passport");

router.post("/signup", authController.signup);
router.post("/login", authController.login);

// Google OAuth
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"], session: false }));
router.get("/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/auth/google/failed" }),
  (req, res) => {
    res.json({ id: req.user.id, email: req.user.email });
  }
);
router.get("/google/failed", (req, res) => res.status(401).json({ error: "Google auth failed" }));

module.exports = router;
