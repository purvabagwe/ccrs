// server.js - College Complaint Report System
require("dotenv").config();
const path = require("path");
const dns = require("dns");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");

// Set reliable public DNS resolvers to handle MongoDB Atlas SRV lookups on Windows
try {
  dns.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);
} catch (e) {
  // Ignore if custom DNS cannot be configured
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// --- Serve Frontend ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- Health / Status Endpoint ---
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    mongoConnected: mongoose.connection.readyState === 1,
    timestamp: new Date().toISOString()
  });
});

// --- MongoDB Schemas & Models ---
const userSchema = new mongoose.Schema({
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, default: "user" }, // "user" or "admin"
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

const complaintSchema = new mongoose.Schema({
  complaintId: { type: String, required: true, unique: true },
  title: { type: String, required: true, trim: true },
  category: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, default: "Pending" }, // "Pending", "In Progress", "Resolved"
  createdAt: { type: Date, default: Date.now }
});

const Complaint = mongoose.model("Complaint", complaintSchema);

// --- MongoDB Connection ---
if (!process.env.MONGODB_URI) {
  console.error("❌ MONGODB_URI is not configured.");
  process.exit(1);
}

mongoose
  .connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000
  })
  .then(async () => {
    console.log("✅ Connected to MongoDB Atlas");

    // Ensure default admin in MongoDB
    try {
      const existingAdmin = await User.findOne({ role: "admin" });

      if (!existingAdmin) {
        const hashedPassword = await bcrypt.hash("admin123", 10);

        await new User({
          firstName: "System",
          lastName: "Admin",
          email: "admin@example.com",
          password: hashedPassword,
          role: "admin"
        }).save();

        console.log(
          "⚡ Default admin created in MongoDB: email=admin@example.com password=admin123"
        );
      }
    } catch (err) {
      console.error("Error setting up default admin:", err.message);
    }
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ==========================================
// User Authentication Routes
// ==========================================

// --- Sign Up (User) ---
app.post("/api/users/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check existing user
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName: firstName ? firstName.trim() : "",
      lastName: lastName ? lastName.trim() : "",
      email: normalizedEmail,
      password: hashedPassword,
      role: "user"
    });

    await newUser.save();

    return res.status(201).json({
      message: "User registered successfully! You can now sign in."
    });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({
      error: "Server error during registration. Please try again."
    });
  }
});

// --- Sign In (User) ---
app.post("/api/users/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    let user;

    user = await User.findOne({
      email: normalizedEmail,
      role: "user"
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    res.json({
      message: "User login successful",
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error("Signin error:", err);
    res.status(500).json({ error: "Server error. Please try again later." });
  }
});

// --- Sign In (Admin) ---
app.post("/api/admin/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    let admin;

    admin = await User.findOne({
      email: normalizedEmail,
      role: "admin"
    });

    if (!admin) {
      return res.status(400).json({ error: "Invalid admin credentials" });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid admin credentials" });
    }

    res.json({
      message: "Admin login successful",
      admin: {
        email: admin.email,
        role: "admin"
      }
    });
  } catch (err) {
    console.error("Admin signin error:", err);
    res.status(500).json({ error: "Server error. Please try again later." });
  }
});

// ==========================================
// Complaints Routes
// ==========================================

// --- Lodge a Complaint ---
app.post("/api/complaints", async (req, res) => {
  try {
    const { title, category, description } = req.body;

    if (!title || !category || !description) {
      return res.status(400).json({ error: "Title, category, and description are required" });
    }

    const complaintId = "COMP-" + Math.floor(100000 + Math.random() * 900000);

    const newComplaint = new Complaint({
      complaintId,
      title: title.trim(),
      category: category.trim(),
      description: description.trim()
    });

    const savedComplaint = await newComplaint.save();

    res.status(201).json({
      message: "Complaint submitted successfully",
      complaintId: savedComplaint.complaintId
    });
  } catch (error) {
    console.error("Complaint submission error:", error);
    res.status(500).json({ error: "Server error while submitting complaint" });
  }
});

// --- View Complaint Status by ID ---
app.get("/api/complaints/:complaintId", async (req, res) => {
  try {
    const { complaintId } = req.params;
    let complaint;

    complaint = await Complaint.findOne({
      complaintId: new RegExp("^" + complaintId.trim() + "$", "i")
    });

    if (!complaint) {
      return res.status(404).json({ error: "Complaint not found" });
    }

    res.json({
      complaintId: complaint.complaintId,
      title: complaint.title,
      category: complaint.category,
      description: complaint.description,
      status: complaint.status,
      createdAt: complaint.createdAt
    });
  } catch (error) {
    console.error("Error fetching complaint:", error);
    res.status(500).json({ error: "Server error. Please try again later." });
  }
});

// --- List All Complaints (for Admin) ---
app.get("/api/complaints", async (req, res) => {
  try {
    let complaints;
    complaints = await Complaint.find().sort({ createdAt: -1 });

    res.json(complaints);
  } catch (err) {
    console.error("Error listing complaints:", err);
    res.status(500).json({ error: "Server error loading complaints" });
  }
});

// --- Update Complaint Status ---
app.patch("/api/complaints/:complaintId/status", async (req, res) => {
  try {
    const { complaintId } = req.params;
    const { status } = req.body;

    const validStatuses = ["Pending", "In Progress", "Resolved"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    let updated;
    updated = await Complaint.findOneAndUpdate(
      { complaintId: new RegExp("^" + complaintId.trim() + "$", "i") },
      { status },
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ error: "Complaint not found" });
    }

    res.json({
      message: "Status updated successfully",
      complaint: updated
    });
  } catch (err) {
    console.error("Error updating complaint status:", err);
    res.status(500).json({ error: "Server error updating status" });
  }
});

// --- Delete Complaint (Admin) ---
app.delete("/api/complaints/:complaintId", async (req, res) => {
  try {
    const { complaintId } = req.params;
    let deleted = false;

    const result = await Complaint.findOneAndDelete({
      complaintId: new RegExp("^" + complaintId.trim() + "$", "i")
    });

    deleted = !!result;

    if (!deleted) {
      return res.status(404).json({ error: "Complaint not found" });
    }

    res.json({ message: "Complaint deleted successfully" });
  } catch (err) {
    console.error("Error deleting complaint:", err);
    res.status(500).json({ error: "Server error deleting complaint" });
  }
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
