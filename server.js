const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use("/api/", limiter);

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/crm_saas";
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  company: String,
  role: { type: String, enum: ["admin", "user"], default: "user" },
  isActive: { type: Boolean, default: true },
  subscription: {
    plan: { type: String, enum: ["free", "pro", "enterprise"], default: "free" },
    status: { type: String, enum: ["active", "cancelled", "expired"], default: "active" },
    expiresAt: Date
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

// Client Schema
const clientSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true },
  phone: String,
  company: String,
  status: { type: String, enum: ["lead", "prospect", "client", "inactive"], default: "lead" },
  tags: [String],
  notes: String,
  value: { type: Number, default: 0 },
  source: String,
  assignedTo: String,
  lastContact: Date,
  nextFollowUp: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Deal Schema
const dealSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: "Client", required: true },
  title: { type: String, required: true },
  value: { type: Number, required: true },
  stage: { type: String, enum: ["lead", "qualified", "proposal", "negotiation", "closed-won", "closed-lost"], default: "lead" },
  probability: { type: Number, min: 0, max: 100, default: 0 },
  expectedCloseDate: Date,
  actualCloseDate: Date,
  description: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Client = mongoose.model("Client", clientSchema);
const Deal = mongoose.model("Deal", dealSchema);

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET || "default_secret", (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

// Auth routes
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, firstName, lastName, company } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      company
    });

    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || "default_secret",
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "User created successfully",
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        company: user.company,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || "default_secret",
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        company: user.company,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Client routes
app.get("/api/clients", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, search } = req.query;
    const query = { userId: req.user.userId };
    
    if (status) query.status = status;
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: "i" } },
        { lastName: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
        { company: { $regex: search, $options: "i" } }
      ];
    }

    const clients = await Client.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Client.countDocuments(query);

    res.json({
      clients,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch clients" });
  }
});

app.post("/api/clients", authenticateToken, async (req, res) => {
  try {
    const clientData = { ...req.body, userId: req.user.userId };
    const client = new Client(clientData);
    await client.save();
    res.status(201).json(client);
  } catch (error) {
    res.status(500).json({ error: "Failed to create client" });
  }
});

app.put("/api/clients/:id", authenticateToken, async (req, res) => {
  try {
    const client = await Client.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );
    if (!client) {
      return res.status(404).json({ error: "Client not found" });
    }
    res.json(client);
  } catch (error) {
    res.status(500).json({ error: "Failed to update client" });
  }
});

app.delete("/api/clients/:id", authenticateToken, async (req, res) => {
  try {
    const client = await Client.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId
    });
    if (!client) {
      return res.status(404).json({ error: "Client not found" });
    }
    res.json({ message: "Client deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete client" });
  }
});

// Deal routes
app.get("/api/deals", authenticateToken, async (req, res) => {
  try {
    const deals = await Deal.find({ userId: req.user.userId })
      .populate("clientId", "firstName lastName company")
      .sort({ createdAt: -1 });
    res.json(deals);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch deals" });
  }
});

app.post("/api/deals", authenticateToken, async (req, res) => {
  try {
    const dealData = { ...req.body, userId: req.user.userId };
    const deal = new Deal(dealData);
    await deal.save();
    const populatedDeal = await Deal.findById(deal._id).populate("clientId", "firstName lastName company");
    res.status(201).json(populatedDeal);
  } catch (error) {
    res.status(500).json({ error: "Failed to create deal" });
  }
});

// Analytics routes
app.get("/api/analytics/dashboard", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const totalClients = await Client.countDocuments({ userId });
    const totalDeals = await Deal.countDocuments({ userId });
    
    const dealsByStatus = await Deal.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(userId) } },
      { $group: { _id: "$stage", count: { $sum: 1 }, totalValue: { $sum: "$value" } } }
    ]);
    
    const monthlyRevenue = await Deal.aggregate([
      { 
        $match: { 
          userId: new mongoose.Types.ObjectId(userId),
          stage: "closed-won",
          actualCloseDate: { $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1) }
        }
      },
      { $group: { _id: null, total: { $sum: "$value" } } }
    ]);

    res.json({
      overview: {
        totalClients,
        totalDeals,
        monthlyRevenue: monthlyRevenue[0]?.total || 0,
        conversionRate: totalClients > 0 ? ((totalDeals / totalClients) * 100).toFixed(1) : 0
      },
      dealsByStatus,
      recentActivity: await Deal.find({ userId }).sort({ updatedAt: -1 }).limit(5).populate("clientId", "firstName lastName")
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch analytics" });
  }
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

// Serve static files in production
if (process.env.NODE_ENV === "production") {
  app.use(express.static("build"));
  app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "build", "index.html"));
  });
}

app.listen(PORT, () => {
  console.log(`🚀 CRM SaaS Server running on port ${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}`);
  console.log(`🔒 Authentication enabled`);
  console.log(`💾 Database: ${MONGODB_URI}`);
});

module.exports = app;
