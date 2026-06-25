const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
dns.setDefaultResultOrder('ipv4first');

const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env") });
console.log("MONGO_URI:", process.env.MONGO_URI);
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose"); 
const app = express();
const uploadRoutes = require("./routes/upload");
const pdfComparisonRoutes = require('./routes/pdf-comparison');
// Middleware
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Request logging
app.use((req, res, next) => {
  console.log("REQUEST:", req.method, req.url);
  next();
});

// Routes
app.use("/api/auth", require("./routes/auth"));
app.use("/api/upload", require("./routes/upload"));
app.use("/api/admin", require("./routes/admin"));
// Either use the variable you already imported:
app.use("/api/pdf", pdfComparisonRoutes);

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Server is running" });

});

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to DB:", mongoose.connection.name);
    console.log("MongoDB Connected");

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Health check: http://localhost:${PORT}/health`);
    });

  } catch (error) {
    console.log("MongoDB connection failed:", error);
    process.exit(1);
  }
}

startServer();