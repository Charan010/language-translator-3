const express = require("express");
const session = require("express-session");
const path = require("path");
const cookieParser = require("cookie-parser");
const bcrypt = require('bcryptjs');
const rateLimit = require("express-rate-limit");
const logger = require("./logger");
const mongoose = require("mongoose");
const MongoStore = require('connect-mongo');
const { default: axios } = require("axios");
const { default: cluster } = require("cluster");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;
const isProduction = process.env.NODE_ENV === 'production';
const UserName = process.env.MONGODB_USERNAME
const Password = process.env.MONGODB_PASSWORD
const Cluster = process.env.CLUSTER
const DBname = process.env.DBNAME
const HG_API_TOKEN = process.env.HG_TOKEN   


const connectDB = async () => {
  try {
    const username = UserName;
    const password = encodeURIComponent(Password);
    const cluster = Cluster;
    const dbName = DBname;
    
    const mongoUrl = `mongodb+srv://${username}:${password}@${cluster}/${dbName}?retryWrites=true&w=majority`;
    
    console.log("Attempting MongoDB connection...");
    
    await mongoose.connect(mongoUrl);
    
    console.log("Connected to MongoDB successfully!");
  } catch (err) {
    console.error("MongoDB connection error:", err.message);
    console.error("Error details:", err);
    process.exit(1);
  }
};
connectDB();

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  translations: [
    {
      english: { type: String, required: true },
      telugu: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
      _id:false
    }
  ],
  savedTranslations: [
    {
      english: { type: String, required: true },
      telugu: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
    }
  ]
});

const User = mongoose.model("users", UserSchema);

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.resolve(__dirname, "../front-end")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_please_change',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      client: mongoose.connection.getClient(),
      ttl: 14 * 24 * 60 * 60,
      autoRemove: 'native'
    }),
    cookie: {
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 24, //24 hours expire date
      sameSite: isProduction ? 'none' : 'lax',
      httpOnly: true
    }
  })
);

if (isProduction) {
  app.set('trust proxy', 1);
}

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 100 : 1000,
  message: "Too many requests from this IP, please try again later.",
  headers: true
});
app.use(limiter);

app.use(logger);

function isAuthenticated(req, res, next) {
  if (req.session.user && req.session.user.username) {
    return next();
  }
  res.status(401).json({ 
    message: "Unauthorized",
    error: "Please login to access this resource"
  });
}

app.get("/", (req, res) => {
    res.sendFile(path.resolve(__dirname, "public", "login.html"));
});

app.get("/home", isAuthenticated, (req, res) => {
  res.sendFile(path.resolve(__dirname, "../front-end/index.html"));
});

app.get("/login", (req, res) => {
  if (req.session.user) {

    return res.redirect("/home");
  }

  res.sendFile(path.resolve(__dirname, "../front-end/login.html"));

});

app.get("/signup", (req, res) => {
  if (req.session.user) {

    return res.redirect("/home");
  }
  res.sendFile(path.resolve(__dirname, "../front-end/signup.html"));

});

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ 
      message: "Username and password are required.",
      error: "validation_error"
    });
  }

  try {
    const userExists = await User.findOne({ username });
    if (userExists) {
      return res.status(409).json({ 
        message: "User already exists.",
        error: "user_exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({ username, password: hashedPassword });
    
    console.log("User created successfully:", username);
    
    return res.status(201).json({ 
      message: "User created successfully",
      success: true
    });


  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ 
      message: "Server error during signup.",
      error: "server_error"
    });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  console.log("Login attempt for:", username);

  if (!username || !password) {
    return res.status(400).json({ 
      message: "Username and password are required.",
      error: "validation_error"
    });
  }

  try {
    const user = await User.findOne({ username });
    console.log("User found:", user ? "yes" : "no");

    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = { 
        username: user.username,
        id: user._id.toString()
      };
      
      req.session.save((err) => {
        if (err) {
          console.error("Session save error:", err);
          return res.status(500).json({
            message: "Error creating session",
            error: "session_error"
          });
        }
        
        console.log("Login successful for:", username);
        return res.json({ 
          message: "Login successful",
          success: true

        });
      });

      
    } else {
      console.log("Invalid credentials for:", username);
      return res.status(401).json({ 
        message: "Invalid credentials",
        error: "auth_error"
      });
    }
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ 
      message: "Server error during login",
      error: "server_error"
    });
  }

});

app.get("/current-user", (req, res) => {
  if (req.session.user) {
    res.json({ 
      username: req.session.user.username,
      authenticated: true
    });

  } else {
    res.json({ 
      username: null,
      authenticated: false
    });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ 
        message: "Error logging out",
        error: "server_error"
      });
    }
    res.clearCookie("connect.sid");
    res.json({ 
      message: "Logged out successfully",
      success: true

    });
  });
});

app.post("/save-translation", isAuthenticated, async (req, res) => {
  const { english, telugu } = req.body;
  
  if (!english || !telugu) {
    return res.status(400).json({ message: "Both English and Telugu text are required" });
  }

  try {
    const user = await User.findOne({ username: req.session.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isDuplicate = user.translations.some(t =>
      t.english === english && t.telugu === telugu
    );

    if (isDuplicate) {
      return res.status(409).json({
        message: "Duplicate translation not stored to keep history clean"
      });
    }

    user.translations.push({ english, telugu });
    await user.save();

    res.json({ message: "Translation saved to history" });
  } catch (err) {
    console.error("Error saving translation:", err);
    res.status(500).json({ message: "Error saving translation" });
  }

});


app.get("/history", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json({ translations: user.translations.reverse() });
  } catch (err) {
    console.error("Error fetching history:", err);
    res.status(500).json({ message: "Error fetching history" });
  }
});

app.get("/saved-translations", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json({ savedTranslations: user.savedTranslations.reverse() });
  } catch (err) {
    console.error("Error fetching saved translations:", err);
    res.status(500).json({ message: "Error fetching saved translations" });
  }
});


//adding this mf.
app.post("/api/translate", async (req, res) => {

  console.log("HG_API_TOKEN:", HG_API_TOKEN?.slice(0, 10) + "...");


  const { text, srcLang, tgtLang } = req.body;

  if (!text || !srcLang || !tgtLang) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const response = await axios.post(
      "https://api-inference.huggingface.co/models/facebook/nllb-200-distilled-600M",
      {
        inputs: text,
        parameters: {
          src_lang: srcLang,
          tgt_lang: tgtLang,
        }
      },
      {
        headers: {
          Authorization: `Bearer ${HG_API_TOKEN}`,
          "Content-Type": "application/json"
        },
      }
    );

    const translatedText = response.data?.[0]?.translation_text || "translation not available";

    res.json({ translatedText });
  } catch (error) {
    console.error("Hugging Face translation error:", error.response?.data || error.message);
    res.status(500).json({ error: "Translation failed" });
  }
});


app.delete("/delete-history-item", isAuthenticated, async (req, res) => {
  const { index } = req.body;
  
  try {
    const user = await User.findOne({ username: req.session.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.translations.splice(index, 1);
    await user.save();
    
    res.json({ message: "History item deleted successfully" });
  } catch (err) {
    console.error("Error deleting history item:", err);
    res.status(500).json({ message: "Error deleting history item" });
  }

});


app.delete("/delete-saved-item", isAuthenticated, async (req, res) => {
  const { index } = req.body;
  
  try {
    const user = await User.findOne({ username: req.session.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.savedTranslations.splice(index, 1);
    await user.save();
    
    res.json({ message: "Saved item deleted successfully" });
  } catch (err) {
    console.error("Error deleting saved item:", err);
    res.status(500).json({ message: "Error deleting saved item" });
  }

});


app.delete("/delete-history", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.translations = [];
    await user.save();
    
    res.json({ message: "History deleted successfully" });
  } catch (err) {
    console.error("Error deleting history:", err);
    res.status(500).json({ message: "Error deleting history" });
  }

});

app.delete("/delete-saved", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.savedTranslations = [];
    await user.save();
    
    res.json({ message: "Saved translations deleted successfully" });
  } catch (err) {
    console.error("Error deleting saved translations:", err);
    res.status(500).json({ message: "Error deleting saved translations" });
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    message: "Something went wrong!",
    error: err.message,
    stack: isProduction ? undefined : err.stack
  });
});

const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${isProduction ? 'Production' : 'Development'}`);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  server.close(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  server.close(() => process.exit(1));
});