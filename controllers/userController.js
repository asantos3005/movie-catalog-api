const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { verifyAccessToken } = require('../utils/jwtUtils'); 
const dayjs = require("dayjs");
const utc = require("dayjs/plugin/utc");
dayjs.extend(utc);



const registerUser = async (req, res) => {
  const { email, password } = req.body;

  // Validate the fields input first
  if (!email || !password) {
    return res.status(400).json({
      error: true,
      message: "Email and password are required.",
    });
  }

  // Validate email format 
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      error: true,
      message: "Invalid email format.",
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: true,
      message: "Password must be at least 6 characters long.",
    });
  }

  try {
    // Pre check for duplicate user
    const existingUser = await req.db("users").where({ email }).first();
    if (existingUser) {
      return res.status(409).json({
        error: true,
        message: "Email is already registered.",
      });
    }

    // secure
    const hashedPassword = await bcrypt.hash(password, 10);

    await req.db("users").insert({
      email,
      password: hashedPassword,
      refresh_token: null, // rem to set null
    });

    // SUccessful response
    return res.status(201).json({
      message: "User registered successfully.",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      error: true,
      message: "An error occurred during registration.",
    });
  }
};



const loginUser = async (req, res) => {
  console.log("LOGIN STARTED")
  const { email, password } = req.body;

  // Validate the input
  if (!email || !password) {
    return res.status(400).json({
      error: true,
      message: "Email and password are required.",
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      error: true,
      message: "Invalid email format.",
    });
  }

  try {
    // Try to find the user in db
    const user = await req.db("users").where({ email }).first();
    if (!user) {
      console.log("User does not exist")
      return res.status(401).json({
        error: true,
        message: "Invalid email or password.",
      });
    }

    // Compare hashed values for pwd
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("Wrong email or password")
      return res.status(401).json({
        error: true,
        message: "Invalid email or password.",
      });
    }

    // Expiry time changed through JSON body? Not through URL params
    const bearerExpiresIn = parseInt(req.body.bearerExpiresInSeconds ?? req.query.bearerExpiresInSeconds) || 600;
    const refreshExpiresIn = parseInt(req.body.refreshExpiresInSeconds ?? req.query.refreshExpiresInSeconds) || 86400;


    // Generate tokens
    const secret = process.env.JWT_SECRET || 'default-secret';
    //console.log("JWT Secret used for login:", secret);

    const bearerToken = jwt.sign(
      { email: user.email, id: user.id },
      secret,
      { expiresIn: bearerExpiresIn }
    );

    //console.log("Bearer Token signed during login:", bearerToken);


    const refreshSecret = process.env.JWT_REFRESH_SECRET || 'default-refresh-secret';
    //console.log("JWT Secret used for retrieval:", refreshSecret);

    const refreshToken = jwt.sign(
      { email: user.email, id: user.id },
      refreshSecret,
      { expiresIn: refreshExpiresIn }
    );
    //console.log("Refresh Token:", refreshToken);
    //console.log("Refresh expiry used:", refreshExpiresIn);
    //console.log("Bearer expiry used:", bearerExpiresIn);



    await req.db("users")
      .where({ id: user.id })
      .update({
        refresh_token: refreshToken,
        updated_at: req.db.fn.now() 
      });


    return res.status(200).json({
      bearerToken: {
        token: bearerToken,
        token_type: "Bearer",
        expires_in: bearerExpiresIn,
      },
      refreshToken: {
        token: refreshToken,
        token_type: "Refresh",
        expires_in: refreshExpiresIn,
      },
    });

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      error: true,
      message: "Internal server error.",
    });
  }
};



const refreshToken = async (req, res) => {
  const token = req.body?.refreshToken;

  if (!token) {
    return res.status(400).json({
      error: true,
      message: "Request body incomplete, refresh token required",
    });
  }

  const refreshSecret = process.env.JWT_REFRESH_SECRET || "fallbackRefreshSecret";
  let decoded;

  // Check if same token
  try {
    decoded = jwt.verify(token, refreshSecret);

    // Optional: log expiration for debugging
    const decodedRaw = jwt.decode(token);
    //console.log("Refresh token expiry:", new Date(decodedRaw.exp * 1000));

  } catch (err) {
    console.error("JWT verification error:", err);
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        error: true,
        message: "JWT token has expired",
      });
    } else if (err.name === "JsonWebTokenError") {
      return res.status(401).json({
        error: true,
        message: "Invalid JWT token",
      });
    } else {
      console.error("Unexpected JWT error:", err);
      return res.status(500).json({
        error: true,
        message: "Unexpected error verifying refresh token.",
      });
    }
  }

  try {
    // Loof for user first 
    const user = await req.db("users").where({ id: decoded.id }).first();

    if (!user) {
      return res.status(401).json({
        error: true,
        message: "User not found or no longer valid.",
      });
    }

    // Same token as in db?
    if (user.refresh_token !== token) {
      return res.status(401).json({
        error: true,
        message: "Refresh token has been invalidated. Please log in again.",
      });
    }

    // expiry durations for testing (via query)
    const parseIntOrDefault = (val, fallback) => {
      const parsed = parseInt(val);
      return isNaN(parsed) ? fallback : parsed;
    };

    const bearerExpiresIn = parseIntOrDefault(req.query.bearerExpiresInSeconds, 600);
    const refreshExpiresIn = parseIntOrDefault(req.query.refreshExpiresInSeconds, 86400);

    const bearerSecret = process.env.JWT_SECRET || "default-secret";

    // New tokens
    const newBearerToken = jwt.sign(
      { id: user.id, email: user.email },
      bearerSecret,
      { expiresIn: bearerExpiresIn }
    );

    const newRefreshToken = jwt.sign(
      { id: user.id, email: user.email },
      refreshSecret,
      { expiresIn: refreshExpiresIn }
    );

    // Put new refresh token in db
    await req.db("users")
      .where({ id: user.id })
      .update({
        refresh_token: newRefreshToken,
        updated_at: req.db.fn.now(),
      });

    // Respond with new tokens
    return res.status(200).json({
      bearerToken: {
        token: newBearerToken,
        token_type: "Bearer",
        expires_in: bearerExpiresIn,
      },
      refreshToken: {
        token: newRefreshToken,
        token_type: "Refresh",
        expires_in: refreshExpiresIn,
      },
    });
  } catch (err) {
    console.error("Token refresh failed:", err);
    return res.status(500).json({
      error: true,
      message: "Internal server error during token refresh.",
    });
  }
};



const logoutUser = async (req, res) => {
  const { refreshToken } = req.body;
  //console.log("START OF LOGOUT INSTANCE: ", refreshToken)

  if (!refreshToken || typeof refreshToken !== "string") {
    return res.status(400).json({
      error: true,
      message: "Request body incomplete, refresh token required",
    });
  }

  const refreshSecret = process.env.JWT_REFRESH_SECRET || "fallbackRefreshSecret";
  //console.log("Refresh Secret Used for Logout: ", refreshSecret);

  try {
    const decoded = jwt.verify(refreshToken, refreshSecret); // throws error if expired - must be caught
    // issue - test is not setting expiry time low enough despite explict expiry test?
    //console.log("Decoded exp:", decoded.exp);
    //console.log("Now:", Math.floor(Date.now() / 1000));
    const match = await req.db("users")
    .where({ id: decoded.id })
    .select("refresh_token");

  //console.log("DB Refresh Token:", match[0]?.refresh_token);
  //console.log("Provided Token:", refreshToken);

    const updatedCount = await req.db("users")
      .where({ id: decoded.id, refresh_token: refreshToken })
      .update({ refresh_token: null });
    
    if (updatedCount === 0) {
      // Only runs if token was valid not expired
      //console.log("Updated Count was 0 \n");
      return res.status(401).json({
        error: true,
        message: "Refresh token not found or already invalidated",
      });
    }
    
    return res.status(200).json({
      error: false,
      message: "Token successfully invalidated",
    });

  } catch (err) {
    //console.log(err.message, refreshToken, '\n');
    return res.status(401).json({
      error: true,
      message: err.name === "TokenExpiredError" ? "JWT token has expired" : "Invalid JWT token",
    });
  }
};



const getUserProfile = async (req, res) => {
  const { email } = req.params;

  const formatDate = (dateObj) => {
  if (!dateObj) return null;
  return dayjs(dateObj).format("YYYY-MM-DD");
  };


  try {
    const user = await req.db("users").where({ email }).first();
    if (!user) {
      return res.status(404).json({
        error: true,
        message: "User not found"
      });
    }

    const publicProfile = {
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName
    };

    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      return res.status(200).json(publicProfile);
    }

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: true,
        message: "Authorization header is malformed"
      });
    }

    const token = authHeader.split(" ")[1];
    const bearerSecret = process.env.JWT_SECRET || "fallbackBearerSecret";
    //console.log("Bearer Token for retrieval:", token);
    //console.log("JWT Secret used for retrieval:", bearerSecret);

    try {
      const decoded = jwt.verify(token, bearerSecret);

      if (decoded.email !== email) {
        return res.status(200).json(publicProfile);
      }

      return res.status(200).json({
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        dob: formatDate(user.dob),
        address: user.address
      });

    } catch (err) {
      // find issue - keeps not finding the token in db - token for login different from token from retreival
  //console.error("JWT verification failed!");
  //console.error("Token being verified:", JSON.stringify(token));
  //console.error("Secret being used:", bearerSecret);
  //console.error("Error message:", err.message);

  if (err.name === "TokenExpiredError") {
    return res.status(401).json({
      error: true,
      message: "JWT token has expired"
    });
  }

  return res.status(401).json({
    error: true,
    message: "Invalid JWT token"
  });
}

  } catch (err) {
    console.error("Error in getUserProfile:", err);
    return res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
};



const updateUserProfile = async (req, res) => {
  const token = req.headers['authorization'];

  // Check auth header
  if (!token) {
    return res.status(401).json({
      error: true,
      message: "Authorization header ('Bearer token') not found",
    });
  }

  // Make sure right format
  if (!token.startsWith('Bearer ')) {
    return res.status(401).json({
      error: true,
      message: "Authorization header is malformed",
    });
  }

  const jwtToken = token.slice(7); // Remove 'Bearer '
  let payload;
  try {
    payload = verifyAccessToken(jwtToken); // throws if invalid or expired
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: true, message: 'JWT token has expired' });
    }
    return res.status(401).json({ error: true, message: 'Invalid JWT token' });
  }

  const { email } = req.params;
  const { firstName, lastName, dob, address } = req.body;

  // Have to update all fields
  if (!firstName || !lastName || !dob || !address) {
    return res.status(400).json({
      error: true,
      message: "Request body incomplete: firstName, lastName, dob and address are required.",
    });
  }

  // Ensure strings
  if (
    typeof firstName !== 'string' ||
    typeof lastName !== 'string' ||
    typeof address !== 'string'
  ) {
    return res.status(400).json({
      error: true,
      message: "Request body invalid: firstName, lastName and address must be strings only.",
    });
  }

  // Validate dob format and ensure it's a real date in the past
  const dobRegex = /^\d{4}-\d{2}-\d{2}$/;
  const dobDate = new Date(dob);
  const now = new Date();

  if (!dobRegex.test(dob) || isNaN(dobDate.getTime())) {
    return res.status(400).json({
      error: true,
      message: "Invalid input: dob must be a real date in format YYYY-MM-DD.",
    });
  }

  if (dobDate >= now) {
    return res.status(400).json({
      error: true,
      message: "Invalid input: dob must be a date in the past.",
    });
  }

  const [year, month, day] = dob.split('-').map(Number);
  if (
    dobDate.getFullYear() !== year ||
    dobDate.getMonth() + 1 !== month ||
    dobDate.getDate() !== day
  ) {
    return res.status(400).json({
      error: true,
      message: "Invalid input: dob must be a real date in format YYYY-MM-DD.",
    });
  }

  // check ownership
  if (payload.email !== email) {
    return res.status(403).json({ error: true, message: 'Forbidden' });
  }


  const existingUser = await req.db('users').where({ email }).first();
  if (!existingUser) {
    return res.status(404).json({ error: true, message: 'User not found' });
  }

  // update profile
  await req.db('users')
    .where({ email })
    .update({ firstName, lastName, dob, address });

  // Format dob before responding - keeps adding timezone stuff
  const formattedDob = new Date(dob).toISOString().split('T')[0];

  res.status(200).json({
    email,
    firstName,
    lastName,
    dob: formattedDob,
    address,
  });
};



module.exports = { registerUser, loginUser, refreshToken, logoutUser, getUserProfile, updateUserProfile }