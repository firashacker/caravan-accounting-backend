const express = require("express");
const app = express();
const port = process.env.SERVER_PORT || 3000; // Use environment variable or default to 3000
const publicDirs = [process.env.IMAGES_DIR || "./uploaded"]; // Use environment variables or default to 'public' and 'public2'
//const mainIndex = `${publicDirs[1]}/index.html`;
const bodyParser = require("body-parser");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { PrismaClient } = require("./generated/prisma");
const prisma = new PrismaClient();

// Configure Express app
app.use(bodyParser.json(), cookieParser());

// Enable CORS (Cross-Origin Resource Sharing) - Allowing requests from the frontend
const cors = require("cors");

// CORS setup to accept all routes from specific origin
const corsOptions = {
  origin: true, // Change to the origin you want to accept, e.g., your frontend URL or IP
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Allow specific methods
  allowedHeaders: ["Content-Type", "Authorization"], // Allow headers
  credentials: true, // If you're using cookies or authentication tokens
};

// Apply CORS to all routes
app.use(cors(corsOptions));
/*app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://37.60.227.221:3000"); // Replace with your frontend URL");
  res.header("Access-Control-Allow-Headers", " Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.header("Access-Control-Allow-Credentials", "true");

  next();
});
*/

//Employees
app.post("/api/employee", async (req, res) => {
  try {
    const employee = req.body;
    console.log(employee);
    if (
      employee.paymentMethod !== "dayly" &&
      employee.paymentMethod !== "weekly" &&
      employee.paymentMethod !== "monthly"
    )
      throw { error: "Invalid Input!" };
    const res1 = await prisma.employee.create({ data: employee });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json(error);
  }
});
app.put("/api/employee", async (req, res) => {
  try {
    const employee = req.body;
    console.log(employee);
    if (
      employee.paymentMethod !== "dayly" &&
      employee.paymentMethod !== "weekly" &&
      employee.paymentMethod !== "monthly"
    )
      throw { error: "Invalid Input!" };
    const res1 = await prisma.employee.update({
      where: { id: employee.id },
      data: employee,
    });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json(error);
  }
});
app.get("/api/employee", async (req, res) => {
  try {
    const employees = await prisma.employee.findMany();
    setTimeout(() => res.status(200).json(employees), 500);
  } catch (error) {
    res.status(500).json("Error: server Error!");
  }
});

//Clients
app.post("/api/client", async (req, res) => {
  try {
    const client = req.body;
    console.log(client);
    const res1 = await prisma.client.create({ data: client });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/client", async (req, res) => {
  try {
    const clients = await prisma.client.findMany();
    res.status(200).json(clients);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Traders
app.post("/api/trader", async (req, res) => {
  try {
    const trader = req.body;
    console.log(trader);
    const res1 = await prisma.trader.create({ data: trader });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/trader", async (req, res) => {
  try {
    const traders = await prisma.trader.findMany();
    res.status(200).json(traders);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Debits
app.post("/api/debit", async (req, res) => {
  try {
    const debit = req.body;
    console.log(debit);
    const res1 = await prisma.debit.create({ data: debit });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/debits", async (req, res) => {
  try {
    const debits = await prisma.debit.findMany();
    res.status(200).json(debits);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Debts
app.post("/api/debt", async (req, res) => {
  try {
    const debt = req.body;
    console.log(debt);
    const res1 = await prisma.debt.create({ data: debt });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/debt", async (req, res) => {
  try {
    const debts = await prisma.debt.findMany();
    res.status(200).json(debts);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Incomes
app.post("/api/income", async (req, res) => {
  try {
    const income = req.body;
    console.log(income);
    const res1 = await prisma.income.create({ data: income });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/income", async (req, res) => {
  try {
    const income = await prisma.income.findMany();
    res.status(200).json(income);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Expenses
app.post("/api/expense", async (req, res) => {
  try {
    const expense = req.body;
    console.log(expense);
    const res1 = await prisma.expense.create({ data: expense });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/expense", async (req, res) => {
  try {
    const expenses = await prisma.expense.findMany();
    res.status(200).json(expenses);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//app.post("/api/employee", async (req, res) => {});

//
//
// Auth

//generate tokens
// Generate JWT payload - Data to be encoded in the JWT
const GeneratePayload = (user) => {
  return {
    id: user.id,
    username: user.username,
    isAdmin: user.isAdmin,
  };
};
// Generate Access Token - JWT for short-term access
const GenerateAccessToken = (user) => {
  return jwt.sign(user, process.env.SECRET_KEY, {
    expiresIn: "1h",
  });
};
// Generate Refresh Token -  Longer-lived token for obtaining new access tokens
const GenerateRefreshToken = (user) => {
  return jwt.sign(user, process.env.SECRET_REFRESH_KEY);
};

// Verify token middleware
const verify = (req, res, next) => {
  const token = req.cookies["token"];

  if (token) {
    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};

// Sign in
app.post("/api/login", async (req, res) => {
  if (!req.body?.username || !req.body?.password)
    return res.status(401).json({ error: "Invalid Username or Password" });
  const { username, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: { username: username },
    });

    if (username === "admin" && !user) {
      // Register Admin User if its not registered
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = await prisma.user.create({
        data: {
          username: username,
          isAdmin: true,
          password: hashedPassword,
        },
      });
      console.log("newUser: " + newUser);
      const payload = GeneratePayload(newUser);
      console.log("payload: " + payload);
      const accessToken = GenerateAccessToken(payload);
      const refreshToken = GenerateRefreshToken(payload);

      await prisma.user.update({
        where: {
          id: newUser.id,
        },
        data: {
          refreshtoken: refreshToken,
        },
      });

      res.cookie("token", accessToken, {
        httpOnly: true,
      });
      return res.send({ refreshToken, ...payload });
    }

    if (!user) {
      return res
        .status(401)
        .json({ error: "Invalid phone number or password" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res
        .status(401)
        .json({ error: "Invalid phone number or password" });
    }

    const payload = GeneratePayload(user);
    const accessToken = GenerateAccessToken(payload);
    const refreshToken = GenerateRefreshToken(payload);
    await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        refreshtoken: refreshToken,
      },
    });

    res.cookie("token", accessToken, {
      httpOnly: true,
    });
    res.send({ refreshToken, ...payload });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to login" });
  }
});

// Sign Out
app.post("/api/logout", verify, async (req, res) => {
  const token = req.cookies["token"];

  if (token) {
    const userId = jwt.decode(token).id;

    //console.log(typeof userId);
    if (typeof userId != "number") res.status(400).json("Bad Request!");
    const invalidateToken = async () => {
      try {
        await prisma.user.update({
          where: {
            id: userId,
          },
          data: {
            refreshtoken: "",
          },
        });
      } catch (err) {
        //console.log(err);
        res.status(500).json({ error: "Failed to authorize!" });
      }
      //console.log("invalidated UserID: " + userId);
    };
    res.cookie("token", "");
    invalidateToken();
  }

  res.status(200).json("Signed Out!");
});

// Refresh accessToken
app.post("/api/refresh", async (req, res) => {
  console.log("attempting Refresh");
  // get refreshToken
  const refreshToken = req.body.token;
  //console.log(refreshToken);

  //send error if theres no token
  if (!refreshToken) return res.status(401).json("You are not authenticated!");

  // verify token
  jwt.verify(
    refreshToken,
    process.env.SECRET_REFRESH_KEY,
    async (err, user) => {
      err && console.log(err); // log any errors

      // get user refresh token from database
      const userToken = await prisma.user.findUnique({
        where: {
          id: user.id,
        },
        select: {
          refreshtoken: true,
        },
      });
      const validToken = userToken["refreshtoken"];

      // compare the tow tokens to check if the  token valid
      if (refreshToken !== validToken)
        return res.status(403).json("Refresh token is not valid!"); // return error if they didn't match

      // create new tokens if every thing is ok
      const payload = GeneratePayload(user);
      const newAccessToken = GenerateAccessToken(payload);
      const newRefreshToken = GenerateRefreshToken(payload);
      // update the database with the new refreshToken
      await prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          refreshtoken: newRefreshToken,
        },
      });
      // send new tokens to client
      try {
        res.cookie("token", newAccessToken, {
          httpOnly: true,
        });
        res.status(200).json({ refreshToken: newRefreshToken, ...user });
      } catch (error) {
        console.error(error); // log any errors
        res.status(500).json({ error: "Failed to authorize" });
      }
    },
  );
});

const path = require("path");
const { setTimeout } = require("timers");

publicDirs.map((publicDir) => {
  app.use(express.static(publicDir));
});

app.get("*", (req, res) => {
  console.log(req.url);
  // res.sendFile(path.join(__dirname, mainIndex));
});

app.listen(
  port,
  //"127.0.0.1", //localhost only
  () => {
    console.log(`App listening on port ${port}`);
  },
);
