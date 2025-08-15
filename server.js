const express = require("express");
const app = express();
const port = process.env.SERVER_PORT || 3000; // Use environment variable or default to 3000
//const publicDirs = [process.env.IMAGES_DIR || "./uploaded", "./dist"]; // Use environment variables or default to 'public' and 'public2'
//const mainIndex = `${publicDirs[1]}/index.html`;
const bodyParser = require("body-parser");
//const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { PrismaClient } = require("./generated/prisma");
const prisma = new PrismaClient();
const defaultResLength = 30;
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

  try {
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
  } catch (error) {
    res.status(500).json("verification server Error");
  }
};

// Verify token middleware
const verifyAdmin = (req, res, next) => {
  const token = req.cookies["token"];

  try {
    if (token) {
      jwt.verify(token, process.env.SECRET_KEY, async (err, user) => {
        if (err) {
          return res.status(403).json("Token is not valid!");
        }

        const isAdmin = (
          await prisma.user.findUnique({ where: { username: user.username } })
        ).isAdmin;
        if (!isAdmin) return res.status(403).json("You are not Admin!");
        req.user = user;
        next();
      });
    } else {
      res.status(401).json("You are not authenticated!");
    }
  } catch (error) {
    res.status(500).json("admin verification server Error");
  }
};

//Employees
app.post("/api/employee", verifyAdmin, async (req, res) => {
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
app.put("/api/employee", verifyAdmin, async (req, res) => {
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
app.get("/api/employee", verify, async (req, res) => {
  try {
    const employees = await prisma.employee.findMany();
    res.status(200).json(employees);
  } catch (error) {
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/employee/:id", verify, async (req, res) => {
  const employeeId = Number(req.params.id);
  try {
    const employees = await prisma.employee.findUnique({
      where: {
        id: employeeId,
      },
    });
    res.status(200).json(employees);
  } catch (error) {
    res.status(500).json("Error: server Error!");
  }
});

//Clients
app.post("/api/client", verifyAdmin, async (req, res) => {
  try {
    const client = req.body;
    console.log(client);
    const res1 = await prisma.client.create({
      data: client,
      include: {
        debits: true,
      },
    });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/client", verify, async (req, res) => {
  try {
    const clients = await prisma.client.findMany();
    res.status(200).json(clients);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Traders
app.post("/api/trader", verifyAdmin, async (req, res) => {
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
app.get("/api/trader", verify, async (req, res) => {
  try {
    const traders = await prisma.trader.findMany();
    res.status(200).json(traders);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Investors
app.post("/api/investor", verifyAdmin, async (req, res) => {
  try {
    const investor = req.body;
    console.log(investor);
    const res1 = await prisma.investor.create({ data: investor });
    res.status(200).json(res1);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});
app.get("/api/investor", verify, async (req, res) => {
  try {
    const investors = await prisma.investor.findMany();
    res.status(200).json(investors);
  } catch (error) {
    console.log(error);
    res.status(500).json("Error: server Error!");
  }
});

//Debits
app.post("/api/debit", verifyAdmin, async (req, res) => {
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
app.get("/api/debit/:target/:id/:method/:from?", async (req, res) => {
  const stringFrom = req.params.from || 0;
  const target = req.params.target;
  const stringId = req.params.id;
  const method = req.params.method;
  try {
    if (isNaN(stringFrom))
      throw { status: 404, message: "route from not found !" };
    const from = parseInt(stringFrom);

    const resolveTarget = () => {
      if (isNaN(stringId) && stringId !== "all")
        throw { status: 404, message: "route id not found !" };
      const id = parseInt(stringId);
      switch (stringId) {
        case "all": {
          switch (target) {
            case "client":
              return {
                clientId: { not: null },
              };
            case "all":
              return {};
            default:
              throw { status: 404, message: "route target not found !" };
          }
        }
        default: {
          switch (target) {
            case "client":
              return { clientId: id };
            default:
              throw { status: 404, message: "route not found !" };
          }
        }
      }
    };
    const query = resolveTarget();
    switch (method) {
      case "list":
        {
          const debts = await prisma.debit.findMany({
            where: query,
            take: Number(from + defaultResLength),
            skip: from,
            orderBy: {
              id: "desc",
            },
          });
          res.status(200).json(debts);
        }
        break;
      case "sum":
        {
          const sum = (
            await prisma.debit.aggregate({
              where: query,
              _sum: { amount: true },
            })
          )._sum.amount;
          res.status(200).json({ amount: Number(sum) });
        }
        break;
      default:
        throw { status: 404, message: "route method not found !" };
    }
  } catch (error) {
    console.log(error);
    if (error.status) res.status(error.status).json(error.message);
    else res.status(500).json("Error: server Error!");
  }
});

//Debts
app.post("/api/debt", verifyAdmin, async (req, res) => {
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
app.get("/api/debt/:target/:id/:method/:from?", async (req, res) => {
  const stringFrom = req.params.from || 0;
  const target = req.params.target;
  const stringId = req.params.id;
  const method = req.params.method;
  try {
    if (isNaN(stringFrom))
      throw { status: 404, message: "route from not found !" };
    const from = parseInt(stringFrom);

    const resolveTarget = () => {
      if (isNaN(stringId) && stringId !== "all")
        throw { status: 404, message: "route id not found !" };
      const id = parseInt(stringId);
      switch (stringId) {
        case "all": {
          switch (target) {
            case "trader":
              return {
                traderId: { not: null },
              };
            case "employee":
              return {
                employeeId: { not: null },
              };
            case "all":
              return {};
            default:
              throw { status: 404, message: "route target not found !" };
          }
        }
        default: {
          switch (target) {
            case "trader":
              return { traderId: id };
            case "employee":
              return { employeeId: id };
            default:
              throw { status: 404, message: "route not found !" };
          }
        }
      }
    };
    const query = resolveTarget();
    switch (method) {
      case "list":
        {
          const debts = await prisma.debt.findMany({
            where: query,
            take: Number(from + defaultResLength),
            skip: from,
            orderBy: {
              id: "desc",
            },
          });
          res.status(200).json(debts);
        }
        break;
      case "sum":
        {
          const sum = (
            await prisma.debt.aggregate({
              where: query,
              _sum: { amount: true },
            })
          )._sum.amount;
          res.status(200).json({ amount: Number(sum) });
        }
        break;
      default:
        throw { status: 404, message: "route method not found !" };
    }
  } catch (error) {
    console.log(error);
    if (error.status) res.status(error.status).json(error.message);
    else res.status(500).json("Error: server Error!");
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
app.get("/api/income/:target/:id/:method/:from?", async (req, res) => {
  const stringFrom = req.params.from || 0;
  const target = req.params.target;
  const stringId = req.params.id;
  const method = req.params.method;
  try {
    if (isNaN(stringFrom))
      throw { status: 404, message: "route from not found !" };
    const from = parseInt(stringFrom);

    const resolveTarget = () => {
      if (isNaN(stringId) && stringId !== "all")
        throw { status: 404, message: "route id not found !" };
      const id = parseInt(stringId);
      switch (stringId) {
        case "all": {
          switch (target) {
            case "client":
              return {
                clientId: { not: null },
              };
            case "all":
              return {};
            default:
              throw { status: 404, message: "route target not found !" };
          }
        }
        default: {
          switch (target) {
            case "client":
              return { clientId: id };
            default:
              throw { status: 404, message: "route not found !" };
          }
        }
      }
    };
    const query = resolveTarget();
    switch (method) {
      case "list":
        {
          const incomes = await prisma.income.findMany({
            where: query,
            take: Number(from + defaultResLength),
            skip: from,
            orderBy: {
              id: "desc",
            },
          });
          res.status(200).json(incomes);
        }
        break;
      case "sum":
        {
          const sum = (
            await prisma.income.aggregate({
              where: query,
              _sum: { amount: true },
            })
          )._sum.amount;
          res.status(200).json({ amount: Number(sum) });
        }
        break;
      default:
        throw { status: 404, message: "route method not found !" };
    }
  } catch (error) {
    console.log(error);
    if (error.status) res.status(error.status).json(error.message);
    else res.status(500).json("Error: server Error!");
  }
});

//Expenses
app.post("/api/expense", verifyAdmin, async (req, res) => {
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
app.get("/api/expense/:target/:id/:method/:from?", async (req, res) => {
  const stringFrom = req.params.from || 0;
  const target = req.params.target;
  const stringId = req.params.id;
  const method = req.params.method;
  try {
    if (isNaN(stringFrom))
      throw { status: 404, message: "route from not found !" };
    const from = parseInt(stringFrom);

    const resolveTarget = () => {
      if (isNaN(stringId) && stringId !== "all")
        throw { status: 404, message: "route id not found !" };
      const id = parseInt(stringId);
      switch (stringId) {
        case "all": {
          switch (target) {
            case "employee":
              return { employeeId: { not: null } };
            case "trader":
              return { traderId: { not: null } };
            case "investor":
              return { investorId: { not: null } };
            case "work":
              return { work: true };
            case "all":
              return {};
            default:
              throw { status: 404, message: "route target not found !" };
          }
        }
        default: {
          switch (target) {
            case "employee":
              return { employeeId: id };
            case "trader":
              return { traderId: id };
            case "investor":
              return { investorId: id };
            default:
              throw { status: 404, message: "route not found !" };
          }
        }
      }
    };
    const query = resolveTarget();
    switch (method) {
      case "list":
        {
          const expenses = await prisma.expense.findMany({
            where: query,
            take: Number(from + defaultResLength),
            skip: from,
            orderBy: {
              id: "desc",
            },
          });
          res.status(200).json(expenses);
        }
        break;
      case "sum":
        {
          const sum = (
            await prisma.expense.aggregate({
              where: query,
              _sum: { amount: true },
            })
          )._sum.amount;
          res.status(200).json({ amount: Number(sum) });
        }
        break;
      default:
        throw { status: 404, message: "route not found !" };
    }
  } catch (error) {
    console.log(error);
    if (error.status) res.status(error.status).json(error.message);
    else res.status(500).json("Error: server Error!");
  }
});

app.post("/api/signup", verifyAdmin, async (req, res) => {
  if (!req.body.username && !req.body.password)
    return res.status(401).json({ error: "Invalid Username or Password" });
  const { username, password, isAdmin = false } = req.body;
  try {
    const user = await prisma.user.findUnique({
      where: { username: username },
    });
    if (user)
      return res.status(401).json({ error: "username already exsists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: {
        username: username,
        isAdmin: isAdmin,
        password: hashedPassword,
      },
    });
    console.log(newUser);
    res.status(200).json("user created successfully !");
  } catch (error) {
    res.status(500).json("failed to signUp !");
  }
});

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

      res.cookie("token", accessToken, {
        httpOnly: true,
        Secure: true,
        Partitioned: true,
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

    res.cookie("token", accessToken, {
      httpOnly: true,
      Secure: true,
      Partitioned: true,
    });
    res.send({ refreshToken, ...payload });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to login" });
  }
});

// Sign Out
app.post("/api/logout", verify, async (req, res) => {
  try {
    const token = req.cookies["token"];
    if (token) {
      res.cookie("token", "");
    }

    res.status(200).json("Signed Out!");
  } catch (error) {
    res.status(500).json("server error");
  }
});

// Refresh accessToken
app.post("/api/refresh", async (req, res) => {
  try {
    console.log("attempting Refresh");
    // get refreshToken
    const refreshToken = req.body.token;
    //console.log(refreshToken);

    //send error if theres no token
    if (!refreshToken)
      return res.status(401).json("You are not authenticated!");

    // verify token
    jwt.verify(
      refreshToken,
      process.env.SECRET_REFRESH_KEY,
      async (err, user) => {
        err && console.log(err); // log any errors

        // create new tokens if every thing is ok
        const payload = GeneratePayload(user);
        const newAccessToken = GenerateAccessToken(payload);
        const newRefreshToken = GenerateRefreshToken(payload);
        // send new tokens to client
        try {
          res.cookie("token", newAccessToken, {
            httpOnly: true,
            Secure: true,
            Partitioned: true,
          });
          res.status(200).json({ refreshToken: newRefreshToken, ...user });
        } catch (error) {
          console.error(error); // log any errors
          res.status(500).json({ error: "Failed to authorize" });
        }
      },
    );
  } catch (error) {
    res.status(500).json("refresh Server Error");
  }
});

/*
const path = require("path");
const { setTimeout } = require("timers");

publicDirs.map((publicDir) => {
  app.use(express.static(publicDir));
});*/

/*app.get("*", (req, res) => {
  console.log(req.url);
  res.sendFile(path.join(__dirname, mainIndex));
});
*/

app.listen(
  port,
  //"127.0.0.1", //localhost only
  () => {
    console.log(`App listening on port ${port}`);
  },
);
