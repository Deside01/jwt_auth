import express, {
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

dotenv.config();

const app = express();
const ACCESS_KEY = process.env.ACCESS_KEY || "secret";
app.use(express.json());

const users: any[] = [];

interface RequestUser extends Request {
  user?: any;
}

const validateAccessToken: RequestHandler = (
  req: RequestUser,
  res: Response,
  next: NextFunction
): void => {
  const header = req.headers.authorization;
  const accessToken = header && header.split(" ")[1];

  if (!accessToken) {
    res.sendStatus(204);
    return;
  }

  jwt.verify(accessToken, ACCESS_KEY, (err: any, user: any) => {
    if (err) {
      res.sendStatus(403);
      return;
    }

    req.user = user;

    next();
  });
};

app.post("/reg", async (req, res): Promise<any> => {
  const { username, password } = req.body;
  if (!username || !password) return res.sendStatus(401);
  if (users.find((u) => u.username === username)) return res.sendStatus(401);

  const hashedPassword = await bcrypt.hash(password, 7);

  const user = { username, password: hashedPassword };

  users.push(user);
  return res.send(users);
});

app.post("/login", async (req, res): Promise<any> => {
  const { username, password } = req.body;
  if (!username || !password) return res.sendStatus(401);

  const user = users.find((u) => u.username === username);
  if (!user) return res.sendStatus(404);

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) return res.sendStatus(403);

  const token = jwt.sign({ username }, ACCESS_KEY, { expiresIn: "30s" });

  return res.send(token);
});

app.get(
  "/profile",
  validateAccessToken,
  (req: RequestUser, res: Response): void => {
    res.send("gg");
  }
);

app.listen(process.env.PORT, () => console.log("WORK"));
