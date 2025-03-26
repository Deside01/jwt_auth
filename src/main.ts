import express, { Response } from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import validateAccessToken from "./middlewares/validateAccessToken";
import IRequestUser from "./interfaces/IRequestUser";
dotenv.config();

const app = express();
const ACCESS_KEY = process.env.ACCESS_KEY || "secret";
const REFRESH_KEY = process.env.ACCESS_KEY || "secret_ref";

app.use(express.json());

const users: any[] = [];
let refTokens: any[] = [];

const generateAccessToken = (payload: object, expiresIn: any = "30s") => {
  return jwt.sign(payload, ACCESS_KEY, { expiresIn });
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

  const accessToken = generateAccessToken({ username });
  const refreshToken = jwt.sign({ username }, REFRESH_KEY, {
    expiresIn: "120s",
  });

  refTokens.push(refreshToken);

  return res.send({ accessToken, refreshToken });
});

app.get(
  "/profile",
  validateAccessToken,
  (req: IRequestUser, res: Response): void => {
    res.send("gg");
  }
);

app.delete("/logout", (req, res): any => {
  const currentToken = req.body.token;
  if (!currentToken) return res.sendStatus(401);

  refTokens = refTokens.filter((token) => token !== currentToken);
  return res.sendStatus(204);
});

app.get("/token", (req, res) => {
  res.send(refTokens);
});

app.post("/token", (req, res): any => {
  const token = req.body.token;
  if (!token) return res.sendStatus(401);

  if (!refTokens.includes(token)) return res.sendStatus(401);

  jwt.verify(token, REFRESH_KEY, (err: any, payload: any) => {
    if (err) return res.sendStatus(403);

    const newAccessToken = generateAccessToken({ username: payload.username });

    return res.send(newAccessToken);
  });
});

app.listen(process.env.PORT, () => console.log("WORK"));
