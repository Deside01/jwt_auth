import { Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import IRequestUser from "../interfaces/IRequestUser";

const ACCESS_KEY = process.env.ACCESS_KEY || "secret";
const REFRESH_KEY = process.env.ACCESS_KEY || "secret_ref";

const users: any[] = [];
let refTokens: any[] = [];

const generateAccessToken = (payload: object, expiresIn: any = "30s") => {
  return jwt.sign(payload, ACCESS_KEY, { expiresIn });
};

class AuthController {
  async registration(req: IRequestUser, res: Response): Promise<Response> {
    const { username, password } = req.body;
    if (!username || !password) return res.sendStatus(401);
    if (users.find((u) => u.username === username)) return res.sendStatus(401);

    const hashedPassword = await bcrypt.hash(password, 7);

    const user = { username, password: hashedPassword };

    users.push(user);
    return res.send(users);
  }

  async login(req: IRequestUser, res: Response) {
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
  }

  async profile(req: IRequestUser, res: Response) {
    res.send("profile");
  }

  async logout(req: IRequestUser, res: Response) {
    const currentToken = req.body.token;
    if (!currentToken) return res.sendStatus(401);

    refTokens = refTokens.filter((token) => token !== currentToken);
    return res.sendStatus(204);
  }

  getToken(req: IRequestUser, res: Response) {
    res.send(refTokens);
  }

  newToken(req: IRequestUser, res: Response) {
    const token = req.body.token;
    if (!token) return res.sendStatus(401);

    if (!refTokens.includes(token)) return res.sendStatus(401);

    jwt.verify(token, REFRESH_KEY, (err: any, payload: any) => {
      if (err) return res.sendStatus(403);

      const newAccessToken = generateAccessToken({
        username: payload.username,
      });

      return res.send(newAccessToken);
    });
  }
}

export default new AuthController();
