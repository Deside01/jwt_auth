import { RequestHandler, NextFunction, Response } from "express";
import IRequestUser from "../interfaces/IRequestUser";
import jwt from "jsonwebtoken";
const ACCESS_KEY = process.env.ACCESS_KEY || "secret";

const validateAccessToken: RequestHandler = (
  req: IRequestUser,
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

export default validateAccessToken;
