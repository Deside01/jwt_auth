import { Request } from "express";

export default interface IRequestUser extends Request {
  user?: any;
}
