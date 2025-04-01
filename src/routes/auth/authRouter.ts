import { Router, Response } from "express";
import validateAccessToken from "../../middlewares/validateAccessToken";
import IRequestUser from "../../interfaces/IRequestUser";
import AuthController from "../../controllers/AuthController";
const router = Router();

router.post(
  "/registration",
  async (req: IRequestUser, res: Response): Promise<any> => {
    return await AuthController.registration(req, res);
  }
);

router.post(
  "/login",
  async (req: IRequestUser, res: Response): Promise<any> => {
    return await AuthController.login(req, res);
  }
);

router.get(
  "/profile",
  validateAccessToken,
  (req: IRequestUser, res: Response): any => {
    return AuthController.profile(req, res);
  }
);

router.delete("/logout", (req: IRequestUser, res: Response): any => {
  return AuthController.logout(req, res);
});

router.get("/token", (req: IRequestUser, res: Response) => {
  return AuthController.getToken(req, res);
});

router.post("/token", (req: IRequestUser, res: Response): any => {
  return AuthController.newToken(req, res);
});

export default router;
