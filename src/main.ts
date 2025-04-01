import express from "express";
import dotenv from "dotenv";
import authRouter from "./routes/auth/authRouter";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(authRouter);

app.listen(PORT, () => console.log(`SERVER STARTED AT ${PORT}`));
