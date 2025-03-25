"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
dotenv_1.default.config();
const app = (0, express_1.default)();
const ACCESS_KEY = process.env.ACCESS_KEY || "secret";
app.use(express_1.default.json());
const users = [];
const validateAccessToken = (req, res, next) => {
    const header = req.headers.authorization;
    const accessToken = header && header.split(" ")[1];
    if (!accessToken) {
        res.sendStatus(204);
        return;
    }
    jsonwebtoken_1.default.verify(accessToken, ACCESS_KEY, (err, user) => {
        if (err) {
            res.sendStatus(403);
            return;
        }
        req.user = user;
        next();
    });
};
app.post("/reg", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    if (!username || !password)
        return res.sendStatus(401);
    if (users.find((u) => u.username === username))
        return res.sendStatus(401);
    const hashedPassword = yield bcrypt_1.default.hash(password, 7);
    const user = { username, password: hashedPassword };
    users.push(user);
    return res.send(users);
}));
app.post("/login", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    if (!username || !password)
        return res.sendStatus(401);
    const user = users.find((u) => u.username === username);
    if (!user)
        return res.sendStatus(404);
    const checkPassword = yield bcrypt_1.default.compare(password, user.password);
    if (!checkPassword)
        return res.sendStatus(403);
    const token = jsonwebtoken_1.default.sign({ username }, ACCESS_KEY, { expiresIn: "30s" });
    return res.send(token);
}));
app.get("/profile", validateAccessToken, (req, res) => {
    res.send("gg");
});
app.listen(process.env.PORT, () => console.log("WORK"));
