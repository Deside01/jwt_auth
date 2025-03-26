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
const validateAccessToken_1 = __importDefault(require("./middlewares/validateAccessToken"));
dotenv_1.default.config();
const app = (0, express_1.default)();
const ACCESS_KEY = process.env.ACCESS_KEY || "secret";
const REFRESH_KEY = process.env.ACCESS_KEY || "secret_ref";
app.use(express_1.default.json());
const users = [];
let refTokens = [];
const generateAccessToken = (payload, expiresIn = "30s") => {
    return jsonwebtoken_1.default.sign(payload, ACCESS_KEY, { expiresIn });
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
    const accessToken = generateAccessToken({ username });
    const refreshToken = jsonwebtoken_1.default.sign({ username }, REFRESH_KEY, {
        expiresIn: "120s",
    });
    refTokens.push(refreshToken);
    return res.send({ accessToken, refreshToken });
}));
app.get("/profile", validateAccessToken_1.default, (req, res) => {
    res.send("gg");
});
app.delete("/logout", (req, res) => {
    const currentToken = req.body.token;
    if (!currentToken)
        return res.sendStatus(401);
    refTokens = refTokens.filter((token) => token !== currentToken);
    return res.sendStatus(204);
});
app.get("/token", (req, res) => {
    res.send(refTokens);
});
app.post("/token", (req, res) => {
    const token = req.body.token;
    if (!token)
        return res.sendStatus(401);
    if (!refTokens.includes(token))
        return res.sendStatus(401);
    jsonwebtoken_1.default.verify(token, REFRESH_KEY, (err, payload) => {
        if (err)
            return res.sendStatus(403);
        const newAccessToken = generateAccessToken({ username: payload.username });
        return res.send(newAccessToken);
    });
});
app.listen(process.env.PORT, () => console.log("WORK"));
