const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { PrismaClient } = require("@prisma/client");


const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

const SECRET = "secret";

const auth = (req: any, res: any, next: any) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send("Unauthorized");

  try {
    const decoded: any = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).send("Invalid token");
  }
};

app.post("/auth/register", async (req: any, res: any) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send("Missing fields");
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, password: hash },
    });

    res.json(user);
  } catch (error: any) {
    console.log(error); // 👈 VERY IMPORTANT
    res.status(500).send("Server error");
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).send("User not found");

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).send("Wrong password");

  const token = jwt.sign({ id: user.id }, SECRET);
  res.json({ token });
});

app.post("/tasks", auth, async (req: any, res) => {
  const task = await prisma.task.create({
    data: {
      title: req.body.title,
      userId: req.userId,
    },
  });
  res.json(task);
});

app.get("/tasks", auth, async (req: any, res) => {
  const { search } = req.query;

  const tasks = await prisma.task.findMany({
    where: {
      userId: req.userId,
      title: { contains: search || "" },
    },
  });

  res.json(tasks);
});

app.patch("/tasks/:id/toggle", auth, async (req, res) => {
  const id = Number(req.params.id);

  const task = await prisma.task.findUnique({ where: { id } });

  const updated = await prisma.task.update({
    where: { id },
    data: { completed: !task?.completed },
  });

  res.json(updated);
});

app.delete("/tasks/:id", auth, async (req, res) => {
  const id = Number(req.params.id);

  await prisma.task.delete({ where: { id } });
  res.send("Deleted");
});

app.listen(5000, () => console.log("Server running"));