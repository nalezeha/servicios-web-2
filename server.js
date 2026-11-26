require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

app.use(express.json());
app.use(cors("*"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const port = 8080;

app.post("/sign-up", async (req, res) => {
  const { nombre, edad, correo, contrasena } = req.body;

  if (!nombre) {
    return res.status(400).json({ error: "El nombre no está definido" });
  }

  if (!edad) {
    return res.status(400).json({ error: "La edad no está definida" });
  }

  if (!correo) {
    return res.status(400).json({ error: "El correo no está definido" });
  }

  if (!contrasena) {
    return res.status(400).json({ error: "La contraseña no está definida" });
  }

  if (edad > 0 && edad < 17) {
    return res.status(400).json({ error: "Muy joven para registrarse" });
  }

  if (edad > 70) {
    return res.status(400).json({ error: "Edad no apropiada" });
  }

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(contrasena, salt);

  const nuevoUsuario = await pool.query(
    'INSERT INTO public."usuarios" (nombre, edad, correo, contrasena) VALUES ($1, $2, $3, $4) RETURNING *',
    [nombre, edad, correo, hash],
  );

  if (nuevoUsuario.rows.length > 0) {
    return res.status(201).json({ message: "Usuario creado exitosamente" });
  }

  return res.status(500).json({ error: "Error al crear el usuario" });
});

app.post("/sign-in", async (req, res) => {
  const { correo, contrasena } = req.body;

  if (!correo) {
    return res.status(400).json({ error: "Correo incorrecto" });
  }

  if (!contrasena) {
    return res.status(400).json({ error: "Contraseña incorrecta" });
  }

  const usuario = await pool.query(
    'SELECT * FROM public."usuarios" WHERE correo = $1',
    [correo],
  );

  if (usuario.rows.length === 0) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }

  const validarContrasena = await bcrypt.compare(
    contrasena,
    usuario.rows[0].contrasena,
  );

  if (!validarContrasena) {
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }

  return res.status(200).json({ message: "Inicio de sesión exitoso" });
});

app.get("/usuarios", async (req, res) => {
  const { nombre, correo } = req.query;

  if (!nombre && !correo) {
    return res
      .status(400)
      .json({ error: "No has enviado el nombre y el correo" });
  }

  let usuarios;

  if (nombre) {
    usuarios = await pool.query(
      `SELECT * FROM public."usuarios" WHERE nombre = $1`,
      [nombre],
    );
  } else if (correo) {
    usuarios = await pool.query(
      `SELECT * FROM public."usuarios" WHERE correo = $1`,
      [correo],
    );
  } else {
    return res.status(400).json({ error: "Has enviado un dato incorrecto" });
  }

  if (!usuarios) {
    return res.status(400).json({ error: "No hay usuarios" });
  }

  if (usuarios.rows.length === 0) {
    return res.status(400).json({ error: "No hay usuarios" });
  }

  usuarios = usuarios.rows.filter((values) => {
    delete values.contrasena;

    return values;
  });

  return res.status(200).json(usuarios || []);
});

app.delete("/usuarios/:id", async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ error: "No has enviado el id" });
  }

  await pool.query(`DELETE FROM public."usuarios" WHERE id = $1`, [id]);

  return res.status(200).json({ message: "Usuario eliminado exitosamente" });
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
