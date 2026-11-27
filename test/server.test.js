const assert = require("assert");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const request = require("supertest");

// Base de datos simulada: las pruebas no tocan la base real.
// Se reemplaza el método query ANTES de cargar el servidor.
let respuestaBD = { rows: [] };
let consultas = [];

Pool.prototype.query = async function (sql, valores) {
  consultas.push({ sql, valores });
  return respuestaBD;
};

const app = require("../server");

describe("API de usuarios", () => {
  beforeEach(() => {
    respuestaBD = { rows: [] };
    consultas = [];
  });

  const usuarioValido = {
    nombre: "Andres",
    edad: 25,
    correo: "andres@correo.com",
    contrasena: "123456",
  };

  describe("POST /sign-up", () => {
    it("responde 400 si falta el nombre", async () => {
      const { nombre, ...datos } = usuarioValido;
      const res = await request(app).post("/sign-up").send(datos);

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "El nombre no está definido");
    });

    it("responde 400 si falta la edad", async () => {
      const { edad, ...datos } = usuarioValido;
      const res = await request(app).post("/sign-up").send(datos);

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "La edad no está definida");
    });

    it("responde 400 si falta el correo", async () => {
      const { correo, ...datos } = usuarioValido;
      const res = await request(app).post("/sign-up").send(datos);

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "El correo no está definido");
    });

    it("responde 400 si el correo no es válido", async () => {
      const res = await request(app)
        .post("/sign-up")
        .send({ ...usuarioValido, correo: "correo-sin-arroba" });

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "El correo no es válido");
    });

    it("responde 400 si falta la contraseña", async () => {
      const { contrasena, ...datos } = usuarioValido;
      const res = await request(app).post("/sign-up").send(datos);

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "La contraseña no está definida");
    });

    it("responde 400 si el usuario es muy joven", async () => {
      const res = await request(app)
        .post("/sign-up")
        .send({ ...usuarioValido, edad: 15 });

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "Muy joven para registrarse");
    });

    it("responde 400 si la edad supera el máximo permitido", async () => {
      const res = await request(app)
        .post("/sign-up")
        .send({ ...usuarioValido, edad: 80 });

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "Edad no apropiada");
    });

    it("responde 201 y guarda la contraseña cifrada con datos válidos", async () => {
      respuestaBD = { rows: [{ id: 1 }] };

      const res = await request(app).post("/sign-up").send(usuarioValido);

      assert.strictEqual(res.status, 201);
      assert.strictEqual(res.body.message, "Usuario creado exitosamente");

      const guardada = consultas[0].valores[3];
      assert.notStrictEqual(guardada, usuarioValido.contrasena);
      assert.ok(bcrypt.compareSync(usuarioValido.contrasena, guardada));
    });

    it("responde 500 si la base de datos no devuelve el usuario", async () => {
      const res = await request(app).post("/sign-up").send(usuarioValido);

      assert.strictEqual(res.status, 500);
      assert.strictEqual(res.body.error, "Error al crear el usuario");
    });
  });

  describe("POST /sign-in", () => {
    it("responde 400 si falta el correo", async () => {
      const res = await request(app)
        .post("/sign-in")
        .send({ contrasena: "123456" });

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "Correo incorrecto");
    });

    it("responde 400 si falta la contraseña", async () => {
      const res = await request(app)
        .post("/sign-in")
        .send({ correo: "andres@correo.com" });

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "Contraseña incorrecta");
    });

    it("responde 404 si el usuario no existe", async () => {
      const res = await request(app)
        .post("/sign-in")
        .send({ correo: "nadie@correo.com", contrasena: "123456" });

      assert.strictEqual(res.status, 404);
      assert.strictEqual(res.body.error, "Usuario no encontrado");
    });

    it("responde 401 si la contraseña es incorrecta", async () => {
      respuestaBD = {
        rows: [{ contrasena: bcrypt.hashSync("correcta", 4) }],
      };

      const res = await request(app)
        .post("/sign-in")
        .send({ correo: "andres@correo.com", contrasena: "equivocada" });

      assert.strictEqual(res.status, 401);
      assert.strictEqual(res.body.error, "Contraseña incorrecta");
    });

    it("responde 200 si las credenciales son correctas", async () => {
      respuestaBD = {
        rows: [{ contrasena: bcrypt.hashSync("correcta", 4) }],
      };

      const res = await request(app)
        .post("/sign-in")
        .send({ correo: "andres@correo.com", contrasena: "correcta" });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.message, "Inicio de sesión exitoso");
    });
  });

  describe("GET /usuarios", () => {
    it("responde 400 si no se envía nombre ni correo", async () => {
      const res = await request(app).get("/usuarios");

      assert.strictEqual(res.status, 400);
      assert.strictEqual(
        res.body.error,
        "No has enviado el nombre y el correo",
      );
    });

    it("responde 400 si no hay usuarios", async () => {
      const res = await request(app).get("/usuarios?nombre=Nadie");

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, "No hay usuarios");
    });

    it("responde 200 con el usuario y sin mostrar la contraseña", async () => {
      respuestaBD = {
        rows: [
          { id: 1, nombre: "Andres", correo: "andres@correo.com", contrasena: "hash" },
        ],
      };

      const res = await request(app).get("/usuarios?nombre=Andres");

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.length, 1);
      assert.strictEqual(res.body[0].nombre, "Andres");
      assert.strictEqual(res.body[0].contrasena, undefined);
    });

    it("permite buscar por correo", async () => {
      respuestaBD = {
        rows: [{ id: 1, nombre: "Andres", correo: "andres@correo.com", contrasena: "hash" }],
      };

      const res = await request(app).get("/usuarios?correo=andres@correo.com");

      assert.strictEqual(res.status, 200);
      assert.deepStrictEqual(consultas[0].valores, ["andres@correo.com"]);
    });
  });

  describe("DELETE /usuarios/:id", () => {
    it("responde 200 al eliminar un usuario", async () => {
      const res = await request(app).delete("/usuarios/5");

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.message, "Usuario eliminado exitosamente");
      assert.deepStrictEqual(consultas[0].valores, ["5"]);
    });
  });
});
