import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET não configurado no arquivo .env");
}

let usuarios = [];
let transacoes = [];
let metas = [];

let proximoUsuarioId = 1;
let proximaTransacaoId = 1;
let proximaMetaId = 1;

function gerarToken(usuario) {
  return jwt.sign(
    {
      id: usuario.id,
      email: usuario.email
    },
    JWT_SECRET,
    { expiresIn: "1d" }
  );
}

function autenticar(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      erro: "Token ausente ou inválido"
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const usuario = usuarios.find(
      (u) => u.id === decoded.id
    );

    if (!usuario) {
      return res.status(401).json({
        erro: "Token ausente ou inválido"
      });
    }

    req.usuario = usuario;
    next();
  } catch (error) {
    return res.status(401).json({
      erro: "Token ausente ou inválido"
    });
  }
}

function validarTransacao(dados) {
  if (
    !dados.descricao ||
    typeof dados.descricao !== "string" ||
    !dados.descricao.trim()
  ) {
    return "Descrição inválida";
  }

  if (
    typeof dados.valor !== "number" ||
    !Number.isFinite(dados.valor) ||
    dados.valor <= 0
  ) {
    return "O valor deve ser maior que zero";
  }

  if (!["receita", "despesa"].includes(dados.tipo)) {
    return "Tipo deve ser receita ou despesa";
  }

  if (
    !dados.data ||
    !/^\d{4}-\d{2}-\d{2}$/.test(dados.data) ||
    !Number.isFinite(Date.parse(dados.data + "T00:00:00Z")) ||
    new Date(dados.data + "T00:00:00Z")
      .toISOString().slice(0, 10) !== dados.data
  ) {
    return "Data inválida";
  }

  return null;
}

function validarMeta(dados) {
  if (
    !dados.nome ||
    typeof dados.nome !== "string" ||
    !dados.nome.trim()
  ) {
    return "Nome da meta inválido";
  }

  if (
    typeof dados.valorObjetivo !== "number" ||
    !Number.isFinite(dados.valorObjetivo) ||
    dados.valorObjetivo <= 0
  ) {
    return "O valor objetivo deve ser maior que zero";
  }

  if (
    dados.valorGuardado !== undefined &&
    (
      typeof dados.valorGuardado !== "number" ||
      !Number.isFinite(dados.valorGuardado) ||
      dados.valorGuardado < 0
    )
  ) {
    return "O valor guardado não pode ser negativo";
  }

  if (
    !dados.dataLimite ||
    !/^\d{4}-\d{2}-\d{2}$/.test(dados.dataLimite) ||
    !Number.isFinite(Date.parse(dados.dataLimite + "T00:00:00Z")) ||
    new Date(dados.dataLimite + "T00:00:00Z")
      .toISOString().slice(0, 10) !== dados.dataLimite
  ) {
    return "Data limite inválida";
  }

  if (
    dados.valorGuardado !== undefined &&
    dados.valorGuardado > dados.valorObjetivo
  ) {
    return "O valor guardado não pode superar o valor objetivo";
  }

  return null;
}
app.post("/auth/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (
      typeof nome !== "string" ||
      !nome.trim() ||
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof senha !== "string" ||
      senha.length < 6
    ) {
      return res.status(400).json({
        erro: "Informe nome, e-mail válido e senha com pelo menos 6 caracteres"
      });
    }

    const emailNormalizado = email.trim().toLowerCase();

    const existente = usuarios.find(
      (u) => u.email === emailNormalizado
    );

    if (existente) {
      return res.status(400).json({
        erro: "E-mail já utilizado"
      });
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    const novoUsuario = {
      id: proximoUsuarioId++,
      nome: nome.trim(),
      email: emailNormalizado,
      senha: senhaHash
    };

    usuarios.push(novoUsuario);

    return res.status(201).json({
      id: novoUsuario.id,
      nome: novoUsuario.nome,
      email: novoUsuario.email
    });

  } catch (error) {
    return res.status(500).json({
      erro: "Erro ao cadastrar usuário"
    });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    const usuario = usuarios.find(
      (u) => u.email === String(email || "").trim().toLowerCase()
    );

    if (
      !usuario ||
      typeof senha !== "string" ||
      !(await bcrypt.compare(senha, usuario.senha))
    ) {
      return res.status(401).json({
        erro: "E-mail ou senha incorretos"
      });
    }

    const token = gerarToken(usuario);

    return res.status(200).json({ token });

  } catch (error) {
    return res.status(500).json({
      erro: "Erro ao realizar login"
    });
  }
});

app.get("/auth/perfil", autenticar, (req, res) => {
  return res.status(200).json({
    id: req.usuario.id,
    nome: req.usuario.nome,
    email: req.usuario.email
  });
});

app.get("/transacoes", autenticar, (req, res) => {
  const resultado = transacoes.filter(
    (t) => t.usuarioId === req.usuario.id
  );

  return res.status(200).json(resultado);
});

app.get("/transacoes/:id", autenticar, (req, res) => {
  const transacao = transacoes.find(
    (t) => t.id === Number(req.params.id)
  );

  if (!transacao) {
    return res.status(404).json({
      erro: "Transação não encontrada"
    });
  }

  if (transacao.usuarioId !== req.usuario.id) {
    return res.status(403).json({
      erro: "Sem permissão para visualizar esta transação"
    });
  }

  return res.status(200).json(transacao);
});

app.post("/transacoes", autenticar, (req, res) => {
  const erro = validarTransacao(req.body);

  if (erro) {
    return res.status(400).json({ erro });
  }

  const novaTransacao = {
    id: proximaTransacaoId++,
    descricao: req.body.descricao.trim(),
    valor: req.body.valor,
    tipo: req.body.tipo,
    data: req.body.data,
    usuarioId: req.usuario.id
  };

  transacoes.push(novaTransacao);

  return res.status(201).json(novaTransacao);
});

app.put("/transacoes/:id", autenticar, (req, res) => {
  const transacao = transacoes.find(
    (t) => t.id === Number(req.params.id)
  );

  if (!transacao) {
    return res.status(404).json({
      erro: "Transação não encontrada"
    });
  }

  if (transacao.usuarioId !== req.usuario.id) {
    return res.status(403).json({
      erro: "Sem permissão para alterar esta transação"
    });
  }

  const erro = validarTransacao(req.body);

  if (erro) {
    return res.status(400).json({ erro });
  }

  transacao.descricao = req.body.descricao.trim();
  transacao.valor = req.body.valor;
  transacao.tipo = req.body.tipo;
  transacao.data = req.body.data;

  return res.status(200).json(transacao);
});

app.delete("/transacoes/:id", autenticar, (req, res) => {
  const indice = transacoes.findIndex(
    (t) => t.id === Number(req.params.id)
  );

  if (indice === -1) {
    return res.status(404).json({
      erro: "Transação não encontrada"
    });
  }

  if (transacoes[indice].usuarioId !== req.usuario.id) {
    return res.status(403).json({
      erro: "Sem permissão para remover esta transação"
    });
  }

  transacoes.splice(indice, 1);

  return res.status(204).send();
});

app.get("/metas", autenticar, (req, res) => {
  const resultado = metas.filter(
    (m) => m.usuarioId === req.usuario.id
  );

  return res.status(200).json(resultado);
});

app.get("/metas/:id", autenticar, (req, res) => {
  const meta = metas.find(
    (m) => m.id === Number(req.params.id)
  );

  if (!meta) {
    return res.status(404).json({
      erro: "Meta não encontrada"
    });
  }

  if (meta.usuarioId !== req.usuario.id) {
    return res.status(403).json({
      erro: "Sem permissão para visualizar esta meta"
    });
  }

  return res.status(200).json(meta);
});

app.post("/metas", autenticar, (req, res) => {
  const erro = validarMeta(req.body);

  if (erro) {
    return res.status(400).json({ erro });
  }

  const novaMeta = {
    id: proximaMetaId++,
    nome: req.body.nome.trim(),
    valorObjetivo: req.body.valorObjetivo,
    valorGuardado: 0,
    dataLimite: req.body.dataLimite,
    usuarioId: req.usuario.id
  };

  metas.push(novaMeta);

  return res.status(201).json(novaMeta);
});

app.put("/metas/:id", autenticar, (req, res) => {
  const meta = metas.find(
    (m) => m.id === Number(req.params.id)
  );

  if (!meta) {
    return res.status(404).json({
      erro: "Meta não encontrada"
    });
  }

  if (meta.usuarioId !== req.usuario.id) {
    return res.status(403).json({
      erro: "Sem permissão para alterar esta meta"
    });
  }

  const erro = validarMeta(req.body);

  if (erro) {
    return res.status(400).json({ erro });
  }

  meta.nome = req.body.nome.trim();
  meta.valorObjetivo = req.body.valorObjetivo;
  meta.valorGuardado = req.body.valorGuardado ?? 0;
  meta.dataLimite = req.body.dataLimite;

  return res.status(200).json(meta);
});

app.delete("/metas/:id", autenticar, (req, res) => {
  const indice = metas.findIndex(
    (m) => m.id === Number(req.params.id)
  );

  if (indice === -1) {
    return res.status(404).json({
      erro: "Meta não encontrada"
    });
  }

  if (metas[indice].usuarioId !== req.usuario.id) {
    return res.status(403).json({
      erro: "Sem permissão para remover esta meta"
    });
  }

  metas.splice(indice, 1);

  return res.status(204).send();
});

app.get("/", (req, res) => {
  res.status(200).json({
    mensagem: "API Controle Financeiro Pessoal funcionando!",
    versao: 1
  });
});

app.use((req, res) => {
  res.status(404).json({
    erro: "Rota não encontrada"
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
