const bcrypt = require('bcrypt-nodejs');

function gerarSenha() {
  const caracteres = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*";
  let senha = "";
  for (let i = 0; i < 8; i++) {
    senha += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
  }
  return senha;
}


async function gerarSenhaCriptografada() {
  const senha = gerarSenha();
  const saltRounds = 10;

  return new Promise((resolve, reject) => {
      bcrypt.genSalt(saltRounds, (err, salt) => {
          if (err) reject(err);

          bcrypt.hash(senha, salt, null, (err, hash) => {
              if (err) reject(err);
              resolve({ senhaPlana: senha, senhaCriptografada: hash });
          });
      });
  });
}

// Exemplo de uso: gera uma senha criptografada e imprime a senha plana e a senha criptografada
gerarSenhaCriptografada()
  .then(resultado => {
      console.log("Senha Plana:", resultado.senhaPlana);
      console.log("Senha Criptografada:", resultado.senhaCriptografada);
  })
  .catch(erro => console.error("Erro ao gerar senha:", erro));