const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  connectionString: 'postgresql://connectfamead:q0rRK1gyMALN@ep-white-sky-a52j6d6i.us-east-2.aws.neon.tech/lms_mmstrok?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

function generateSecurePassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789@#$!';
  let password = '';
  for (let i = 0; i < 12; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  // Ensure at least one uppercase, lowercase, number, special
  if (!/[A-Z]/.test(password)) password = password.slice(0, -1) + 'A';
  if (!/[a-z]/.test(password)) password = password.slice(0, -1) + 'b';
  if (!/[0-9]/.test(password)) password = password.slice(0, -1) + '2';
  if (!/[@#$!]/.test(password)) password = password.slice(0, -1) + '@';
  return password;
}

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

async function main() {
  const client = await pool.connect();
  
  try {
    // Get all alunos from the company
    const alunosResult = await client.query(`
      SELECT id, username, nome, sobrenome, email 
      FROM users 
      WHERE empresa = 'Gabriel - GRUPO ZAMBIANCO' 
      AND role = 'Aluno'
      ORDER BY id
    `);
    
    const alunos = alunosResult.rows;
    console.log(`Encontrados ${alunos.length} alunos para atualizar senhas`);
    
    const updatedCredentials = [];
    
    for (const aluno of alunos) {
      const novaSenha = generateSecurePassword();
      const senhaHash = await hashPassword(novaSenha);
      
      await client.query(`
        UPDATE users SET senha = $1 WHERE id = $2
      `, [senhaHash, aluno.id]);
      
      updatedCredentials.push({
        username: aluno.username,
        nome: aluno.nome,
        sobrenome: aluno.sobrenome,
        email: aluno.email,
        novaSenha: novaSenha
      });
      
      console.log(`✅ Senha atualizada: ${aluno.username} (${aluno.email})`);
    }
    
    console.log('\n========== NOVAS CREDENCIAIS INDIVIDUAIS ==========\n');
    
    // Print credentials table
    console.log('┌────┬──────────────────────┬──────────────────────────────────────┬──────────────────────┐');
    console.log('│ #  │ Username             │ Email                                │ Senha                │');
    console.log('├────┼──────────────────────┼──────────────────────────────────────┼──────────────────────┤');
    
    updatedCredentials.forEach((cred, i) => {
      const num = String(i + 1).padStart(2, '0');
      const user = cred.username.padEnd(20);
      const email = cred.email.padEnd(36);
      const senha = cred.novaSenha.padEnd(20);
      console.log(`│ ${num} │ ${user} │ ${email} │ ${senha} │`);
    });
    
    console.log('└────┴──────────────────────┴──────────────────────────────────────┴──────────────────────┘');
    
    // Also print as CSV for easy sharing
    console.log('\n--- CSV FORMAT ---');
    console.log('username,nome,sobrenome,email,senha');
    updatedCredentials.forEach(cred => {
      console.log(`${cred.username},${cred.nome},${cred.sobrenome},${cred.email},${cred.novaSenha}`);
    });
    
    console.log('\n⚠️  IMPORTANTE: Salve estas credenciais agora! Não será possível recuperar as senhas depois.');
    console.log('   Cada aluno deve receber sua senha individual de forma segura (ex: WhatsApp, e-mail pessoal).');
    
  } catch (error) {
    console.error('❌ Erro:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

main();