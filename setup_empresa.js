const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); // usar bcryptjs que é mais confiável

const pool = new Pool({
  connectionString: 'postgresql://connectfamead:q0rRK1gyMALN@ep-white-sky-a52j6d6i.us-east-2.aws.neon.tech/lms_mmstrok?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

async function main() {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 1. Create company
    const empresaNome = 'Empresa Teste Acesso Total';
    const empresaEmail = 'empresa@testeacesso.com';
    const empresaSenha = 'Empresa@123';
    const empresaSenhaHash = await hashPassword(empresaSenha);
    
    const empresaResult = await client.query(`
      INSERT INTO empresas (nome, email, senha, cnpj, razao_social, endereco, cidade, estado, cep, telefone, responsavel)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, nome, email
    `, [
      empresaNome,
      empresaEmail,
      empresaSenhaHash,
      '12.345.678/0001-90',
      'Empresa Teste Acesso Total LTDA',
      'Rua Teste, 123',
      'São Paulo',
      'SP',
      '01000-000',
      '(11) 99999-9999',
      'Responsável Teste'
    ]);
    
    const empresa = empresaResult.rows[0];
    console.log('✅ Empresa criada:', empresa);
    
    // 2. Get all courses with valor_10d = 280
    const cursosResult = await client.query(`
      SELECT id FROM cursos WHERE valor_10d = '280.00' OR valor_10d = 280
    `);
    const cursoIds = cursosResult.rows.map(r => r.id);
    console.log(`✅ Encontrados ${cursoIds.length} cursos com valor 280`);
    
    // 3. Create 3 students
    const alunos = [
      { username: 'aluno1_teste', nome: 'Aluno', sobrenome: 'Um', email: 'aluno1@testeacesso.com', senha: 'Aluno1@123' },
      { username: 'aluno2_teste', nome: 'Aluno', sobrenome: 'Dois', email: 'aluno2@testeacesso.com', senha: 'Aluno2@123' },
      { username: 'aluno3_teste', nome: 'Aluno', sobrenome: 'Tres', email: 'aluno3@testeacesso.com', senha: 'Aluno3@123' },
    ];
    
    const createdAlunos = [];
    
    for (const aluno of alunos) {
      const senhaHash = await hashPassword(aluno.senha);
      
      const userResult = await client.query(`
        INSERT INTO users (username, nome, sobrenome, email, role, empresa, senha)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, username, email
      `, [
        aluno.username,
        aluno.nome,
        aluno.sobrenome,
        aluno.email,
        'Aluno',
        empresaNome,
        senhaHash
      ]);
      
      const user = userResult.rows[0];
      createdAlunos.push({ ...user, senhaOriginal: aluno.senha });
      console.log(`✅ Aluno criado:`, user);
      
      // 4. Grant access to all 280 courses for this student
      for (const cursoId of cursoIds) {
        await client.query(`
          INSERT INTO compras_cursos (user_id, curso_id, status, periodo, data_inicio_acesso, data_fim_acesso)
          VALUES ($1, $2, 'aprovado', '6m', NOW(), NOW() + INTERVAL '6 months')
          ON CONFLICT DO NOTHING
        `, [user.id, cursoId]);
      }
      console.log(`   → Acesso concedido a ${cursoIds.length} cursos`);
    }
    
    await client.query('COMMIT');
    
    // Summary
    console.log('\n========== RESUMO FINAL ==========');
    console.log('\n🏢 EMPRESA:');
    console.log(`   Nome: ${empresa.nome}`);
    console.log(`   Email: ${empresa.email}`);
    console.log(`   Senha: ${empresaSenha}`);
    console.log(`   ID: ${empresa.id}`);
    
    console.log('\n👥 ALUNOS (3 criados com acesso a TODOS os 84 cursos de R$ 280):');
    createdAlunos.forEach((a, i) => {
      console.log(`\n   Aluno ${i+1}:`);
      console.log(`     Username: ${a.username}`);
      console.log(`     Email: ${a.email}`);
      console.log(`     Senha: ${a.senhaOriginal}`);
      console.log(`     ID: ${a.id}`);
      console.log(`     Empresa: ${empresaNome}`);
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Erro:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

main();
