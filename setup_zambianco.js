const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

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
    
    // ============================================================
    // 1. CREATE COMPANY "Gabriel - GRUPO ZAMBIANCO"
    // ============================================================
    const empresaNome = 'Gabriel - GRUPO ZAMBIANCO';
    const empresaEmail = 'gabriel@grupozambianco.com.br';
    const empresaSenha = 'Zambianco2620##';
    const empresaSenhaHash = await hashPassword(empresaSenha);
    
    const empresaResult = await client.query(`
      INSERT INTO empresas (nome, email, senha, cnpj, razao_social, endereco, cidade, estado, cep, telefone, responsavel)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, nome, email
    `, [
      empresaNome,
      empresaEmail,
      empresaSenhaHash,
      '00.000.000/0001-00', // CNPJ placeholder
      'GRUPO ZAMBIANCO LTDA',
      'Rodovia SP-304, Km 150',
      'Lençóis Paulista',
      'SP',
      '18680-000',
      '(14) 99999-9999',
      'Gabriel'
    ]);
    
    const empresa = empresaResult.rows[0];
    console.log('✅ Empresa criada:', empresa);
    
    // ============================================================
    // 2. DEFINE COURSES
    // ============================================================
    // 6 EAD modules from PDF (page 3)
    const cursosEAD = [1, 2, 3, 4, 11, 14]; // All 19 users get these
    
    // 3 Bonus Compras courses (page 2 of PDF)
    const cursosCompras = [5, 8, 9]; // 3 users get these additionally
    
    console.log(`\n📚 Cursos EAD (6): ${cursosEAD.join(', ')}`);
    console.log(`📚 Cursos Compras Bonus (3): ${cursosCompras.join(', ')}`);
    
    // ============================================================
    // 3. CREATE 19 ALUNOS FROM PDF
    // ============================================================
    const alunos = [
      { username: 'jose.baron', nome: 'Jose', sobrenome: 'Pedro Baron Junior', email: 'jose.baron@grupozambianco.com.br', cargo: 'Líder Almoxarifado' },
      { username: 'marcos.santos', nome: 'Marcos', sobrenome: 'Adriano Magalhães dos Santos', email: 'marcostenebra.2@gmail.com', cargo: 'Almoxarife Júnior' },
      { username: 'alexsandro.chaves', nome: 'Alexsandro', sobrenome: 'Chaves', email: 'chavesalexsandro349@gmail.com', cargo: 'Almoxarife Júnior' },
      { username: 'gabriel.leite', nome: 'Gabriel', sobrenome: 'da Silva Leite', email: 'gabrielfodex2004@gmail.com', cargo: 'Almoxarife Júnior' },
      { username: 'jefferson.santos', nome: 'Jefferson', sobrenome: 'Silva dos Santos', email: 'jeffersilsantos@gmail.com', cargo: 'Almoxarife Júnior' },
      { username: 'matheus.oliveira', nome: 'Matheus', sobrenome: 'Campos Conde de Oliveira', email: 'matheuscamposs7@gmail.com', cargo: 'Auxiliar de Almoxarifado' },
      { username: 'otavio.silva', nome: 'Otavio', sobrenome: 'Jacson Alfredo da Silva', email: 'otavio17jacson19@gmail.com', cargo: 'Auxiliar de Almoxarifado' },
      { username: 'patrick.ribeiro', nome: 'Patrick', sobrenome: 'Teodoro Teles Ribeiro', email: 'patrickteles2016@gmail.com', cargo: 'Almoxarife Sênior' },
      { username: 'ronald.santos', nome: 'Ronald', sobrenome: 'Pedro Ferreira dos Santos', email: 'ronaldsantos040903@gmail.com', cargo: 'Auxiliar de Almoxarifado' },
      { username: 'ryan.silva', nome: 'Ryan', sobrenome: 'Amario da Silva', email: 'ryanamario429@gmail.com', cargo: 'Auxiliar de Escritório' },
      { username: 'abel.junior', nome: 'Abel', sobrenome: 'Antonio da Silva Junior', email: 'junioramariodasilva@gmail.com', cargo: 'Auxiliar de Escritório' },
      { username: 'joao.boni', nome: 'Joao', sobrenome: 'Paulo Milani Boni', email: 'joaopaulomilaniboni@gmail.com', cargo: 'Auxiliar de Escritório' },
      { username: 'robson.augusto', nome: 'Robson', sobrenome: 'Aparecido Augusto', email: 'augustorobson621@gmail.com', cargo: 'Líder de Almoxarifado' },
      { username: 'willian.goncalves', nome: 'Willian', sobrenome: 'Paris Gonçalves', email: 'willianparis834@gmail.com', cargo: 'Almoxarife Júnior' },
      { username: 'ruan.souza', nome: 'Ruan', sobrenome: 'Pablo Nascimento de Souza', email: 'ruanpablons.souza@gmail.com', cargo: 'Menor Aprendiz' },
      { username: 'iury.silva', nome: 'Iury', sobrenome: 'Augusto Silva', email: 'augustoiury969@gmail.com', cargo: 'Almoxarife Pleno' },
      { username: 'barbara.lima', nome: 'Barbara', sobrenome: 'Diomar Silva de Lima', email: 'barbaradiomar@hotmail.com', cargo: 'Almoxarife Júnior' },
      { username: 'steffany.rocha', nome: 'Steffany', sobrenome: 'Gabrielle Silveira Rocha', email: 'steffanygabrielle47@gmail.com', cargo: 'Almoxarife Júnior' },
      { username: 'gelton.pereira', nome: 'Gelton', sobrenome: 'da Silva Pereira', email: 'gelton.silvasp@gmail.com', cargo: 'Almoxarife Júnior' },
    ];
    
    // 3 bonus users for Compras courses (first 3 from list)
    const bonusUsers = ['jose.baron', 'robson.augusto', 'patrick.ribeiro']; // Leaders get bonus
    
    const createdAlunos = [];
    const defaultSenha = 'Zambianco2620##'; // Same password for all students
    const senhaHash = await hashPassword(defaultSenha);
    
    for (const aluno of alunos) {
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
      createdAlunos.push({ 
        ...user, 
        senhaOriginal: defaultSenha,
        isBonus: bonusUsers.includes(aluno.username)
      });
      console.log(`✅ Aluno criado: ${aluno.nome} ${aluno.sobrenome} (${aluno.email})`);
      
      // Grant access to 6 EAD courses
      for (const cursoId of cursosEAD) {
        await client.query(`
          INSERT INTO compras_cursos (user_id, curso_id, status, periodo, data_inicio_acesso, data_fim_acesso)
          VALUES ($1, $2, 'aprovado', '6m', NOW(), NOW() + INTERVAL '6 months')
          ON CONFLICT DO NOTHING
        `, [user.id, cursoId]);
      }
      
      // Grant access to 3 bonus Compras courses for selected users
      if (bonusUsers.includes(aluno.username)) {
        for (const cursoId of cursosCompras) {
          await client.query(`
            INSERT INTO compras_cursos (user_id, curso_id, status, periodo, data_inicio_acesso, data_fim_acesso)
            VALUES ($1, $2, 'aprovado', '6m', NOW(), NOW() + INTERVAL '6 months')
            ON CONFLICT DO NOTHING
          `, [user.id, cursoId]);
        }
        console.log(`   → Acesso BONUS concedido a 3 cursos Compras (5, 8, 9)`);
      }
      
      console.log(`   → Acesso EAD concedido a 6 cursos (${cursosEAD.join(', ')})`);
    }
    
    await client.query('COMMIT');
    
    // ============================================================
    // SUMMARY
    // ============================================================
    console.log('\n========== RESUMO FINAL ==========');
    console.log('\n🏢 EMPRESA:');
    console.log(`   Nome: ${empresa.nome}`);
    console.log(`   Email: ${empresa.email}`);
    console.log(`   Senha: ${empresaSenha}`);
    console.log(`   ID: ${empresa.id}`);
    
    console.log('\n👥 ALUNOS (19 criados):');
    createdAlunos.forEach((a, i) => {
      console.log(`\n   ${i+1}. ${a.username}`);
      console.log(`      Email: ${a.email}`);
      console.log(`      Senha: ${a.senhaOriginal}`);
      console.log(`      ID: ${a.id}`);
      console.log(`      Cursos: 6 EAD ${a.isBonus ? '+ 3 Compras Bonus' : ''}`);
    });
    
    console.log('\n📋 CREDENCIAIS PARA ENTREGA:');
    console.log('┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ EMPRESA: Gabriel - GRUPO ZAMBIANCO                                 │');
    console.log('│ Login: gabriel@grupozambianco.com.br                               │');
    console.log('│ Senha: Zambianco2620##                                             │');
    console.log('├─────────────────────────────────────────────────────────────────────┤');
    console.log('│ ALUNOS (19) - Todos com senha: Zambianco2620##                    │');
    createdAlunos.forEach((a, i) => {
      const bonus = a.isBonus ? ' [BONUS COMPRAS]' : '';
      console.log(`│ ${String(i+1).padStart(2,'0')}. ${a.username.padEnd(20)} │ ${a.email.padEnd(35)} │${bonus.padEnd(18)}│`);
    });
    console.log('└─────────────────────────────────────────────────────────────────────┘');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Erro:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

main();