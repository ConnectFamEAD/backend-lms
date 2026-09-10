const { Pool } = require('pg');

const pool = new Pool({
  connectionString: 'postgresql://connectfamead:q0rRK1gyMALN@ep-white-sky-a52j6d6i.us-east-2.aws.neon.tech/lms_mmstrok?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

async function main() {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Get all compras_cursos for Zambianco students
    const compras = await client.query(`
      SELECT cc.*, u.nome as aluno_nome, c.nome as curso_nome
      FROM compras_cursos cc
      JOIN users u ON cc.user_id = u.id
      JOIN cursos c ON cc.curso_id = c.id
      WHERE u.empresa = 'Gabriel - GRUPO ZAMBIANCO'
      AND cc.status = 'aprovado'
      ORDER BY cc.user_id, cc.curso_id
    `);
    
    console.log(`Encontradas ${compras.rows.length} compras para inserir no histórico`);
    
    let inserted = 0;
    
    for (const compra of compras.rows) {
      // Check if historico already exists for this user+curso
      const existing = await client.query(
        'SELECT id FROM historico WHERE user_id = $1 AND curso_id = $2',
        [compra.user_id, compra.curso_id]
      );
      
      if (existing.rows.length > 0) {
        console.log(`  ⏭️  Histórico já existe: user ${compra.user_id} - curso ${compra.curso_id}`);
        continue;
      }
      
      // Insert into historico
      await client.query(`
        INSERT INTO historico (
          user_id, 
          curso_id, 
          compra_id, 
          status, 
          periodo, 
          valor_pago, 
          data_compra, 
          data_aprovacao, 
          status_progresso, 
          data_conclusao, 
          cod_indent
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      `, [
        compra.user_id,
        compra.curso_id,
        compra.id,           // compra_id
        'aprovado',          // status
        compra.periodo,      // periodo (e.g., '6m')
        null,                // valor_pago
        compra.data_compra,  // data_compra
        compra.data_compra,  // data_aprovacao (same as purchase for approved)
        'Não Iniciado',      // status_progresso
        null,                // data_conclusao
        null                 // cod_indent
      ]);
      
      inserted++;
      if (inserted % 20 === 0) {
        console.log(`  Inseridos ${inserted}...`);
      }
    }
    
    await client.query('COMMIT');
    
    console.log(`\n✅ ${inserted} registros inseridos na tabela historico`);
    
    // Verify
    const verify = await client.query(`
      SELECT h.*, u.nome as aluno_nome, c.nome as curso_nome
      FROM historico h
      JOIN users u ON h.user_id = u.id
      JOIN cursos c ON h.curso_id = c.id
      WHERE u.empresa = 'Gabriel - GRUPO ZAMBIANCO'
      ORDER BY u.nome, c.nome
    `);
    
    console.log(`\n📊 Total de registros no histórico para Zambianco: ${verify.rows.length}`);
    
    // Stats per student
    const stats = await client.query(`
      SELECT u.nome, COUNT(h.id) as total_cursos,
             COUNT(CASE WHEN h.status_progresso = 'concluido' THEN 1 END) as concluidos,
             COUNT(CASE WHEN h.status_progresso = 'iniciado' THEN 1 END) as em_andamento,
             COUNT(CASE WHEN h.status_progresso IS NULL OR h.status_progresso = 'Não Iniciado' THEN 1 END) as nao_iniciados
      FROM historico h
      JOIN users u ON h.user_id = u.id
      WHERE u.empresa = 'Gabriel - GRUPO ZAMBIANCO'
      GROUP BY u.id, u.nome
      ORDER BY u.nome
    `);
    
    console.log('\n📈 Por aluno:');
    stats.rows.forEach(s => {
      console.log(`  ${s.nome}: ${s.total_cursos} cursos (${s.concluidos} concluídos, ${s.em_andamento} andamento, ${s.nao_iniciados} não iniciados)`);
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