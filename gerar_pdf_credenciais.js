const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

const outputPath = path.join(__dirname, 'credenciais-grupo-zambianco.pdf');

// Course details
const cursos = {
  1: { nome: 'Gestão de Inventários Estoques MRO', categoria: 'EAD', carga: '1 Hora' },
  2: { nome: 'Planejamento Estratégico Estoques MRO - MRP', categoria: 'EAD', carga: '1 Hora' },
  3: { nome: 'Obsolescência Estoques', categoria: 'EAD', carga: '1 Hora' },
  4: { nome: 'Processo Recebimento Físico de Materiais', categoria: 'EAD', carga: '1 Hora' },
  5: { nome: 'Contratos Fornecimentos Impacto nos Estoques', categoria: 'Compras (Bônus)', carga: '1 Hora' },
  6: { nome: 'Governança Cadastro Materiais e Fornecedores', categoria: 'EAD', carga: '1 Hora' },
  8: { nome: 'IQF Qualificação Técnica Estrutural Fornecedores', categoria: 'Compras (Bônus)', carga: '1 Hora' },
  9: { nome: 'Follow Up Operacional de Compras', categoria: 'Compras (Bônus)', carga: '1 Hora' },
  11: { nome: 'Gestão de Estoques em Trânsito', categoria: 'EAD', carga: '1 Hora' },
  14: { nome: 'Acuracidade de Estoques', categoria: 'EAD', carga: '1 Hora' }
};

const cursosEAD = [1, 2, 3, 4, 11, 14];
const cursosCompras = [5, 8, 9];

const alunos = [
  { username: 'jose.baron', nome: 'Jose Pedro Baron Junior', email: 'jose.baron@grupozambianco.com.br', cargo: 'Líder Almoxarifado', senha: 'KnbR2RRaQMS@', bonus: true },
  { username: 'marcos.santos', nome: 'Marcos Adriano Magalhães dos Santos', email: 'marcostenebra.2@gmail.com', cargo: 'Almoxarife Júnior', senha: 'Snt8CGxqr8!6', bonus: false },
  { username: 'alexsandro.chaves', nome: 'Alexsandro Chaves', email: 'chavesalexsandro349@gmail.com', cargo: 'Almoxarife Júnior', senha: 'Y#gWyWz5K7dn', bonus: false },
  { username: 'gabriel.leite', nome: 'Gabriel da Silva Leite', email: 'gabrielfodex2004@gmail.com', cargo: 'Almoxarife Júnior', senha: 'GvvyykMhcRP@', bonus: false },
  { username: 'jefferson.santos', nome: 'Jefferson Silva dos Santos', email: 'jeffersilsantos@gmail.com', cargo: 'Almoxarife Júnior', senha: 'HgVjaEP6tL8@', bonus: false },
  { username: 'matheus.oliveira', nome: 'Matheus Campos Conde de Oliveira', email: 'matheuscamposs7@gmail.com', cargo: 'Auxiliar de Almoxarifado', senha: 'CqYj#CzMnWQ2', bonus: false },
  { username: 'otavio.silva', nome: 'Otavio Jacson Alfredo da Silva', email: 'otavio17jacson19@gmail.com', cargo: 'Auxiliar de Almoxarifado', senha: 'shDCnSx2tpN@', bonus: false },
  { username: 'patrick.ribeiro', nome: 'Patrick Teodoro Teles Ribeiro', email: 'patrickteles2016@gmail.com', cargo: 'Almoxarife Sênior', senha: '#S#KGsU$XR7C', bonus: true },
  { username: 'ronald.santos', nome: 'Ronald Pedro Ferreira dos Santos', email: 'ronaldsantos040903@gmail.com', cargo: 'Auxiliar de Almoxarifado', senha: 'wS5EEypG#cQT', bonus: false },
  { username: 'ryan.silva', nome: 'Ryan Amario da Silva', email: 'ryanamario429@gmail.com', cargo: 'Auxiliar de Escritório', senha: '4b6wUKf6wmM@', bonus: false },
  { username: 'abel.junior', nome: 'Abel Antonio da Silva Junior', email: 'junioramariodasilva@gmail.com', cargo: 'Auxiliar de Escritório', senha: 'bp!F#GxUqb7m', bonus: false },
  { username: 'joao.boni', nome: 'Joao Paulo Milani Boni', email: 'joaopaulomilaniboni@gmail.com', cargo: 'Auxiliar de Escritório', senha: 'MZ#H@k!QdxL2', bonus: false },
  { username: 'robson.augusto', nome: 'Robson Aparecido Augusto', email: 'augustorobson621@gmail.com', cargo: 'Líder de Almoxarifado', senha: 'gXmhyMXXSj3@', bonus: true },
  { username: 'willian.goncalves', nome: 'Willian Paris Gonçalves', email: 'willianparis834@gmail.com', cargo: 'Almoxarife Júnior', senha: 'En!!cmwKF!3W', bonus: false },
  { username: 'ruan.souza', nome: 'Ruan Pablo Nascimento de Souza', email: 'ruanpablons.souza@gmail.com', cargo: 'Menor Aprendiz', senha: 'Z89ib5CBtjd@', bonus: false },
  { username: 'iury.silva', nome: 'Iury Augusto Silva', email: 'augustoiury969@gmail.com', cargo: 'Almoxarife Pleno', senha: 'mXQB4qgHh2!B', bonus: false },
  { username: 'barbara.lima', nome: 'Barbara Diomar Silva de Lima', email: 'barbaradiomar@hotmail.com', cargo: 'Almoxarife Júnior', senha: 'jMP4pRTcHTp@', bonus: false },
  { username: 'steffany.rocha', nome: 'Steffany Gabrielle Silveira Rocha', email: 'steffanygabrielle47@gmail.com', cargo: 'Almoxarife Júnior', senha: 'YHjPw8yg$quW', bonus: false },
  { username: 'gelton.pereira', nome: 'Gelton da Silva Pereira', email: 'gelton.silvasp@gmail.com', cargo: 'Almoxarife Júnior', senha: 'XHUiA!qeXww2', bonus: false }
];

const empresa = {
  nome: 'Gabriel - GRUPO ZAMBIANCO',
  email: 'gabriel@grupozambianco.com.br',
  senha: 'Zambianco2620##',
  responsavel: 'Gabriel',
  cnpj: '00.000.000/0001-00',
  endereco: 'Rodovia SP-304, Km 150 - Lençóis Paulista/SP',
  telefone: '(14) 99999-9999'
};

const doc = new PDFDocument({ 
  margin: 40,
  size: 'A4',
  info: {
    Title: 'Credenciais de Acesso - GRUPO ZAMBIANCO',
    Author: 'FMATCH / Connect Consultoria',
    Subject: 'Credenciais de Acesso à Plataforma EAD',
    Keywords: 'FMATCH, EAD, GRUPO ZAMBIANCO, Credenciais'
  }
});

doc.pipe(fs.createWriteStream(outputPath));

// Colors
const primaryColor = '#0f1d2e';
const secondaryColor = '#15283e';
const accentColor = '#ff7f00';
const lightGray = '#f8fafc';
const mediumGray = '#e2e8f0';
const darkGray = '#334155';
const textColor = '#1e293b';
const successColor = '#10b981';
const warningColor = '#f59e0b';

// Helper functions
function drawHeader() {
  // Header background
  doc.rect(0, 0, doc.page.width, 100).fill(primaryColor);
  
  // Logo area
  doc.fontSize(28).font('Helvetica-Bold').fillColor('#ffffff').text('FMATCH', 50, 20);
  doc.fontSize(10).font('Helvetica').fillColor('#ff7f00').text('PLATAFORMA EAD PROFISSIONAL', 50, 52);
  
  // Title
  doc.fontSize(18).font('Helvetica-Bold').fillColor('#ffffff').text('CREDENCIAIS DE ACESSO', doc.page.width - 50, 25, { align: 'right', width: 250 });
  doc.fontSize(12).font('Helvetica').fillColor('#ff7f00').text('GRUPO ZAMBIANCO', doc.page.width - 50, 50, { align: 'right', width: 250 });
  
  doc.moveDown(6);
}

function drawSectionTitle(title, icon = '') {
  doc.moveDown(1);
  doc.fontSize(16).font('Helvetica-Bold').fillColor(primaryColor).text(`${icon} ${title}`);
  doc.moveTo(doc.x, doc.y + 4).lineTo(doc.x + 100, doc.y + 4).strokeColor(accentColor).lineWidth(2).stroke();
  doc.moveDown(0.5);
}

function drawInfoRow(label, value, indent = 50) {
  const x = indent;
  const y = doc.y;
  doc.fontSize(10).font('Helvetica-Bold').fillColor(darkGray).text(label, x, y, { width: 140 });
  doc.fontSize(10).font('Helvetica').fillColor(textColor).text(value, x + 140, y, { width: doc.page.width - x - 180 });
  doc.moveDown(0.4);
}

function drawTable(header, rows, colWidths, startY = null) {
  if (startY) doc.y = startY;
  
  const tableTop = doc.y;
  const rowHeight = 24;
  const headerHeight = 28;
  let x = 50;
  
  // Header
  doc.rect(x, tableTop, doc.page.width - 100, headerHeight).fill(primaryColor);
  doc.fontSize(9).font('Helvetica-Bold').fillColor('#ffffff');
  
  header.forEach((h, i) => {
    doc.text(h, x + 5, tableTop + 8, { width: colWidths[i] - 10, align: i === 0 ? 'center' : 'left' });
    x += colWidths[i];
  });
  
  // Rows
  let currentY = tableTop + headerHeight;
  rows.forEach((row, rowIndex) => {
    if (currentY + rowHeight > doc.page.height - 60) {
      doc.addPage();
      currentY = 50;
      // Redraw header on new page
      x = 50;
      doc.rect(x, currentY, doc.page.width - 100, headerHeight).fill(primaryColor);
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#ffffff');
      header.forEach((h, i) => {
        doc.text(h, x + 5, currentY + 8, { width: colWidths[i] - 10, align: i === 0 ? 'center' : 'left' });
        x += colWidths[i];
      });
      currentY += headerHeight;
    }
    
    const isEven = rowIndex % 2 === 0;
    doc.rect(50, currentY, doc.page.width - 100, rowHeight).fill(isEven ? lightGray : '#ffffff');
    
    x = 50;
    doc.fontSize(8).font('Helvetica').fillColor(textColor);
    row.forEach((cell, i) => {
      const align = i === 0 ? 'center' : 'left';
      doc.text(String(cell), x + 5, currentY + 6, { width: colWidths[i] - 10, align });
      x += colWidths[i];
    });
    
    currentY += rowHeight;
  });
  
  doc.y = currentY + 10;
  return doc.y;
}

function drawCourseBadges(courseIds, startX, startY, maxWidth) {
  let x = startX;
  let y = startY;
  const badgeHeight = 20;
  const gap = 6;
  
  courseIds.forEach((id, i) => {
    const curso = cursos[id];
    if (!curso) return;
    
    const text = `${id} - ${curso.nome}`;
    const textWidth = doc.widthOfString(text, { font: 'Helvetica', size: 7 }) + 16;
    
    if (x + textWidth > startX + maxWidth) {
      x = startX;
      y += badgeHeight + gap;
    }
    
    const isBonus = curso.categoria.includes('Bônus');
    doc.rect(x, y, textWidth, badgeHeight).fill(isBonus ? '#fef3c7' : '#e0f2fe');
    doc.rect(x, y, textWidth, badgeHeight).stroke(isBonus ? '#f59e0b' : '#3b82f6');
    doc.fontSize(7).font('Helvetica-Bold').fillColor(isBonus ? '#92400e' : '#1e40af').text(text, x + 8, y + 5);
    
    x += textWidth + gap;
  });
  
  return y + badgeHeight + 10;
}

// ============================================================
// PAGE 1: COVER / COMPANY INFO
// ============================================================
drawHeader();

doc.moveDown(2);
drawSectionTitle('DADOS DA EMPRESA', '🏢');

drawInfoRow('Empresa:', empresa.nome);
drawInfoRow('Responsável:', empresa.responsavel);
drawInfoRow('CNPJ:', empresa.cnpj);
drawInfoRow('Endereço:', empresa.endereco);
drawInfoRow('Telefone:', empresa.telefone);
doc.moveDown(0.5);

// Credentials box
doc.rect(50, doc.y, doc.page.width - 100, 70).fill(lightGray).stroke(accentColor).lineWidth(1).stroke();
doc.fontSize(12).font('Helvetica-Bold').fillColor(primaryColor).text('CREDENCIAIS DE ACESSO - EMPRESA', 70, doc.y + 10);
drawInfoRow('Login (Email):', empresa.email, 70);
drawInfoRow('Senha:', empresa.senha, 70);

doc.moveDown(4);
drawSectionTitle('INFORMAÇÕES DO CONTRATO', '📋');

const contractInfo = [
  ['Item', 'Detalhes'],
  ['Proposta', 'PROP-2026-ZAMB01-V7'],
  ['Data', '25 de Agosto de 2026'],
  ['Modelo', 'Capacitação Integrada + Apresentação Executiva'],
  ['Investimento Total', 'R$ 17.000,00 (5 parcelas de R$ 3.400,00)'],
  ['Período de Acesso', 'Setembro/2026 a Janeiro/2027'],
  ['Total de Colaboradores', '19 usuários'],
  ['Total de Cursos EAD', '6 módulos (6 horas)'],
  ['Cursos Bônus Compras', '3 módulos (3 horas) - para 3 líderes'],
  ['Apresentação Presencial', 'Sr. Amadeu Rocha - 16 ITs desenvolvidas']
];

drawTable(contractInfo[0], contractInfo.slice(1), [150, 350]);

doc.moveDown(2);
drawSectionTitle('GRADE CURRICULAR - MÓDULOS EAD (6 MÓDULOS)', '📚');

const eadRows = cursosEAD.map((id, i) => [String(i+1), cursos[id].nome, cursos[id].carga, 'Todos os 19 colaboradores']);
drawTable(['#', 'Módulo', 'Carga Horária', 'Público'], eadRows, [40, 350, 80, 130]);

doc.moveDown(1);
drawSectionTitle('CURSOS BÔNUS - COMPRAS & SUPRIMENTOS (3 MÓDULOS)', '🎁');

const bonusRows = cursosCompras.map((id, i) => [String(i+1), cursos[id].nome, cursos[id].carga, '3 líderes selecionados']);
drawTable(['#', 'Módulo', 'Carga Horária', 'Público'], bonusRows, [40, 350, 80, 130]);

// ============================================================
// PAGE 2: ALUNOS - CREDENCIAIS INDIVIDUAIS
// ============================================================
doc.addPage();
drawHeader();

drawSectionTitle('CREDENCIAIS INDIVIDUAIS DOS ALUNOS (19 USUÁRIOS)', '👥');
doc.fontSize(10).fillColor(darkGray).text('⚠️ LGPD COMPLIANT - Senhas únicas por usuário | Entregar individualmente via canal seguro', { align: 'center' });
doc.moveDown(1);

const credHeader = ['#', 'Usuário', 'Nome Completo', 'E-mail', 'Cargo', 'Senha Individual'];
const credWidths = [35, 70, 130, 140, 100, 95];
const credRows = alunos.map((a, i) => [
  String(i+1).padStart(2, '0'),
  a.username,
  a.nome,
  a.email,
  a.cargo,
  a.senha
]);

drawTable(credHeader, credRows, credWidths);

// ============================================================
// PAGE 3: MATRIZ DE ACESSO - CURSOS POR ALUNO
// ============================================================
doc.addPage();
drawHeader();

drawSectionTitle('MATRIZ DE ACESSO - CURSOS LIBERADOS POR ALUNO', '📊');
doc.fontSize(10).fillColor(darkGray).text('Legenda: ✓ = Acesso liberado | ★ = Curso Bônus Compras (apenas 3 líderes) | Período: 6 meses', { align: 'center' });
doc.moveDown(1);

// Matrix table
const matrixHeader = ['#', 'Aluno', 'Cargo'];
cursosEAD.forEach(id => matrixHeader.push(cursos[id].nome.substring(0, 22)));
cursosCompras.forEach(id => matrixHeader.push(cursos[id].nome.substring(0, 22)));

const matrixWidths = [35, 120, 100];
cursosEAD.forEach(() => matrixWidths.push(70));
cursosCompras.forEach(() => matrixWidths.push(70));

const matrixRows = alunos.map((a, i) => {
  const row = [
    String(i+1).padStart(2, '0'),
    a.nome,
    a.cargo
  ];
  
  // EAD courses
  cursosEAD.forEach(id => {
    row.push('✓');
  });
  
  // Bonus courses
  cursosCompras.forEach(id => {
    row.push(a.bonus ? '★' : '—');
  });
  
  return row;
});

drawTable(matrixHeader, matrixRows, matrixWidths);

doc.moveDown(2);
// Summary box
doc.rect(50, doc.y, doc.page.width - 100, 80).fill('#f0fdf4').stroke(successColor).lineWidth(1).stroke();
doc.fontSize(12).font('Helvetica-Bold').fillColor('#166534').text('RESUMO DE ACESSOS', 70, doc.y + 10);
doc.fontSize(10).font('Helvetica').fillColor('#166534').text('• 19 colaboradores com acesso a 6 cursos EAD (6h total)', 70, doc.y + 35);
doc.fontSize(10).font('Helvetica').fillColor('#166534').text('• 3 líderes com acesso adicional a 3 cursos Compras Bônus (3h total)', 70, doc.y + 50);
doc.fontSize(10).font('Helvetica').fillColor('#166534').text('• Período de acesso: 6 meses a partir do primeiro login', 70, doc.y + 65);
doc.fontSize(10).font('Helvetica').fillColor('#166534').text('• Certificado válido em todos os cursos ao concluir', 70, doc.y + 80);

doc.y += 100;

// ============================================================
// PAGE 4: DETALHAMENTO POR ALUNO (CARDS INDIVIDUAIS)
// ============================================================
alunos.forEach((aluno, index) => {
  if (index % 4 === 0) {
    if (index > 0) doc.addPage();
    drawHeader();
  }
  
  const cardY = doc.y;
  const cardHeight = 160;
  const cardX = 50;
  const cardWidth = doc.page.width - 100;
  
  // Card background
  doc.rect(cardX, cardY, cardWidth, cardHeight).fill('#ffffff').stroke(mediumGray).lineWidth(0.5).stroke();
  
  // Left side - Info
  let infoX = cardX + 20;
  let infoY = cardY + 15;
  
  // Header row
  doc.fontSize(11).font('Helvetica-Bold').fillColor(primaryColor).text(`${String(index+1).padStart(2,'0')}. ${aluno.nome}`, infoX, infoY);
  doc.fontSize(9).font('Helvetica').fillColor(accentColor).text(aluno.cargo, infoX + 200, infoY);
  
  infoY += 22;
  doc.fontSize(9).font('Helvetica').fillColor(darkGray).text(`Usuário: ${aluno.username}`, infoX, infoY);
  infoY += 14;
  doc.fontSize(9).font('Helvetica').fillColor(darkGray).text(`E-mail: ${aluno.email}`, infoX, infoY);
  infoY += 14;
  
  // Password box
  doc.rect(infoX, infoY, 220, 30).fill(lightGray).stroke(accentColor).lineWidth(1).stroke();
  doc.fontSize(9).font('Helvetica-Bold').fillColor(darkGray).text('SENHA INDIVIDUAL:', infoX + 5, infoY + 3);
  doc.fontSize(11).font('Helvetica-Bold').fillColor(primaryColor).font('Courier').text(aluno.senha, infoX + 5, infoY + 15);
  
  infoY += 40;
  doc.fontSize(9).font('Helvetica-Bold').fillColor(darkGray).text('Cursos Liberados:', infoX, infoY);
  infoY += 16;
  
  // Course badges
  const allCourses = [...cursosEAD];
  if (aluno.bonus) allCourses.push(...cursosCompras);
  
  drawCourseBadges(allCourses, infoX, infoY, 250);
  
  // Bonus indicator
  if (aluno.bonus) {
    doc.fontSize(8).font('Helvetica-Bold').fillColor(warningColor).text('★ INCLUI 3 CURSOS BÔNUS COMPRAS', infoX, infoY + 45);
  }
  
  doc.y = cardY + cardHeight + 10;
});

// ============================================================
// PAGE FINAL: INSTRUÇÕES DE ENTREGA E SEGURANÇA
// ============================================================
doc.addPage();
drawHeader();

drawSectionTitle('INSTRUÇÕES DE ENTREGA E SEGURANÇA (LGPD)', '🔒');

const instrucoes = [
  { titulo: '1. Entrega Individual Obrigatória', texto: 'Cada senha deve ser entregue exclusivamente ao seu titular. Não envie listas com múltiplas senhas por e-mail, WhatsApp em grupo ou planilhas compartilhadas.' },
  { titulo: '2. Canais Seguros Recomendados', texto: '• WhatsApp pessoal (mensagem direta)\n• E-mail pessoal do colaborador\n• Entrega presencial com assinatura de recibo\n• Gestor de senhas corporativo (Bitwarden, 1Password, etc.)' },
  { titulo: '3. Primeiro Acesso', texto: 'Ao primeiro login, oriente o colaborador a:\n  1. Acessar https://fmatchcursos.com.br (ou URL da plataforma)\n  2. Clicar em "Login" e inserir usuário (e-mail) e senha\n  3. Alterar a senha imediatamente (recurso "Esqueci minha senha" ou perfil)\n  4. Confirmar dados de perfil (nome, cargo, telefone)' },
  { titulo: '4. Acesso aos Cursos', texto: '• Após login, ir em "Catálogo de Cursos" ou "Meus Cursos"\n• Cursos EAD (6): Liberados para todos os 19\n• Cursos Compras Bônus (3): Apenas para José, Patrick e Robson\n• Período: 6 meses contados do primeiro acesso ao módulo\n• Certificado emitido automaticamente ao concluir 100% + avaliação' },
  { titulo: '5. Suporte Técnico', texto: 'Em caso de problemas de acesso:\n• Felipe: fg@connectconsultoria.com.br\n• Matheus: miguel.matheus@hotmail.com\n• Plataforma: https://fmatchcursos.com.br' },
  { titulo: '6. Apresentação Presencial', texto: 'Agendada com Sr. Amadeu Rocha para apresentação das 16 ITs (Instruções de Trabalho) desenvolvidas pela Connect Consultoria. Data a confirmar conforme cronograma de parcelas.' }
];

instrucoes.forEach(item => {
  doc.fontSize(12).font('Helvetica-Bold').fillColor(primaryColor).text(item.titulo);
  doc.moveDown(0.3);
  doc.fontSize(10).font('Helvetica').fillColor(textColor).text(item.texto, { indent: 20 });
  doc.moveDown(1);
});

// Footer
doc.moveDown(3);
doc.fontSize(9).font('Helvetica').fillColor('#94a3b8').text(
  'Documento gerado automaticamente pela Plataforma FMATCH | Connect Consultoria\n' +
  'Data: ' + new Date().toLocaleDateString('pt-BR') + ' | Confidencial - Uso interno GRUPO ZAMBIANCO',
  { align: 'center' }
);

doc.end();

console.log(`PDF gerado: ${outputPath}`);