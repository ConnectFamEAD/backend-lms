const nodemailer = require('nodemailer');

// Configuração do email (mesma do server.js)
const transporter = nodemailer.createTransport({
    host: 'smtp.office365.com',
    port: 587,
    secure: false,
    auth: {
        user: 'suporte.fmatch@outlook.com',
        pass: '@Desenho1977##',
    },
});

// ============================================================
// EXEMPLO DE EMAIL PARA UM ALUNO (José Baron - Líder com Bônus)
// ============================================================

const alunoExemplo = {
    nome: 'Jose Pedro Baron Junior',
    email: 'jose.baron@grupozambianco.com.br',
    username: 'jose.baron',
    senha: 'KnbR2RRaQMS@',
    cargo: 'Líder Almoxarifado',
    empresa: 'Gabriel - GRUPO ZAMBIANCO',
    cursos: [
        // EAD (6)
        { id: 1, nome: 'Gestão de Inventários Estoques MRO', categoria: 'EAD', carga: '1 Hora' },
        { id: 2, nome: 'Planejamento Estratégico Estoques MRO - MRP', categoria: 'EAD', carga: '1 Hora' },
        { id: 3, nome: 'Obsolescência Estoques', categoria: 'EAD', carga: '1 Hora' },
        { id: 4, nome: 'Processo Recebimento Físico de Materiais', categoria: 'EAD', carga: '1 Hora' },
        { id: 11, nome: 'Gestão de Estoques em Trânsito', categoria: 'EAD', carga: '1 Hora' },
        { id: 14, nome: 'Acuracidade de Estoques', categoria: 'EAD', carga: '1 Hora' },
        // Bônus Compras (3)
        { id: 5, nome: 'Contratos Fornecimentos Impacto nos Estoques', categoria: 'Bônus Compras', carga: '1 Hora' },
        { id: 8, nome: 'IQF Qualificação Técnica Estrutural Fornecedores', categoria: 'Bônus Compras', carga: '1 Hora' },
        { id: 9, nome: 'Follow Up Operacional de Compras', categoria: 'Bônus Compras', carga: '1 Hora' },
    ]
};

function gerarEmailHTML(aluno) {
    const cursosEAD = aluno.cursos.filter(c => c.categoria === 'EAD');
    const cursosBonus = aluno.cursos.filter(c => c.categoria === 'Bônus Compras');
    const temBonus = cursosBonus.length > 0;
    const totalCursos = aluno.cursos.length;

    return `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Seus Cursos na Plataforma FMATCH</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f7fa; line-height: 1.6;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        
        <!-- Header -->
        <div style="background: linear-gradient(135deg, #0f1d2e 0%, #15283e 100%); border-radius: 12px 12px 0 0; padding: 30px 20px; text-align: center;">
            <div style="background: rgba(255,255,255,0.1); display: inline-block; padding: 12px 24px; border-radius: 50px; margin-bottom: 16px;">
                <span style="color: #ff7f00; font-weight: 700; font-size: 14px; letter-spacing: 1px;">FMATCH</span>
            </div>
            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 700;">Seus Cursos Foram Liberados! 🎓</h1>
            <p style="color: rgba(255,255,255,0.8); margin: 8px 0 0; font-size: 15px;">Plataforma FMATCH - Capacitação Corporativa</p>
        </div>

        <!-- Card Principal -->
        <div style="background: #ffffff; border-radius: 0 0 12px 12px; padding: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);">
            
            <!-- Saudação -->
            <div style="margin-bottom: 24px;">
                <p style="font-size: 16px; color: #334155; margin: 0 0 8px;">Olá, <strong style="color: #0f1d2e;">${aluno.nome}</strong>!</p>
                <p style="font-size: 14px; color: #64748b; margin: 0;">Seus acessos na plataforma FMATCH foram liberados pela <strong>${aluno.empresa}</strong>.</p>
            </div>

            <!-- Credenciais Box -->
            <div style="background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; margin-bottom: 24px;">
                <h2 style="color: #0f1d2e; margin: 0 0 16px; font-size: 16px; font-weight: 600;">🔐 Suas Credenciais de Acesso</h2>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-size: 13px; font-weight: 500; width: 100px;">🔗 Link da Plataforma</td>
                        <td style="padding: 8px 0; font-family: monospace; font-size: 13px; color: #0f1d2e; word-break: break-all;"><a href="https://fmatchcursos.com.br/login" style="color: #ff7f00; text-decoration: none;">fmatchcursos.com.br/login</a></td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-size: 13px; font-weight: 500;">👤 Usuário (Email)</td>
                        <td style="padding: 8px 0; font-family: monospace; font-size: 13px; color: #0f1d2e; font-weight: 600;">${aluno.email}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-size: 13px; font-weight: 500;">🔐 Senha Temporária</td>
                        <td style="padding: 8px 0; font-family: monospace; font-size: 14px; color: #dc2626; font-weight: 700; background: #fef2f2; padding: 4px 8px; border-radius: 4px;">${aluno.senha}</td>
                    </tr>
                </table>
                <p style="margin: 16px 0 0; padding-top: 12px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #dc2626; font-weight: 500;">⚠️ <strong>Importante:</strong> Altere sua senha no primeiro acesso (Menu → Perfil → Alterar Senha)</p>
            </div>

            <!-- Resumo dos Cursos -->
            <div style="margin-bottom: 24px;">
                <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;">
                    <div style="background: #e0f2fe; border: 1px solid #bae6fd; border-radius: 8px; padding: 12px 16px; flex: 1; min-width: 140px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: #0369a1;">${cursosEAD.length}</div>
                        <div style="font-size: 12px; color: #0369a1; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;">Cursos EAD</div>
                    </div>
                    ${temBonus ? `
                    <div style="background: #fef3c7; border: 1px solid #fde68a; border-radius: 8px; padding: 12px 16px; flex: 1; min-width: 140px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: #92400e;">${cursosBonus.length}</div>
                        <div style="font-size: 12px; color: #92400e; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;">Bônus Compras</div>
                    </div>
                    ` : ''}
                    <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 12px 16px; flex: 1; min-width: 140px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: #166534;">${totalCursos}</div>
                        <div style="font-size: 12px; color: #166534; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;">Total Liberado</div>
                    </div>
                </div>
                <p style="font-size: 13px; color: #64748b; margin: 0;">
                    ${temBonus ? 
                        `✅ <strong>${cursosEAD.length} cursos EAD</strong> (obrigatórios para todos) + ⭐ <strong>${cursosBonus.length} cursos Bônus Compras</strong> (líderes)` :
                        `✅ <strong>${cursosEAD.length} cursos EAD</strong> (grade padrão)`
                    }
                    <br><span style="color: #94a3b8;">Período de acesso: 6 meses a partir do primeiro login | Certificado automático ao concluir</span>
                </p>
            </div>

            <!-- Lista de Cursos EAD -->
            <div style="margin-bottom: 20px;">
                <h3 style="color: #0f1d2e; font-size: 15px; font-weight: 600; margin: 0 0 12px; display: flex; align-items: center; gap: 8px;">
                    <span style="background: #e0f2fe; color: #0369a1; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase;">EAD</span>
                    Cursos Principais (${cursosEAD.length})
                </h3>
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">
                    ${cursosEAD.map((curso, i) => `
                    <div style="display: flex; align-items: center; padding: 12px 16px; border-bottom: ${i < cursosEAD.length - 1 ? '1px solid #e2e8f0' : 'none'}; ${i % 2 === 0 ? 'background: #ffffff;' : 'background: #f8fafc;'}">
                        <span style="width: 28px; height: 28px; background: #e0f2fe; color: #0369a1; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; margin-right: 12px; flex-shrink: 0;">${i + 1}</span>
                        <div style="flex: 1;">
                            <div style="font-size: 14px; font-weight: 500; color: #0f1d2e;">${curso.nome}</div>
                            <div style="font-size: 11px; color: #94a3b8;">${curso.carga} | ${curso.categoria}</div>
                        </div>
                        <span style="background: #22c55e; color: white; font-size: 10px; font-weight: 600; padding: 3px 8px; border-radius: 4px;">LIBERADO</span>
                    </div>
                    `).join('')}
                </div>
            </div>

            ${temBonus ? `
            <!-- Lista de Cursos Bônus -->
            <div style="margin-bottom: 20px;">
                <h3 style="color: #0f1d2e; font-size: 15px; font-weight: 600; margin: 0 0 12px; display: flex; align-items: center; gap: 8px;">
                    <span style="background: #fef3c7; color: #92400e; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase;">★ Bônus</span>
                    Cursos Compras & Suprimentos (${cursosBonus.length}) - Exclusivo para Líderes
                </h3>
                <div style="background: #fefce8; border: 1px solid #fde68a; border-radius: 8px; overflow: hidden;">
                    ${cursosBonus.map((curso, i) => `
                    <div style="display: flex; align-items: center; padding: 12px 16px; border-bottom: ${i < cursosBonus.length - 1 ? '1px solid #fde68a' : 'none'}; ${i % 2 === 0 ? 'background: #fffbeb;' : 'background: #fefce8;'}">
                        <span style="width: 28px; height: 28px; background: #fef3c7; color: #92400e; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; margin-right: 12px; flex-shrink: 0;">★</span>
                        <div style="flex: 1;">
                            <div style="font-size: 14px; font-weight: 500; color: #0f1d2e;">${curso.nome}</div>
                            <div style="font-size: 11px; color: #94a3b8;">${curso.carga} | ${curso.categoria}</div>
                        </div>
                        <span style="background: #f59e0b; color: white; font-size: 10px; font-weight: 600; padding: 3px 8px; border-radius: 4px;">BÔNUS</span>
                    </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}

            <!-- Passos para Primeiro Acesso -->
            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 10px; padding: 20px; margin-bottom: 24px;">
                <h3 style="color: #166534; font-size: 15px; font-weight: 600; margin: 0 0 16px; display: flex; align-items: center; gap: 8px;">🚀 Primeiro Acesso - Passo a Passo</h3>
                <ol style="margin: 0; padding-left: 20px; color: #166534; font-size: 13px; line-height: 2;">
                    <li style="margin-bottom: 8px;">Acesse <a href="https://fmatchcursos.com.br/login" style="color: #16a34a; text-decoration: none;"><strong>fmatchcursos.com.br/login</strong></a></li>
                    <li style="margin-bottom: 8px;">Insira seu <strong>email</strong> e a <strong>senha temporária</strong> acima</li>
                    <li style="margin-bottom: 8px;">Clique em <strong>Entrar</strong> → Vá em <strong>Perfil → Alterar Senha</strong></li>
                    <li style="margin-bottom: 8px;">Crie uma <strong>nova senha pessoal</strong> (mín. 8 chars, maiúscula, número, especial)</li>
                    <li style="margin-bottom: 8px;">Acesse <strong>Meus Cursos</strong> ou <strong>Catálogo</strong> e comece a estudar!</li>
                </ol>
            </div>

            <!-- Informações Adicionais -->
            <div style="border-top: 1px solid #e2e8f0; padding-top: 20px;">
                <h3 style="color: #0f1d2e; font-size: 14px; font-weight: 600; margin: 0 0 12px;">📋 Informações Importantes</h3>
                <ul style="margin: 0; padding-left: 18px; color: #475569; font-size: 13px; line-height: 1.8;">
                    <li><strong>Período:</strong> 6 meses contados do primeiro acesso a cada módulo</li>
                    <li><strong>Certificado:</strong> Emitido automaticamente ao concluir 100% + avaliação</li>
                    <li><strong>Apresentação Presencial:</strong> Sr. Amadeu Rocha apresentará as 16 ITs (data a confirmar)</li>
                    <li><strong>Suporte:</strong> Felipe (fg@connectconsultoria.com.br) | Matheus (miguel.matheus@hotmail.com)</li>
                </ul>
            </div>
        </div>

        <!-- Footer -->
        <div style="text-align: center; padding: 20px; color: #94a3b8; font-size: 12px;">
            <p style="margin: 0 0 8px;">Este email foi enviado automaticamente pela Plataforma FMATCH</p>
            <p style="margin: 0;">Connect Consultoria | FMATCH Tecnologia LTDA</p>
            <p style="margin: 8px 0 0;">CNPJ: 52.622.018/0001-29 | Lençóis Paulista - SP</p>
        </div>

    </div>
</body>
</html>
    `;
}

// Texto puro (fallback)
function gerarEmailTexto(aluno) {
    const cursosEAD = aluno.cursos.filter(c => c.categoria === 'EAD');
    const cursosBonus = aluno.cursos.filter(c => c.categoria === 'Bônus Compras');
    const temBonus = cursosBonus.length > 0;

    return `
==========================================
🎓 FMATCH - Seus Cursos Foram Liberados!
==========================================

Olá, ${aluno.nome}!

Seus acessos na plataforma FMATCH foram liberados pela ${aluno.empresa}.

------------------------------------------
🔐 SUAS CREDENCIAIS
------------------------------------------
🔗 Plataforma: https://fmatchcursos.com.br/login
👤 Usuário: ${aluno.email}
🔐 Senha: ${aluno.senha}

⚠️ ALTERE SUA SENHA NO PRIMEIRO ACESSO (Perfil → Alterar Senha)

------------------------------------------
📚 SEUS CURSOS LIBERADOS (${aluno.cursos.length} total)
------------------------------------------

✅ CURSOS EAD (${cursosEAD.length} - obrigatórios para todos):
${cursosEAD.map((c, i) => `${i+1}. ${c.nome} (${c.carga})`).join('\n')}

${temBonus ? `
⭐ BÔNUS COMPRAS (${cursosBonus.length} - exclusivo para líderes):
${cursosBonus.map((c, i) => `${i+1}. ${c.nome} (${c.carga})`).join('\n')}
` : ''}

Total: ${aluno.cursos.length} cursos | Período: 6 meses | Certificado automático

------------------------------------------
🚀 PRIMEIRO ACESSO
------------------------------------------
1. Acesse https://fmatchcursos.com.br/login
2. Insira seu email e a senha temporária acima
3. Perfil → Alterar Senha → Crie sua senha pessoal
4. Acesse "Meus Cursos" e comece a estudar!

------------------------------------------
📋 INFORMAÇÕES IMPORTANTES
------------------------------------------
• Período: 6 meses a partir do 1º login
• Certificado: Automático ao concluir 100% + avaliação
• Apresentação Presencial: Sr. Amadeu Rocha (16 ITs) - data a confirmar
• Suporte: Felipe (fg@connectconsultoria.com.br) | Matheus (miguel.matheus@hotmail.com)

==========================================
Enviado pela Plataforma FMATCH
Connect Consultoria | FMATCH Tecnologia LTDA
CNPJ: 52.622.018/0001-29 | Lençóis Paulista - SP
==========================================
    `;
}

// Mostrar preview no console
console.log('='.repeat(60));
console.log('📧 PREVIEW DO EMAIL PARA:', alunoExemplo.nome);
console.log('Email:', alunoExemplo.email);
console.log('='.repeat(60));
console.log('\n--- VERSÃO TEXTO (fallback) ---\n');
console.log(gerarEmailTexto(alunoExemplo));

console.log('\n\n--- VERSÃO HTML (será renderizada no cliente de email) ---\n');
console.log('[HTML gerado - visualizar no navegador ou cliente de email]');

// Salvar HTML em arquivo para visualização
const fs = require('fs');
const htmlCompleto = gerarEmailHTML(alunoExemplo);
fs.writeFileSync('/home/mmstrok/projetos/freelance-dev-business/backend-lms-main/preview-email-aluno.html', htmlCompleto);
console.log('\n✅ HTML salvo em: preview-email-aluno.html (abra no navegador para ver o layout)');

// Opção de enviar email de teste real
const ENVIAR_TESTE = false; // Mude para true para enviar email real

if (ENVIAR_TESTE) {
    const mailOptions = {
        from: 'suporte.fmatch@outlook.com',
        to: alunoExemplo.email, // ou seu email de teste
        subject: '🎓 FMATCH - Seus Cursos Foram Liberados! | GRUPO ZAMBIANCO',
        text: gerarEmailTexto(alunoExemplo),
        html: htmlCompleto
    };

    transporter.sendMail(mailOptions)
        .then(info => console.log('✅ Email de teste enviado:', info.messageId))
        .catch(err => console.error('❌ Erro ao enviar:', err));
}