--
-- PostgreSQL database dump
--

\restrict NnOsueo89e0pQRp7cSSvqLANFOVbO0D3jW6J2Z8Rgn8d25SBS0zrCG8eAXOMfD2

-- Dumped from database version 15.19 (c779254)
-- Dumped by pg_dump version 15.19 (Ubuntu 15.19-1.pgdg22.04+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

ALTER TABLE IF EXISTS ONLY public.users DROP CONSTRAINT IF EXISTS users_empresa_id_fkey;
ALTER TABLE IF EXISTS ONLY public.progresso_cursos DROP CONSTRAINT IF EXISTS progresso_cursos_user_id_fkey;
ALTER TABLE IF EXISTS ONLY public.progresso_cursos DROP CONSTRAINT IF EXISTS progresso_cursos_curso_id_fkey;
ALTER TABLE IF EXISTS ONLY public.historico DROP CONSTRAINT IF EXISTS historico_curso_id_fkey;
ALTER TABLE IF EXISTS ONLY public.compras_cursos DROP CONSTRAINT IF EXISTS compras_cursos_user_id_fkey;
ALTER TABLE IF EXISTS ONLY public.compras_cursos DROP CONSTRAINT IF EXISTS compras_cursos_curso_id_fkey;
ALTER TABLE IF EXISTS ONLY public.avaliacoes DROP CONSTRAINT IF EXISTS avaliacoes_curso_id_fkey;
ALTER TABLE IF EXISTS ONLY public.aulas DROP CONSTRAINT IF EXISTS aulas_curso_id_fkey;
ALTER TABLE IF EXISTS ONLY public.users DROP CONSTRAINT IF EXISTS users_username_key;
ALTER TABLE IF EXISTS ONLY public.users DROP CONSTRAINT IF EXISTS users_pkey;
ALTER TABLE IF EXISTS ONLY public.progresso_cursos DROP CONSTRAINT IF EXISTS unique_user_curso;
ALTER TABLE IF EXISTS ONLY public.historico DROP CONSTRAINT IF EXISTS unique_compra_id;
ALTER TABLE IF EXISTS ONLY public.progresso_cursos DROP CONSTRAINT IF EXISTS progresso_cursos_pkey;
ALTER TABLE IF EXISTS ONLY public.historico DROP CONSTRAINT IF EXISTS historico_pkey;
ALTER TABLE IF EXISTS ONLY public.empresas DROP CONSTRAINT IF EXISTS empresas_pkey;
ALTER TABLE IF EXISTS ONLY public.empresas DROP CONSTRAINT IF EXISTS empresas_email_key;
ALTER TABLE IF EXISTS ONLY public.cursos DROP CONSTRAINT IF EXISTS cursos_pkey;
ALTER TABLE IF EXISTS ONLY public.compras_cursos DROP CONSTRAINT IF EXISTS compras_cursos_pkey;
ALTER TABLE IF EXISTS ONLY public.cnpj_tentativas DROP CONSTRAINT IF EXISTS cnpj_tentativas_pkey;
ALTER TABLE IF EXISTS ONLY public.avaliacoes DROP CONSTRAINT IF EXISTS avaliacoes_pkey;
ALTER TABLE IF EXISTS ONLY public.aulas DROP CONSTRAINT IF EXISTS aulas_pkey;
ALTER TABLE IF EXISTS ONLY public."Courses" DROP CONSTRAINT IF EXISTS "Courses_pkey";
ALTER TABLE IF EXISTS public.users ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.progresso_cursos ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.historico ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.empresas ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.cursos ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.compras_cursos ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.avaliacoes ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.aulas ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public."Courses" ALTER COLUMN id DROP DEFAULT;
DROP SEQUENCE IF EXISTS public.users_id_seq;
DROP TABLE IF EXISTS public.users;
DROP SEQUENCE IF EXISTS public.progresso_cursos_id_seq;
DROP TABLE IF EXISTS public.progresso_cursos;
DROP SEQUENCE IF EXISTS public.historico_id_seq;
DROP TABLE IF EXISTS public.historico;
DROP SEQUENCE IF EXISTS public.empresas_id_seq;
DROP TABLE IF EXISTS public.empresas;
DROP SEQUENCE IF EXISTS public.cursos_id_seq;
DROP TABLE IF EXISTS public.cursos;
DROP SEQUENCE IF EXISTS public.compras_cursos_id_seq;
DROP TABLE IF EXISTS public.compras_cursos;
DROP TABLE IF EXISTS public.cnpj_tentativas;
DROP SEQUENCE IF EXISTS public.avaliacoes_id_seq;
DROP TABLE IF EXISTS public.avaliacoes;
DROP SEQUENCE IF EXISTS public.aulas_id_seq;
DROP TABLE IF EXISTS public.aulas;
DROP SEQUENCE IF EXISTS public."Courses_id_seq";
DROP TABLE IF EXISTS public."Courses";
DROP EXTENSION IF EXISTS unaccent;
DROP EXTENSION IF EXISTS pgcrypto;
--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: unaccent; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS unaccent WITH SCHEMA public;


--
-- Name: EXTENSION unaccent; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION unaccent IS 'text search dictionary that removes accents';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: Courses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public."Courses" (
    id integer NOT NULL,
    "courseName" character varying(255) NOT NULL,
    "thumbnailUrl" character varying(255),
    "lessonName" character varying(255),
    "videoLessonUrl" character varying(255),
    "additionalFilesUrl" character varying(255),
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: Courses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public."Courses_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: Courses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public."Courses_id_seq" OWNED BY public."Courses".id;


--
-- Name: aulas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.aulas (
    id integer NOT NULL,
    curso_id integer,
    nome character varying(255),
    descricao text,
    url_video text
);


--
-- Name: aulas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.aulas_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: aulas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.aulas_id_seq OWNED BY public.aulas.id;


--
-- Name: avaliacoes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.avaliacoes (
    id integer NOT NULL,
    curso_id integer NOT NULL,
    pergunta text NOT NULL,
    opcoes jsonb NOT NULL,
    resposta_correta character(1) NOT NULL
);


--
-- Name: avaliacoes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.avaliacoes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: avaliacoes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.avaliacoes_id_seq OWNED BY public.avaliacoes.id;


--
-- Name: cnpj_tentativas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cnpj_tentativas (
    cnpj character varying(14) NOT NULL,
    tentativas integer DEFAULT 0,
    ultima_tentativa timestamp with time zone
);


--
-- Name: compras_cursos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compras_cursos (
    id integer NOT NULL,
    user_id integer,
    curso_id integer,
    data_compra timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    status character varying(255),
    periodo character varying(255),
    created_at timestamp without time zone DEFAULT now(),
    data_inicio_acesso timestamp without time zone,
    data_fim_acesso timestamp without time zone,
    link_checkout character varying(255)
);


--
-- Name: compras_cursos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compras_cursos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compras_cursos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compras_cursos_id_seq OWNED BY public.compras_cursos.id;


--
-- Name: cursos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cursos (
    id integer NOT NULL,
    nome character varying(255) NOT NULL,
    descricao text,
    thumbnail character varying(255),
    valor_15d numeric(10,2),
    valor_30d numeric(10,2),
    valor_6m numeric(10,2),
    caminho_pdf character varying(255),
    valor_10d numeric
);


--
-- Name: cursos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cursos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cursos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cursos_id_seq OWNED BY public.cursos.id;


--
-- Name: empresas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.empresas (
    id integer NOT NULL,
    nome character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    senha character varying(255) NOT NULL,
    modulos jsonb,
    cnpj character varying(20),
    logradouro character varying(255),
    numero character varying(10),
    complemento character varying(255),
    bairro character varying(255),
    cidade character varying(255),
    estado character varying(255),
    cep character varying(10),
    telefone character varying(20),
    responsavel character varying(255),
    razao_social character varying(255),
    endereco character varying(255)
);


--
-- Name: empresas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.empresas_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: empresas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.empresas_id_seq OWNED BY public.empresas.id;


--
-- Name: historico; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.historico (
    id integer NOT NULL,
    user_id integer NOT NULL,
    curso_id integer NOT NULL,
    compra_id integer NOT NULL,
    status character varying NOT NULL,
    periodo character varying,
    valor_pago numeric,
    data_compra timestamp without time zone NOT NULL,
    data_aprovacao timestamp without time zone,
    status_progresso character varying,
    data_conclusao timestamp without time zone,
    cod_indent character varying(255)
);


--
-- Name: historico_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.historico_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: historico_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.historico_id_seq OWNED BY public.historico.id;


--
-- Name: progresso_cursos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.progresso_cursos (
    id integer NOT NULL,
    user_id integer NOT NULL,
    curso_id integer NOT NULL,
    progresso numeric(5,2) NOT NULL,
    status character varying(20) DEFAULT 'incompleto'::character varying,
    time_certificado timestamp with time zone,
    acessos_pos_conclusao integer DEFAULT 0,
    cod_indent character varying(255)
);


--
-- Name: progresso_cursos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.progresso_cursos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: progresso_cursos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.progresso_cursos_id_seq OWNED BY public.progresso_cursos.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    senha character varying(255) NOT NULL,
    role character varying(50) NOT NULL,
    email character varying(255),
    nome character varying(255),
    sobrenome character varying(255),
    endereco character varying(255),
    cidade character varying(255),
    pais character varying(255),
    cep character varying(20),
    cod_rec character varying(6),
    empresa character varying(255),
    empresa_id integer
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: Courses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."Courses" ALTER COLUMN id SET DEFAULT nextval('public."Courses_id_seq"'::regclass);


--
-- Name: aulas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aulas ALTER COLUMN id SET DEFAULT nextval('public.aulas_id_seq'::regclass);


--
-- Name: avaliacoes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.avaliacoes ALTER COLUMN id SET DEFAULT nextval('public.avaliacoes_id_seq'::regclass);


--
-- Name: compras_cursos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compras_cursos ALTER COLUMN id SET DEFAULT nextval('public.compras_cursos_id_seq'::regclass);


--
-- Name: cursos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cursos ALTER COLUMN id SET DEFAULT nextval('public.cursos_id_seq'::regclass);


--
-- Name: empresas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.empresas ALTER COLUMN id SET DEFAULT nextval('public.empresas_id_seq'::regclass);


--
-- Name: historico id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.historico ALTER COLUMN id SET DEFAULT nextval('public.historico_id_seq'::regclass);


--
-- Name: progresso_cursos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.progresso_cursos ALTER COLUMN id SET DEFAULT nextval('public.progresso_cursos_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: Courses; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public."Courses" (id, "courseName", "thumbnailUrl", "lessonName", "videoLessonUrl", "additionalFilesUrl", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: aulas; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.aulas (id, curso_id, nome, descricao, url_video) FROM stdin;
19	1	MÓDULO 1 - Gestão de Inventários Estoques MRO	Descroção Módulo 1	o96be6rdnq
20	2	MÓDULO 2 - Planejamento Estratégico Estoques MRO - MRP	Descrição do MÓDULO 2	mrr8dl2t4k
21	3	MÓDULO 3 - Obsolecência Estoques 	Descrição do MÓDULO 3	m1bcm2is7p
22	4	MÓDULO 4 - Processo Recebimento Físico de Materiais	Descrição do MÓDULO 4	dn7wor28qk
23	5	MÓDULO 5 - Contratos Fornecimentos Impacto nos Estoques 	Descrição do MÓDULO 5	6smceehc8g
24	6	MÓDULO 6 -  Governança Cadastro Materiais e Forncedores	Descrição do MÓDULO 6	2kn0g8ngt7
26	8	MÓDULO 8 - IQF Qualificação Técnica Estrutural Fornecedores	Descrição do MÓDULO 8	x4itrft2zh
27	9	MÓDULO 9 - Follow Up	Descrição do MÓDULO 9	mug34x2r6k
28	14	MÓDULO 10 - Acuracidade de Estoques	Descrição do MÓDULO 10	lfslslbsdv
29	11	MÓDULO 7 - Gestão de Estoques em Trânsito	Descrição do MÓDULO 7	wwo7hhmrc6
\.


--
-- Data for Name: avaliacoes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.avaliacoes (id, curso_id, pergunta, opcoes, resposta_correta) FROM stdin;
78	4	Qual é o primeiro passo no recebimento físico de mercadorias?	{"A": "Armazenagem dos materiais e produtos recebidos", "B": "Checagem (quantitativa e qualitativa) itens apontados espelho cego", "C": "Etiquetar materiais e produtos recebidos", "D": "Atender demandas pendentes, antes do processo de entrada estar efetivado"}	B
79	4	O que autoriza a entrada da transportado para local do recebimento físico mercadorias e produtos?	{"A": "O preço de compra", "B": "O número do documento interno de ordem de compra, informado no corpo da NF", "C": "A data de validade do produto", "D": "A descrição qualitativa do produto"}	B
80	4	O que deve ser feito com produtos destinados ao estoque após a conferência?	{"A": "Devem ficar na área por tempo indeterminado", "B": "Devem ser etiquetados e armazenados em suas localizações cadastradas", "C": "Devem ser descartados se não forem usados em 24 horas", "D": "Devem ser enviados de volta ao fornecedor sem justificativa alguma"}	B
81	4	Como o método FIFO influencia a gestão de estoques?	{"A": "Prioriza a saída dos materiais e produtos LOTES mais antigos em estoques, primeiro", "B": "Mantém os produtos mais novos direcionados para saída imediata", "C": "Não afeta a ordem de saída dos produtos", "D": "Prioriza a saída dos materiais e produtos recém-chegados primeiro"}	A
82	4	Qual método de armazenagem não é vantajoso para estoques com giro alongado?	{"A": "FIFO", "B": "LIFO", "C": "Just in Time", "D": "ABC"}	B
83	4	O que acontece com os materiais de aplicação direta após conferência?	{"A": "Devem ser armazenados indefinidamente", "B": "Devem permanecer sob guarda, proteção e controle da gestão de materiais", "C": "Devem ser retirados no prazo máximo de 24 horas, por seus solicitantes", "D": "Devem ser inventariados e inclusos estoques, por conta ajuste entrada"}	C
84	4	Quando o transportador é liberado no processo de recebimento físico de mercadorias?	{"A": "Após a entrega dos volumes, materiais ou produtos", "B": "Antes da conferência física", "C": "Após a conferência física dos materiais, produtos individualmente ou volumes, assinatura do canhoto da Nota Fiscal, e via conhecimento frete", "D": "Após a liberação do item no estoque contábil pela área fiscal"}	C
106	9	Qual é o objetivo do follow-up de compras?	{"A": "Aumentar o estoque da empresa", "B": "Garantir o abastecimento e cumprimento de prazos acordados", "C": "Prospectar novos fornecedores", "D": "Impedir que fornecedor entregue materiais e serviços vendidos"}	B
107	9	O que significa "follow-up" em inglês?	{"A": "Acompanhar", "B": "Controlar", "C": "Verificar", "D": "Prospectar"}	A
108	9	Qual é um dos benefícios do follow-up de compras?	{"A": "Aumento de compras emergenciais", "B": "Aumento do índice de atraso de entregas", "C": "Redução de compras emergenciais e eliminação risco de rupturas estoques MRO", "D": "Aumento de rupturas estoques"}	C
109	9	Quando ocorre atraso de entrega item estratégico a qual “gravidade” poderemos deparar?	{"A": "Compra de emergência", "B": "Parada de um processo produtivo ou operacional", "C": "Aplicar multa no fornecedor", "D": "Excluir fornecedor da lista de qualificados"}	B
110	9	Quando um fornecedor deve ser suspenso ou desqualificado?	{"A": "Quando entrega no prazo", "B": "Quando entrega antes prazo", "C": "Quando seu índice de atraso de entrega for superior a 3%, cabe avaliação quanto a suspensão ou desqualificação", "D": "Quando não reponde posições de cobrança follow-up"}	C
111	9	O índice de atraso de entrega por fornecedores, estão diretamente ligados ao grau de amadurecimento das áreas compradoras?	{"A": "Sim", "B": "Não"}	A
112	9	Qual importância de se ter um KPI, que mesa o índice de atraso entregas?	{"A": "Segrega a estrutura de players homologados para fornecimentos", "B": "Elimina pontos de rupturas de estoques MRO", "C": "Impõe rigor no cumprimento de entrega seus fornecedores, pois este índices são disponibilizados e amparam as decisões de suspensão ou exclusão, tirando da pessoalidade esta decisão", "D": "Todas as respostas estão corretas"}	D
113	6	Qual é o objetivo principal de um cadastro íntegro e padronizado de materiais?	{"A": "Aumentar os estoques", "B": "Redução dos custos operacionais", "C": "Dificultar a gestão de compras", "D": "Reduzir a produtividade"}	B
114	6	O que é o PDM mencionado no curso?	{"A": "Programa de Desenvolvimento de Materiais", "B": "Padrão Descritivo de Materiais", "C": "Plano Diretor de Manufatura", "D": "Processo Digital de Materiais"}	B
115	6	Qual é a quantidade de dígitos do código NCM?	{"A": "4 dígitos", "B": "6 dígitos", "C": "8 dígitos", "D": "10 dígitos"}	C
116	6	O que representa a sigla CEST?	{"A": "Código Específico de Substituição Tributária", "B": "Classificação Estatística de Serviços e Tributos", "C": "Código Especificador da Substituição Tributária", "D": "Cadastro Estadual de Serviços e Tributos"}	C
117	6	Quantos dígitos compõem o código da NBS?	{"A": "7 dígitos", "B": "8 dígitos", "C": "9 dígitos", "D": "10 dígitos"}	C
118	6	Quem é o responsável pela classificação fiscal de materiais?	{"A": "O vendedor", "B": "O comprador", "C": "Ambos, vendedor e comprador", "D": "O governo"}	C
119	6	Qual é o risco de ter erros no cadastro de materiais?	{"A": "Recuperação indevida de tributos", "B": "Pagamentos indevidos de tributos", "C": "Recusa pela receita sped fiscal", "D": "Devolução mercadorias, compras erradas", "E": "Autuação pela receita", "F": "Todas as alternativas estão corretas"}	E
120	14	Qual indicador de eficiência que mede a integridade física x sistêmica dos estoques ?:	{"A": "Acuracidade", "B": "Nível de atendimento cliente interno", "C": "Giro dos estoques", "D": "Estoques em equilíbrio"}	A
121	14	Qual percentual de acuracidade é necessário para que determinado estoque seja reconhecido em nível de excelência ?:	{"A": "95%", "B": "100%"}	B
122	14	Porque ?: Nada deve entrar sem documento fiscal e nada deve sair sem a devida requisição de material;	{"A": "Nada deve entrar sem devida nota fiscal", "B": "Nada pode sair sem devida requisição de material"}	A
123	14	Qual ambiente do armazém contribui para excelência acuracidade ?:	{"A": "Limpo e organizado", "B": "Sistema de localização simples e eficiente", "C": "100% itens identificados em suas respectivas localizações", "D": "Todas as respostas estão corretas"}	D
124	14	Qual é o programa que avalia o ambiente do armazém em relação ao quesito limpasa e organização ?:	{"A": "ISO-9000", "B": "IQF", "C": "8S", "D": "ISO 14000"}	C
85	5	Quem é o instrutor do curso?	{"A": "João Silva", "B": "Amadeu Rocha", "C": "Maria Santos", "D": "Paulo Souza"}	B
86	5	Qual é o tema principal do curso?	{"A": "Compras modalidade “contrato” e impacto gestão estoques", "B": "Marketing", "C": "Gestão de Estoques", "D": "Gestão de Pessoas"}	A
87	5	O que significa a sigla SAVING que aparece no curso?	{"A": "Sistema de Análise de compras Inteligentes e Negociação", "B": "Redução de Custo com Aquisições (Economia Gerada Processo Negociação)", "C": "Sistema Automatizado de Compras", "D": "Nenhuma das alternativas"}	B
88	5	Quais impostos são citados no conteúdo sobre análise tributária?	{"A": "IPTU e IPVA", "B": "ICMS, IPI, PIS/COFINS", "C": "IRPF e CSLL", "D": "IOF e ITR"}	B
89	5	O que é apresentado no slide sobre o índice de atendimento das entregas?	{"A": "Gráfico de barras", "B": "Relógio IQF, índice qualitativo fornecedor", "C": "Texto descritivo", "D": "Organograma"}	B
90	5	Qual é o objetivo do processo de gestão de contratos mencionado?	{"A": "Recrutamento de pessoas", "B": "Seleção de fornecedores", "C": "Gerar “saving’s” CUSTO DE AQUISIÇÃO, reduzir “lead time” TEMPO processo de compras, consequentemente reduzir o tamanho do estoque, imobilizando menor capital financeiro no armazém", "D": "Propaganda e marketing"}	C
91	5	Qual é o comportamento no gráfico da demanda projetada na coluna onde o número de itens é 2428?	{"A": "Constante", "B": "Crescente", "C": "Decrescente", "D": "Irregular"}	A
99	8	O que é homologação técnica estrutural de fornecedores?	{"A": "Uma avaliação documental dos fornecedores", "B": "Um processo em loco em cada fornecedor, visando avaliar a estrutura técnica e ambiente instalado, para garantir que os mesmos tenham condições de garantir a qualidade de serviços e materiais a serem fornecidos, foco ESG", "C": "Análise de respostas de questionários enviados", "D": "Indicação mercado"}	B
100	8	Qual dos seguintes é um benefício da homologação de fornecedores?	{"A": "Redução índices de retrabalhos e devoluções", "B": "Análises comerciais mais justas, priorizando fornecedores estruturados e comprometidos com questões sociais, ambientais e de governança", "C": "Qualidade garantida no fornecimento de peças e serviços", "D": "Todas respostas estão corretas"}	D
101	8	O que se busca realizar, com a homologação de fornecedores?	{"A": "Diminuir o envolvimento com a linha de frente operacional", "B": "Acelerar a transformação operacional e garantir resultados futuros", "C": "Limitar a transparência na cadeia de suprimentos", "D": "Aumentar a dependência de fornecedores específicos"}	B
102	8	O que se verifica durante o processo de homologação?	{"A": "Estrutura física fornecedores conforme checklist específico, de cada seguimento", "B": "Certificações e homologações", "C": "A localização geográfica dos fornecedores", "D": "Todas respostas estão corretas"}	D
103	8	Qual é o objetivo da qualificação estrutural de fornecedores?	{"A": "Focar apenas no menor custo de aquisição", "B": "Qualificar e monitorar o desempenho dos fornecedores", "C": "Evitar auditorias e análises de desempenho", "D": "Consolidar contratos de longo prazo sem revisão"}	B
104	8	O que define o sucesso da homologação de fornecedores?	{"A": "Pela rapidez do processo", "B": "Pelo número de fornecedores homologados", "C": "Pela obtenção de índices qualitativos que impactarão da disponibilidade operacional de equipamentos, maquinas e componentes", "D": "Pela exclusão de fornecedores sem estrutura adequadas"}	C
105	8	Objetivo do processo de qualificação técnica e estrutural é desqualificar fornecedores que estejam fora dos requisitos por categorias?	{"A": "Sim, deste modo nivelar por cima a gama de fornecedores aprovados", "B": "Não, mais sim, oportunizar a adequação destes fornecedores, de modo a estarem aptos a atender as demandas de seu seguimento em alto grau de eficiência"}	B
125	14	É através de qual evento que se identifica a acuracidade ?:	{"A": "Auditoria", "B": "Inventário", "C": "Relatório posição estoque", "D": "Relatório itens movimentados"}	B
126	14	O que um estoque com baixa acuracidade pode trazer de transtorno ao processo produtivo operacional de uma empresa ?:	{"A": "Nenhum", "B": "Perda financeira", "C": "Aumento produção", "D": "Compra planejada de reposição"}	B
127	14	Em qual ponto da curva ABC a acuracidade baixa pode representar uma perda financeira expressiva ?:	{"A": "Curva \\"A\\"", "B": "Curva \\"B\\"", "C": "Curva \\"C\\"", "D": "Todas as alternativas estão corretas"}	A
128	11	Porque a gestão de estoque em trânsitos é de responsabilidade da área de gestão de materiais ?	{"A": "Pelo fato de ser ativo de estoques, portanto patrimônio empresa;", "B": "Pelo fato de ainda não ter se transformado em despesas;", "C": "Pelo fato de que enquanto estoque deve ter controle efetivo de acuracidade;", "D": "Todas as respostas estão corretas;"}	D
129	11	É fato que quando estes estoques não são controlados pela área de materiais ocorrem ?	{"A": "Perdas financeiras e operacionais;", "B": "Aumento da disponibilidade equipamentos/componentes e da frota nas frentes trabalhos;", "C": "Menor índice de intervenção manutenção corretiva;", "D": "Aumento produtividade;"}	A
130	11	Gerenciamento dos estoques em trânsitos pela área de materiais garantem ?	{"A": "Ineficiência operacional;", "B": "Paradas operacionais por falta de materiais (peças e componentes);", "C": "Eficiência operacional e controle efetivo destes ativos de estoque;", "D": "Todas as respostas estão corretas;"}	C
131	11	Qual a importância dos inventários na gestão estoques em trânsitos?	{"A": "Controlar a disponibilidade peças e componentes no estoque;", "B": "Controlar a reposição destes estoques;", "C": "Impedir estoques superdimensionados;", "D": "Garantir integridade (física x contábil e fiscal) destes estoques;"}	D
132	11	O que a coleta dos itens “trocados em campo”, durante o processo de manutenções corretivas, proporcionam quando geridos pela área de materiais?	{"A": "Perdas financeiras;", "B": "Controle sobre descartes, em especial a vida útil do ativo trocado, descartes adequados áreas de sucatas e impedem desvios;", "C": "Atrasos na execução dos serviços demandados;", "D": " Todas as repostas estão corretas;"}	B
133	11	O ambiente destes almoxarifados em trânsito devem estar sempre em qual condição?:	{"A": "Guardados em caixa ou armários na área onde ocorre os trabalhos mecânicos;", "B": "Dispostos dentro da área de manutenção em transido, de modo a agilizar os trabalhos dos mecânicos;", "C": "Ambiente limpo, organizado, com identificação e em espaço “segregado” da área de manutenção;", "D": "Ambiente limpo e organizado dispostos no mesmo local físico da área de manutenção;"}	C
57	1	Qual é o principal propósito da execução de inventários?	{"A": "Verificar a acuracidade dos estoques, integridade físico x sistema", "B": "Minimizar os custos de estoques", "C": "Garantir disponibilidade de estoque para atendimentos demandas geradas", "D": "Medir a qualidade da gestão área materiais MRO", "E": "Todas as respostas estão corretas"}	E
58	1	Qual ação é necessária antes do start do processo inventário?	{"A": "Gerar lista “cega” de checagem", "B": "Definir equipe operacional", "C": "Planejamento e preparação de inventário", "D": "Comunicar áreas clientes internas das datas do procedimento"}	C
59	1	Qual é o índice mínimo (%) de validação inventário pelo método acuracidade?	{"A": "80%", "B": "60%", "C": "75%", "D": "95%"}	D
60	1	Com que frequência as empresas tributadas com base no lucro real devem produzir o Livro de Registro de Inventário no Brasil?	{"A": "Mensalmente", "B": "Trimestral ou Anualmente", "C": "Semanalmente", "D": "Diariamente"}	B
61	1	Qual impacto de estoques sem acuracidade?	{"A": "Podem parar processo produtivo e ou operacional", "B": "Compras de urgência", "C": "Prejudicar índices de disponibilidades frotas e equipamentos", "D": "Todas alternativas estão corretas"}	D
62	1	Qual tipo de inventário envolve a contagem de todo o estoque de uma vez?	{"A": "Rotativo", "B": "Amostral", "C": "Geral", "D": "Por qualidade"}	C
63	1	Qual é o propósito da validação de inventário?	{"A": "Melhorar o atendimento ao cliente", "B": "Ajustar os dados do sistema ERP", "C": "Garantir que processo de execução, foi efetivado com qualidade", "D": "Preparar para auditorias financeiras"}	C
64	2	O que o MRP ajuda a determinar na gestão de estoques?	{"A": "A localização física dos itens no armazém", "B": "A projeção de quantidade e alocação dos materiais de modo a garantir estoques em equilíbrio", "C": "O número de funcionários necessários no armazém", "D": "O preço médio itens em estoque"}	B
65	2	Qual a fórmula para calcular o estoque mínimo?	{"A": "Estoque Mínimo = CMM x K", "B": "Estoque Mínimo = CMM + K", "C": "Estoque Mínimo = CMM / K", "D": "Estoque Mínimo = CMM – K"}	A
66	2	Qual dos seguintes NÃO é um dado necessário para o MRP?	{"A": "Curva de demanda histórica", "B": "Tempo de reposição", "C": "Preço de compra dos materiais", "D": "Tamanho do lote de reposição"}	C
67	2	Como é calculado o Estoque Máximo?	{"A": "Estoque Máximo = Estoque Mínimo + Lote de Compra", "B": "Estoque Máximo = Estoque Mínimo x Lote de Compra", "C": "Estoque Máximo = Lote de Compra - Estoque Mínimo", "D": "Estoque Máximo = Lote de Compra / Estoque Mínimo"}	A
68	2	O que o Ponto de Pedido indica?	{"A": "Indica o momento de acionar follow-up", "B": "Indica o nível de estoque que aciona a emissão de uma solicitação de compra de reposição", "C": "Indica que estoque está abastecido", "D": "Indica ponto de ruptura de estoques"}	B
69	2	Qual é o papel do Fator de Segurança na gestão de estoques?	{"A": "Determinar o tamanho dos estoques MRO", "B": "Calcular a quantidade de produtos danificados", "C": "Garantir que estoque mínimo, suporte eventuais atrasos, logísticos e ou de imprevistos pontuais", "D": "Definir a localização dos produtos no armazém"}	C
70	2	Qual desses elementos NÃO é influenciado diretamente pela política de estoque da empresa?	{"A": "Estoque Máximo", "B": "Tempo de Reposição", "C": "Ponto de Pedido", "D": "Estrutura do Produto"}	D
71	3	O que caracteriza a obsolescência de um produto no estoque?	{"A": "Falta de acompanhamento da curva de demanda online", "B": "Evolução tecnológica", "C": "Armazenagens ambientes inadequados", "D": "Equipamento retirado operação, itens aplicação específica", "E": "Todas as alternativas estão corretas"}	E
72	3	Qual das seguintes NÃO é uma causa para a obsolescência do estoque?	{"A": "Ausência de procedimentos", "B": "Evolução tecnológica", "C": "Comunicação eficaz entre áreas técnicas com planejador estoques", "D": "Falta de análise de suficiência em dias de estoque"}	C
73	3	Como pode ser reduzida a obsolescência do estoque?	{"A": "Eliminando estoques diretos", "B": "Aumentando os pontos de estoque mínimo e máximo, sem análise", "C": "Acompanhando a movimentação da curva de demanda, sempre em sintonia com áreas técnicas, planos investimentos e cuidados com armazenamentos", "D": "Evitando revisões periódicas dos estoques"}	C
74	3	O que deve ser feito com o estoque obsoleto?	{"A": "Armazenar indefinidamente", "B": "Segregar e quantificar para venda ou troca", "C": "Descartar como sucata", "D": "Doar"}	B
75	3	Qual a importância de comunicar-se com as áreas técnicas?	{"A": "Diminuir a eficiência operacional", "B": "Aumentar os custos de estoque", "C": "Prevenir obsolescência por falta de conhecimento dos planos de investimento, evolução tecnológica e demandas sazonais ou cíclicas", "D": "Aumentar a disponibilidade de itens em estoques"}	C
76	3	Por que é importante revisar periodicamente os pontos de mínimo e máximo do estoque?	{"A": "Para aumentar o espaço de armazenamento necessário", "B": "Para ajustar o estoque às mudanças na demanda e evitar obsolescência", "C": "Para reduzir a quantidade de itens estoque", "D": "Para aumentar a suficiência dias estoques"}	B
77	3	Qual ação NÃO contribui para reduzir a obsolescência de estoque?	{"A": "Segregar o estoque obsoleto", "B": "Acompanhar rigorosamente os itens com garantia condicionada à validade", "C": "Manter estoques pulverizados na planta e alta suficiência em estoques", "D": "Estabelecer critérios de homologação de fornecedores e marcas"}	C
134	11	O que a mobilidade oferece ao processo de gestão destes estoques em trânsito?:	{"A": "Controle em tempo real das demandas geradas pelas intervenções mecânicas;", "B": "Reposição destes estoques em sincronia com demandas;", "C": "Controle efetivo destes estoques;", "D": "Todas as repostas estão corretas;"}	D
\.


--
-- Data for Name: cnpj_tentativas; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.cnpj_tentativas (cnpj, tentativas, ultima_tentativa) FROM stdin;
69350396000101	3	2024-09-08 19:05:27.699436+00
83279185000142	1	2024-09-08 19:21:08.152035+00
87868273000130	1	2024-09-08 20:32:11.599415+00
\.


--
-- Data for Name: compras_cursos; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.compras_cursos (id, user_id, curso_id, data_compra, status, periodo, created_at, data_inicio_acesso, data_fim_acesso, link_checkout) FROM stdin;
864	98	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
865	98	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
866	98	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
867	98	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
868	98	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
869	98	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
870	98	5	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
871	98	8	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
872	98	9	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
873	99	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
874	99	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
875	99	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
876	99	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
877	99	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
878	99	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
879	100	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
880	100	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
881	100	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
882	100	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
883	100	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
884	100	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
885	101	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
886	101	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
887	101	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
888	101	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
889	101	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
890	101	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
891	102	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
892	102	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
893	102	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
894	102	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
895	102	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
896	102	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
897	103	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
898	103	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
899	103	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
900	103	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
901	103	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
902	103	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
903	104	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
904	104	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
905	104	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
906	104	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
907	104	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
908	104	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
909	105	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
910	105	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
911	105	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
643	80	5	2024-07-19 20:48:38.954673	aprovado	6m	2024-07-19 20:48:38.954673	\N	\N	\N
912	105	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
913	105	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
914	105	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
915	105	5	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
916	105	8	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
917	105	9	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
918	106	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
919	106	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
651	80	2	2024-07-19 22:08:28.87817	pendente	6m	2024-07-19 22:08:28.87817	\N	\N	\N
920	106	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
921	106	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
922	106	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
923	106	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
924	107	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
925	107	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
926	107	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
927	107	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
928	107	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
929	107	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
930	108	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
931	108	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
932	108	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
933	108	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
934	108	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
935	108	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
936	109	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
937	109	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
938	109	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
939	109	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
940	109	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
669	81	3	2024-10-17 21:15:08.803685	Não Realizada	10d	2024-10-17 21:15:08.803685	\N	\N	\N
670	81	3	2024-10-17 21:44:11.391951	Não Realizada	10d	2024-10-17 21:44:11.391951	\N	\N	\N
941	109	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
942	110	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
943	110	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
944	110	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
945	110	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
946	110	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
947	110	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
948	110	5	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
949	110	8	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
950	110	9	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
951	111	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
952	111	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
953	111	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
954	111	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
955	111	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
956	111	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
957	112	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
958	112	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
959	112	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
960	112	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
961	112	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
962	112	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
963	113	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
964	113	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
965	113	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
966	113	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
967	113	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
968	113	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
969	114	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
970	114	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
971	114	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
972	114	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
973	114	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
974	114	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
975	115	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
976	115	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
977	115	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
978	115	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
979	115	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
980	115	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
981	116	1	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
982	116	2	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
983	116	3	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
984	116	4	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
985	116	11	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
986	116	14	2026-09-01 03:09:30.027113	aprovado	6m	2026-09-01 03:09:30.027113	2026-09-01 03:09:30.027113	2027-03-01 03:09:30.027113	\N
807	88	1	2024-11-05 16:42:17.49606	pendente	10d	2024-11-05 16:42:17.49606	\N	\N	\N
832	93	4	2025-01-21 14:48:54.363238	Não Realizada	10d	2025-01-21 14:48:54.363238	\N	\N	\N
833	93	3	2025-01-21 14:48:54.36635	Não Realizada	10d	2025-01-21 14:48:54.36635	\N	\N	\N
834	95	3	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
835	95	4	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
836	95	5	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
837	95	6	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
838	95	2	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
839	95	9	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
840	95	14	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
841	95	11	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
842	95	8	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
843	95	1	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
844	96	3	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
845	96	4	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
846	96	5	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
847	96	6	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
848	96	2	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
849	96	9	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
850	96	14	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
851	96	11	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
852	96	8	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
853	96	1	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
854	97	3	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
855	97	4	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
856	97	5	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
857	97	6	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
858	97	2	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
859	97	9	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
860	97	14	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
861	97	11	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
862	97	8	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
863	97	1	2026-08-29 02:15:49.437293	aprovado	6m	2026-08-29 02:15:49.437293	2026-08-29 02:15:49.437293	2027-02-28 02:15:49.437293	\N
\.


--
-- Data for Name: cursos; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.cursos (id, nome, descricao, thumbnail, valor_15d, valor_30d, valor_6m, caminho_pdf, valor_10d) FROM stdin;
3	Obsolecência Estoques	Entenda como identificar e mitigar os riscos associados à obsolescência de estoques, garantindo a eficiência e a sustentabilidade das operações.	https://imgur.com/K8XcWd4.png	1.00	0.01	1200.00	../pdf/3 Obsolecência Estoques.pdf	280.00
4	Processo Recebimento Físico de Materiais	Aprenda sobre as etapas críticas no recebimento físico de materiais, incluindo inspeção, registro, e armazenamento, assegurando a acurácia do estoque.	https://imgur.com/CMae34w.png	1.00	0.01	1600.00	../pdf/4 Processo Recebimento Físico de Materiais.pdf	280.00
5	Contratos Fornecimentos Impacto nos Estoques	Examine como contratos de fornecimento influenciam a gestão de estoques e aprenda estratégias para otimizar este impacto, equilibrando oferta e demanda.	https://imgur.com/hYctD3C.png	1.00	0.01	1600.00	../pdf/5 Contratos Fornecimentos Impacto nos Estoques.pdf	280.00
6	Governança Cadastro Materiais e Forncedores	Descubra a importância de uma governança robusta no cadastro de materiais e fornecedores para a integridade dos dados e a eficiência operacional.	https://imgur.com/geZqOGC.png	1.00	0.01	1200.00	../pdf/6 Governança Cadastro Materiais e Forncedores (V.1).pdf	280.00
2	Planejamento Estratégico Estoques MRO - MRP	Este módulo oferece uma visão aprofundada sobre o Planejamento Estratégico de Estoques focado em Manutenção, Reparo e Operações (MRO) e Planejamento de Recursos de Materiais (MRP). Através de estudos de caso, análises de melhores práticas e simulações, os participantes aprenderão a otimizar estoques de MRO, alinhando-os com as demandas de produção e manutenção. O curso aborda técnicas de previsão, gestão de inventário, análise de custo-benefício para a compra e armazenagem de itens MRO, e estratégias para implementação de um sistema MRP eficiente. Ideal para profissionais de suprimentos, operações e logística, este módulo é crucial para quem busca excelência na gestão de estoques e na redução de custos operacionais.	https://imgur.com/L4aplVT.png	1.00	0.01	1600.00	../pdf/2 Planejamento Estratégico Estoques MRO - MRP.pdf	280.00
9	Follow Up	Este módulo é focado no desenvolvimento de habilidades para o eficaz acompanhamento e gestão de fornecedores após a sua qualificação. Os participantes aprenderão técnicas para monitorar o desempenho dos fornecedores, garantindo o cumprimento dos prazos, qualidade, e especificações contratuais. Serão discutidas estratégias para a comunicação efetiva, resolução de problemas, e melhoria contínua, visando fortalecer as relações entre empresa e fornecedor, e assegurar uma cadeia de suprimentos robusta e confiável.	https://imgur.com/8FNFt8Y.png	1.00	0.01	1200.00	../pdf/9 Follow Up.pdf	280.00
14	Acuracidade de Estoques	Este módulo aborda os conceitos e práticas fundamentais para uma gestão eficiente e precisa dos estoques de materiais de reparo e operação (MRO). Ministrado pelo experiente instrutor Amadeu Rocha, o treinamento explora o princípio da acuracidade de 100% nos estoques como obrigação da gestão de materiais.\r\n\r\nOs participantes aprenderão sobre a importância da acuracidade nos registros de estoque, bem como a fórmula para sua medição, comparando as quantidades físicas com as registradas no sistema ERP. Além disso, serão apresentados os princípios básicos para entrada e saída de materiais do armazém, garantindo o controle adequado.\r\n\r\nO curso também aborda aspectos essenciais para um ambiente de armazenagem eficiente, como equipe comprometida e valorizada, organização, sistema de localização simples, identificação correta dos itens e uso de tecnologias. Serão discutidas as possíveis carreiras na área de suprimentos e logística, bem como a importância de treinamento, educação, economia e o programa 8S.\r\n\r\nAo final do módulo, os participantes estarão aptos a compreender e aplicar as melhores práticas para a gestão inteligente dos estoques MRO, contribuindo para a redução de desperdícios, aumento da eficiência operacional e atendimento excepcional aos clientes internos	https://imgur.com/LWY53dL.png	1.00	0.01	1200.00	../pdf/10 ACURACIDADE ESTOQUES.pdf	280.00
11	Gestão de Estoques em Trânsito	Maximize a eficiência e o controle dos estoques móveis em suas operações de campo. Este treinamento aborda estratégias e práticas para gerenciar de forma inteligente os estoques em trânsito, como caminhões oficina, garantindo a disponibilidade adequada de peças, otimizando processos de reposição e controle de estoque, melhorando a mobilidade com tablets para requisições, implementando a gestão de peças usadas para remanufratura e aumentando a segurança nas operações de campo. Aprenda a transformar a gestão de estoques em trânsito, impulsionando a melhoria contínua e a eficiência operacional em suas atividades críticas.	https://imgur.com/zSIvnQ3.png	1.00	0.01	1200.00	../pdf/11 Gestão Estoques em Trânsito.pdf	280.00
8	IQF Qualificação Técnica Estrutural Fornecedores	Este módulo visa capacitar os participantes no processo de avaliação e qualificação técnica de fornecedores, assegurando que estes atendam aos rigorosos requisitos estruturais e de qualidade necessários para a produção e fornecimento de componentes críticos. Através de uma abordagem prática, serão abordados temas como critérios de seleção, análise de capacidade técnica, auditorias de processos, e gestão de riscos, preparando os alunos para identificar e selecionar parceiros estratégicos que garantam a integridade e a confiabilidade dos produtos finais.	https://imgur.com/0jHug9J.png	1.00	0.01	1200.00	../pdf/8 IQF QUALIFICAÇÃO TÉCNICA ESTRUTURAL FORNECEDORES.pdf	280.00
1	Gestão de Inventários Estoques MRO	Este módulo de cursos é projetado para profissionais e estudantes que desejam aprimorar suas habilidades em gestão de inventários e estoques MRO (Manutenção, Reparo e Operações). Abrangendo desde os fundamentos da gestão de estoques até estratégias avançadas de otimização, o curso oferece uma abordagem prática para melhorar a eficiência, reduzir custos e garantir a disponibilidade de itens críticos para as operações. Os participantes aprenderão técnicas de previsão de demanda, gestão de fornecedores, análise de custo-benefício de estoques, além de explorar as melhores práticas e tecnologias emergentes no campo. Ideal para gerentes de operações, supervisores de estoque, e profissionais de compras, este módulo é a chave para dominar a arte da gestão de estoques MRO.	https://imgur.com/KF0vBLV.png	1.00	0.01	1200.00	../pdf/1 Gestão de Inventários Estoques MRO.pdf	280.00
\.


--
-- Data for Name: empresas; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.empresas (id, nome, email, senha, modulos, cnpj, logradouro, numero, complemento, bairro, cidade, estado, cep, telefone, responsavel, razao_social, endereco) FROM stdin;
7	FMATCH TECNOLOGIA LTDA	fmatch@fmatch.com	$2a$10$Iysu5XZKtTw75aCjFVvUP.6W52ImL3czPfFY0HX2L8SoFnM.tX7PK	\N	52.622.018/0001-29	R. Cel. Joaquim Gabriel	 521	Sala 2	Centro	Lençóis Paulista	São Paulo	18682-030	14998728006	Felipe	\N	\N
8	Pagrisa	suus123@gmail.com	$2a$10$ShVQwckDxjSBQE4WnDbzx.jIvyJWjzQADn3E/zlN2Zcgrm4PngnbG	\N	87.868.273/0001-30	\N	\N	\N	\N	lençóis paulista	sao paulo	18683-200	14998556480	\N	sdds	rua atilio frezzarin, 47
10	INPASA AGROINDUSTRIAL S/A	acesso.inpasa@fmatch.com	$2a$10$EnZE0m.mXgPRCbtdRiW6LOfhDZ2jaWjKD/yHbv2PZ8bTmMtmiVDc6	\N	29316596000115	\N	\N	\N	\N	SINOP	MT	78559-899	(66)35315494	\N	\N	\N
11	mms teste	gyomeji@gmail.com	$2a$10$kIT.u3b4dcT7SNq9bPyHC.bAwoRMoyKooHU86qg9KMx3w96/coh6K	\N	62937906000194	\N	\N	\N	\N	lençóis paulista	São Paulo	18683-200	14998224352	\N	\N	\N
12	Empresa Teste Acesso Total	empresa@testeacesso.com	$2a$10$ME9LHw4EbqAWa8LVNV5jy.3nJpWQnTlYFaSfjYVlmhxMQe4nfQNHq	\N	12.345.678/0001-90	\N	\N	\N	\N	São Paulo	SP	01000-000	(11) 99999-9999	Responsável Teste	Empresa Teste Acesso Total LTDA	Rua Teste, 123
13	Guilherme - GRUPO ZAMBIANCO	guilherme.massarico@outlook.com	$2a$10$NcfJyNZ42HMbexwMN5zScuG4mGqBZjbVg1u4QYHIdtFtL02NSvcnW	\N	00.000.000/0001-00	\N	\N	\N	\N	Lençóis Paulista	SP	18680-000	(14) 99999-9999	Guilherme Massarico	GRUPO ZAMBIANCO LTDA	Rodovia SP-304, Km 150
\.


--
-- Data for Name: historico; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.historico (id, user_id, curso_id, compra_id, status, periodo, valor_pago, data_compra, data_aprovacao, status_progresso, data_conclusao, cod_indent) FROM stdin;
180	57	3	636	aprovado	\N	\N	2024-07-19 20:14:18.364	2024-07-19 20:15:22.981751	\N	\N	\N
182	57	4	633	aprovado	\N	\N	2024-07-19 20:14:18.258	2024-07-19 20:15:23.249148	\N	\N	\N
316	102	11	895	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
317	102	14	896	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
184	57	11	638	aprovado	\N	\N	2024-07-19 20:35:21.716	2024-07-19 20:35:57.650693	\N	\N	\N
186	57	1	639	aprovado	\N	\N	2024-07-19 20:35:21.716	2024-07-19 20:35:57.917284	\N	\N	\N
318	103	1	897	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
319	103	2	898	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
188	57	5	644	aprovado	\N	\N	2024-07-19 20:48:38.997	2024-07-19 20:52:03.998128	\N	\N	\N
189	80	5	643	aprovado	\N	\N	2024-07-19 20:48:38.954	2024-07-19 20:52:04.13603	\N	\N	\N
190	57	6	642	aprovado	\N	\N	2024-07-19 20:48:38.915	2024-07-19 20:52:04.26794	\N	\N	\N
192	57	14	654	aprovado	\N	\N	2024-07-19 22:45:31.434	2024-07-19 22:54:18.895458	\N	\N	\N
320	103	3	899	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
321	103	4	900	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
322	103	11	901	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
323	103	14	902	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
194	79	4	671	aprovado	\N	\N	2024-10-17 21:55:08.101	2024-10-17 21:57:02.933059	concluido	2024-10-17 19:10:47.444	368162a8-5b6f-4959-b6e2-10c4e721940b
195	79	11	672	aprovado	\N	\N	2024-10-17 21:55:08.144	2024-10-17 21:57:03.072794	concluido	2024-11-07 16:27:53.904	a2704be0-87e8-43d9-a12a-697c08477239
181	80	3	635	aprovado	\N	\N	2024-07-19 20:14:18.315	2024-07-19 20:15:23.117096	concluido	2024-12-09 17:57:01.89561	\N
183	80	4	634	aprovado	\N	\N	2024-07-19 20:14:18.306	2024-07-19 20:15:23.337414	concluido	2024-12-09 17:57:01.89561	\N
185	80	11	637	aprovado	\N	\N	2024-07-19 20:35:21.68	2024-07-19 20:35:57.785237	concluido	2024-12-09 17:57:01.89561	\N
187	80	1	640	aprovado	\N	\N	2024-07-19 20:35:21.935	2024-07-19 20:35:58.049556	concluido	2024-12-09 17:57:01.89561	\N
191	80	6	641	aprovado	\N	\N	2024-07-19 20:48:38.909	2024-07-19 20:52:04.399876	concluido	2024-12-09 17:57:01.89561	\N
193	80	14	653	aprovado	\N	\N	2024-07-19 22:45:31.369	2024-07-19 22:54:19.041311	concluido	2024-12-09 17:57:01.89561	\N
273	96	8	852	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
274	96	1	853	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
275	97	3	854	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
276	97	4	855	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
277	97	5	856	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
278	97	6	857	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
279	97	2	858	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
280	97	9	859	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
281	97	14	860	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
282	97	11	861	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
283	97	8	862	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
324	104	1	903	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
325	104	2	904	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
326	104	3	905	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
327	104	4	906	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
328	104	11	907	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
329	104	14	908	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
330	105	1	909	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
284	97	1	863	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
302	100	3	881	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
303	100	4	882	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
304	100	11	883	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
305	100	14	884	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
306	101	1	885	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
307	101	2	886	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
308	101	3	887	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
309	101	4	888	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
310	101	11	889	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
311	101	14	890	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
312	102	1	891	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
313	102	2	892	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
314	102	3	893	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
315	102	4	894	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
331	105	2	910	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
332	105	3	911	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
333	105	4	912	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
334	105	5	915	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
335	105	8	916	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
336	105	9	917	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
337	105	11	913	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
338	105	14	914	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
339	106	1	918	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
340	106	2	919	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
341	106	3	920	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
342	106	4	921	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
343	106	11	922	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
344	106	14	923	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
345	107	1	924	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
346	107	2	925	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
347	107	3	926	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
348	107	4	927	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
349	107	11	928	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
350	107	14	929	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
351	108	1	930	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
352	108	2	931	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
353	108	3	932	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
227	88	2	750	aprovado	\N	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-07 12:33:46.9	8d8b8225-7789-42ee-b533-2284857d0d7f
235	87	4	746	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-07 22:23:55.869	714f8029-d860-47b1-bef9-086ab2a93996
229	88	14	756	aprovado	\N	\N	2024-10-29 21:33:39.302527	2024-11-07 20:18:50.690972	concluido	2024-11-07 14:59:11.64	30cb9274-02cf-40e5-a7f0-df36ae45ba0a
244	84	3	736	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-16 10:08:27.863	74284147-7f3d-4a5a-a2c5-1ebd083213a5
230	88	3	748	aprovado	\N	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-07 11:40:12.079	290cf620-e98e-427f-ba52-9ba72d5ae1bf
233	88	1	758	aprovado	\N	\N	2024-10-29 22:00:07.923324	2024-11-07 20:18:50.690972	concluido	2024-11-06 17:37:06.76	b426730b-d65a-48fd-b6b9-9625c34e146e
246	84	2	738	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-16 10:56:19.462	651d28b7-ce85-4b5f-970e-3d20503750d3
225	85	4	740	aprovado	\N	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-06 17:16:04.344	c73d09c0-92be-46d7-8561-a93bfc5a3a76
226	85	2	741	aprovado	\N	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-06 17:22:11.257	0c368a8f-0934-4ac5-b557-623b40fec7a1
228	85	1	761	aprovado	\N	\N	2024-10-29 22:00:07.923324	2024-11-07 20:18:50.690972	concluido	2024-11-06 17:37:40.695	27e9192a-0cc7-47f1-a238-0f5b3357e00a
231	85	14	753	aprovado	\N	\N	2024-10-29 21:33:39.302527	2024-11-07 20:18:50.690972	concluido	2024-11-07 14:58:24.387	8e84107b-5ab7-4c3d-974d-c0fd4f46fffa
232	85	3	739	aprovado	\N	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-06 17:24:36.388	e187521f-564b-471e-bff0-6d1ec3475ce2
254	88	4	830	aprovado	10d	\N	2024-11-26 20:14:25.667819	2024-11-26 20:14:25.667819	concluido	2024-12-09 18:01:17.136039	\N
289	98	5	870	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
290	98	8	871	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
255	95	3	834	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	concluido	2026-08-29 02:35:10.775	e17aeb6f-9478-43be-9e5b-cd5ed9076628
242	82	14	751	aprovado	10d	\N	2024-10-29 21:33:39.302527	2024-11-07 20:18:50.690972	concluido	2024-11-20 19:51:09.031	38835219-7839-48d8-9857-2fbc168fcfe1
248	84	1	760	aprovado	6m	\N	2024-12-12 13:43:19.734824	2024-12-12 13:43:19.734824	concluido	2024-12-12 18:10:48.551	a69ea144-32f9-4ba8-9bcc-6bbf596b1d65
243	82	1	759	aprovado	10d	\N	2024-10-29 22:00:07.923324	2024-11-07 20:18:50.690972	concluido	2024-11-26 15:14:35.76	03f43fcd-a2f9-4809-83f0-ef5a2896d86a
245	84	4	737	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-26 15:16:35.298	8bcbde9e-685d-4ef1-afcd-28eb0ffa32c2
249	86	3	742	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-07 22:41:44.586	ff162fca-373b-4a68-b6b6-6c5fd1afd496
234	87	3	745	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-07 21:46:08.732	b6cd9859-9e08-48ef-9b99-edc0e7b60f76
257	95	5	836	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
247	84	14	752	aprovado	10d	\N	2024-10-29 21:33:39.302527	2024-11-07 20:18:50.690972	concluido	2024-11-26 15:24:26.41	56f6477b-0341-4ed4-b7e0-d73bb5f23bd3
291	98	9	872	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
258	95	6	837	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
236	87	2	747	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-07 23:10:24.144	cc60c0ed-f72f-464d-bfd2-c97c5740c759
241	82	2	735	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-26 16:44:32.645	87c5f7be-8fd9-409f-b44d-9327921b8061
259	95	2	838	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
239	82	3	733	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-26 16:48:54.064	be39c92d-7dbc-4bf2-858a-9e0c10ed5e67
250	86	4	743	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-07 23:24:47.454	bf2a39d7-bdf1-49f5-955b-2b1df75709b4
260	95	9	839	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
240	82	4	734	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-26 16:59:03.567	0d7768a9-2e6c-4468-90a8-4cf8e39ea076
238	87	1	757	aprovado	10d	\N	2024-10-29 22:00:07.923324	2024-11-07 20:18:50.690972	concluido	2024-11-09 16:13:25.834	47ac35cc-1a93-4a99-a048-5e701281a8ff
237	87	14	755	aprovado	10d	\N	2024-10-29 21:33:39.302527	2024-11-07 20:18:50.690972	concluido	2024-11-09 16:56:24.469	2ef7bf77-f796-4cae-aa31-b32c0a941ebf
256	95	4	835	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	concluido	2026-08-29 03:03:08.125	011ee739-895c-456e-96c9-15682f086abe
285	98	1	864	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
251	86	2	744	aprovado	10d	\N	2024-10-29 20:59:14.768119	2024-11-07 20:18:50.690972	concluido	2024-11-10 15:18:44.353	d82353db-2a18-49b7-ab40-665ad54eaf76
286	98	2	865	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
287	98	3	866	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
261	95	14	840	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
253	86	1	762	aprovado	10d	\N	2024-10-29 22:00:07.923324	2024-11-07 20:18:50.690972	concluido	2024-11-10 22:30:57.396	3b1e5986-a8ae-4775-b0b2-02d7c5639346
262	95	11	841	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
252	86	14	754	aprovado	10d	\N	2024-10-29 21:33:39.302527	2024-11-07 20:18:50.690972	concluido	2024-11-11 09:43:55.673	b66fa752-7915-455b-85e1-ce9456bd95b6
263	95	8	842	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
264	95	1	843	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
265	96	3	844	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
266	96	4	845	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
267	96	5	846	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
268	96	6	847	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
269	96	2	848	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
270	96	9	849	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
271	96	14	850	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
272	96	11	851	aprovado	\N	\N	2026-08-29 02:45:06.645573	2026-08-29 02:45:06.645573	nao_iniciado	\N	\N
288	98	4	867	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
292	98	11	868	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
293	98	14	869	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
294	99	1	873	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
295	99	2	874	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
296	99	3	875	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
297	99	4	876	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
298	99	11	877	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
299	99	14	878	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
300	100	1	879	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
301	100	2	880	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
354	108	4	933	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
355	108	11	934	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
356	108	14	935	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
357	109	1	936	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
358	109	2	937	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
359	109	3	938	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
360	109	4	939	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
361	109	11	940	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
362	109	14	941	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
363	110	1	942	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
364	110	2	943	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
365	110	3	944	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
366	110	4	945	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
367	110	5	948	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
368	110	8	949	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
369	110	9	950	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
370	110	11	946	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
371	110	14	947	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
372	111	1	951	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
373	111	2	952	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
374	111	3	953	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
375	111	4	954	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
376	111	11	955	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
377	111	14	956	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
378	112	1	957	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
379	112	2	958	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
380	112	3	959	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
381	112	4	960	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
382	112	11	961	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
383	112	14	962	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
384	113	1	963	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
385	113	2	964	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
386	113	3	965	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
387	113	4	966	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
388	113	11	967	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
389	113	14	968	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
390	114	1	969	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
391	114	2	970	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
392	114	3	971	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
393	114	4	972	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
394	114	11	973	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
395	114	14	974	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
396	115	1	975	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
397	115	2	976	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
398	115	3	977	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
399	115	4	978	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
400	115	11	979	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
401	115	14	980	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
402	116	1	981	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
403	116	2	982	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
404	116	3	983	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
405	116	4	984	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
406	116	11	985	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
407	116	14	986	aprovado	6m	\N	2026-09-01 03:09:30.027	2026-09-01 03:09:30.027	Não Iniciado	\N	\N
\.


--
-- Data for Name: progresso_cursos; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.progresso_cursos (id, user_id, curso_id, progresso, status, time_certificado, acessos_pos_conclusao, cod_indent) FROM stdin;
236	85	3	0.00	concluido	2024-11-06 17:24:36.388+00	0	e187521f-564b-471e-bff0-6d1ec3475ce2
253	82	3	0.00	concluido	2024-11-26 16:48:54.064+00	0	be39c92d-7dbc-4bf2-858a-9e0c10ed5e67
254	82	4	0.00	concluido	2024-11-26 16:59:03.567+00	0	0d7768a9-2e6c-4468-90a8-4cf8e39ea076
224	80	2	0.00	concluido	2024-12-09 17:57:02.243723+00	0	\N
257	84	2	0.00	concluido	2024-11-16 10:56:19.462+00	0	651d28b7-ce85-4b5f-970e-3d20503750d3
227	80	3	0.00	concluido	2024-12-09 17:57:02.243723+00	0	\N
222	78	3	0.00	concluido	2024-06-24 00:56:46.585+00	0	3f3d9347-4c4a-4690-90ad-566132b68646
228	80	4	0.00	concluido	2024-12-09 17:57:02.243723+00	0	\N
241	85	1	0.00	concluido	2024-11-06 17:37:40.695+00	1	27e9192a-0cc7-47f1-a238-0f5b3357e00a
238	85	4	0.00	concluido	2024-11-06 17:16:04.344+00	2	c73d09c0-92be-46d7-8561-a93bfc5a3a76
239	85	2	0.00	concluido	2024-11-06 17:22:11.257+00	1	0c368a8f-0934-4ac5-b557-623b40fec7a1
223	78	4	0.00	concluido	2024-06-24 20:25:58.608+00	0	dd8ecc5a-dc43-4a35-b3cd-1cfec8f26250
229	80	11	0.00	concluido	2024-12-09 17:57:02.243723+00	0	\N
230	80	1	0.00	concluido	2024-12-09 17:57:02.243723+00	0	\N
264	86	4	0.00	concluido	2024-11-07 23:24:47.454+00	0	bf2a39d7-bdf1-49f5-955b-2b1df75709b4
263	86	3	0.00	concluido	2024-11-07 22:41:44.586+00	1	ff162fca-373b-4a68-b6b6-6c5fd1afd496
225	80	6	0.00	concluido	2024-12-09 17:57:02.243723+00	0	\N
235	88	1	0.00	concluido	2024-11-06 17:37:06.76+00	1	b426730b-d65a-48fd-b6b9-9625c34e146e
232	80	14	0.00	concluido	2024-12-09 17:57:02.243723+00	0	\N
233	79	4	0.00	concluido	2024-10-17 19:10:47.444+00	1	368162a8-5b6f-4959-b6e2-10c4e721940b
247	88	3	0.00	concluido	2024-11-07 11:40:12.079+00	0	290cf620-e98e-427f-ba52-9ba72d5ae1bf
255	82	14	0.00	concluido	2024-11-20 19:51:09.031+00	2	38835219-7839-48d8-9857-2fbc168fcfe1
248	88	2	0.00	concluido	2024-11-07 12:33:46.9+00	0	8d8b8225-7789-42ee-b533-2284857d0d7f
266	87	1	0.00	concluido	2024-11-09 16:13:25.834+00	0	47ac35cc-1a93-4a99-a048-5e701281a8ff
268	87	3	0.00	concluido	2024-11-07 21:46:08.732+00	1	b6cd9859-9e08-48ef-9b99-edc0e7b60f76
256	84	1	0.00	concluido	2024-12-12 18:10:48.551+00	0	a69ea144-32f9-4ba8-9bcc-6bbf596b1d65
259	84	4	0.00	concluido	2024-11-26 15:16:35.298+00	0	8bcbde9e-685d-4ef1-afcd-28eb0ffa32c2
251	82	1	0.00	concluido	2024-11-26 15:14:35.76+00	1	03f43fcd-a2f9-4809-83f0-ef5a2896d86a
249	88	14	0.00	concluido	2024-11-07 14:59:11.64+00	1	30cb9274-02cf-40e5-a7f0-df36ae45ba0a
246	85	14	0.00	concluido	2024-11-07 14:58:24.387+00	1	8e84107b-5ab7-4c3d-974d-c0fd4f46fffa
262	86	2	0.00	concluido	2024-11-10 15:18:44.353+00	3	d82353db-2a18-49b7-ab40-665ad54eaf76
250	79	11	0.00	concluido	2024-11-07 16:27:53.904+00	0	a2704be0-87e8-43d9-a12a-697c08477239
267	87	2	0.00	concluido	2024-11-07 23:10:24.144+00	0	cc60c0ed-f72f-464d-bfd2-c97c5740c759
260	84	14	0.00	concluido	2024-11-26 15:24:26.41+00	0	56f6477b-0341-4ed4-b7e0-d73bb5f23bd3
261	86	1	0.00	concluido	2024-11-10 22:30:57.396+00	1	3b1e5986-a8ae-4775-b0b2-02d7c5639346
252	82	2	0.00	concluido	2024-11-26 16:44:32.645+00	0	87c5f7be-8fd9-409f-b44d-9327921b8061
265	86	14	0.00	concluido	2024-11-11 09:43:55.673+00	0	b66fa752-7915-455b-85e1-ce9456bd95b6
258	84	3	0.00	concluido	2024-11-16 10:08:27.863+00	0	74284147-7f3d-4a5a-a2c5-1ebd083213a5
269	87	4	0.00	concluido	2024-11-07 22:23:55.869+00	0	714f8029-d860-47b1-bef9-086ab2a93996
270	87	14	0.00	concluido	2024-11-09 16:56:24.469+00	0	2ef7bf77-f796-4cae-aa31-b32c0a941ebf
291	88	4	0.00	iniciado	\N	0	\N
292	95	3	0.00	concluido	2026-08-29 02:35:10.775+00	1	e17aeb6f-9478-43be-9e5b-cd5ed9076628
293	95	4	0.00	concluido	2026-08-29 03:03:08.125+00	2	011ee739-895c-456e-96c9-15682f086abe
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (id, username, senha, role, email, nome, sobrenome, endereco, cidade, pais, cep, cod_rec, empresa, empresa_id) FROM stdin;
2	Admin	@desenho1977	Admin	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N
44	VOROSADV	$2b$10$YqFEdaCip1gDRylSgxqiZuYnhI9/SpvKh/5gmp6WLVkxWJm0/DKQy	Aluno	voros@adv.oabsp.org.br	CRISTIANO	VOROS	\N	\N	\N	\N	\N	\N	\N
45	Cassiano	$2b$10$Tqjf.LW7bSNGSbSNfhurQees1gkDDSLsd.6SI22dcxyF6ybQpk1oW	Aluno	cpgrejo@hotmail.com	Cassiano	Grejo	\N	\N	\N	\N	\N	\N	\N
95	aluno1_teste	$2a$10$7Yr9GvXqiHgldDBelG9JP.p0SDs778uRWypaXdB4a73yjgNn9v/Ta	Aluno	aluno1@testeacesso.com	João	Um	\N	\N	\N	\N	\N	Empresa Teste Acesso Total	\N
49	EduardoMGoncales	$2b$10$1hkOGiK3cArUS9WHH3LwLue.WLQYyvrKchPHhim2zafLoT2Qqebea	Aluno	eduardomachadogoncales@gmail.com	Eduardo	Machado Gonçales	\N	\N	\N	\N	\N	\N	\N
50	Caio Jordan 	$2b$10$LXRroOWx2zz/jnOsJjBAu.yffp1u/460TjSO70qx.y8SeHJ8Tx4T.	Aluno	caioclj8@gmail.com	Caio 	Jordan 	\N	\N	\N	\N	\N	\N	\N
31	ConnectAdmin	$2b$10$rGw8Jy7ook/zycBxdtru1OvAz8it77sLxhWUaAnznbmOoWZYQ87D2	Admin	conect.fam@gmail.com	Administração 	Connect	\N	\N	\N	\N	\N	\N	\N
41	AmadeuFMATCH  	$2a$10$ETcxnA4DiUaF1sCzut0BJ.Dv2N93m8E9UPd/oMh4nuhfd51L3vjWm	Admin	arsf@connectconsultoria.com.br	Amadeu	Rocha	\N	\N	\N	\N	\N	\N	\N
52	everaldoferreira2024	$2b$10$qFwQcnWoM5/wvjSxSpiAve106pW3ThHRnuMB5Er/WkLqTTIScHRjO	Aluno	everaldoferreira176@gmail.com	everaldo ferreira de souza	ferreira de souza	Rua Pedro Coneglian 47	Lençóis Paulista	Brasil	18680370	\N	\N	\N
87	Rodrigo_Florenciano	$2a$10$8DmzXzNkRgFbLksNvhj.xeSkK3WReOilPF0C6iHJSneqjIp.FrGDO	Aluno	Rodrigo.Florenciano@fmatch.com	Rodrigo	Florenciano Rolon Leal	\N	\N	\N	\N	\N	INPASA AGROINDUSTRIAL S/A	\N
54	FelipeFMATCH	$2a$10$ETcxnA4DiUaF1sCzut0BJ.Dv2N93m8E9UPd/oMh4nuhfd51L3vjWm	Admin	felipe@fmatch.com.br	Felipe	Gilioli	Rua Coronel Álvaro Martins	LENÇÓIS PAULISTA	Brasil	18682-180	\N	\N	\N
88	Rosane_Lima	$2a$10$qbIPTjb5ymEXO4GXtlEuk.2IFQGbUREyVihXQQP0UuvJ3EkKkMkTi	Aluno	Rosane.lima@fmatch.com	Rosane	de Lima Damas	\N	\N	\N	\N	\N	INPASA AGROINDUSTRIAL S/A	\N
89	Edvaldo_Junior	$2a$10$40bZCj4zRfb7X297e0YGgeleEL6RJVwSpvPbP5MMR2MbaOpFDjXWm	Aluno	smarllerjunior@gmail.com	Edvaldo	Junior Fialho	\N	\N	\N	\N	\N	FMATCH TECNOLOGIA LTDA	\N
90	Michael_Henrique	$2a$10$/gJXmZrH7mlQmjnsz2Dz9OHIJOuew2oQUE6wt0ndah5wRH92mrUU6	Aluno	toko.henrique.127@gmail.com	Michael Henrique	 dos Santos	\N	\N	\N	\N	\N	FMATCH TECNOLOGIA LTDA	\N
58	RROSAOLIVEIRA	$2b$10$aIePW6Rh9ZBoZ/x2Gym4u./lO78x2aYabMBQlMHg7L/ar4yGUzFma	Aluno	rrosaoliveira@gmail.com	Renato	Oliveira 	\N	\N	\N	\N	\N	\N	\N
96	aluno2_teste	$2a$10$fRzj2k3Ze9P3YdAav2qusOm1CHp736Myv9H5d7ageIaCg9qf3qunG	Aluno	aluno2@testeacesso.com	Maria	Dois	\N	\N	\N	\N	\N	Empresa Teste Acesso Total	\N
78	testemms	$2a$10$nnhawQzk8gobVcF5Ooa5YOLJnWWPJgOVrlfsptwK.OE4w5KrmC8W6	Aluno	usuario@semempresa.com	usuario	semempresa	\N	\N	\N	\N	\N	\N	\N
79	Amadeu_Aluno	$2a$10$3y9kT0RHxoC6znxIPCIXHuNG86xmIMwK/UyXmInFSfCFA0XwhikT6	Aluno	amadeu.aluno@fmatch.com	Amadeu	Rocha	\N	\N	\N	\N	\N	FMATCH TECNOLOGIA LTDA	\N
80	teste@fmatch.com	$2a$10$CiQeIZsCLesZF3CaXPtIkeQsEhY1RDyXWarM4.xZ/TZCLbHtRb2Zq	Aluno	teste@fmatch.com	teste	teste123	\N	\N	\N	\N	\N	TesteFmatch	\N
91	Gabriel_Batista	$2a$10$ZWqz5qGP0ildbpzfKgVFGONPHLrTZdnQh9e3YRjpUGyw9NsOvyYWm	Aluno	gabriel-gbg44@hotmail.com	Gabriel Batista 	Geronymo	\N	\N	\N	\N	\N	FMATCH TECNOLOGIA LTDA	\N
81	Mmstrok_.	$2a$10$OPzcDw7uR65yh/Axbg3sLeBBs7mcM0fEitLCSr1P8SLqkxbj6OjMe	Aluno	gtaresidentevil2009@gmail.com	Matheus 	Santos	\N	\N	\N	\N	\N	\N	\N
92	Trste	$2a$10$fsHMPkwbUc0ZZm5zKqLfG.B4uT3aJnh7SatB1ze7Sd.LWQ7oqK9J.	Aluno	suustrok@gmail.com	Mathud	Sabtos	\N	\N	\N	\N	\N	\N	\N
82	Alexandre_Jose	$2a$10$6EfL/p73CUlhXZH/aa.VYujfrszc.8Xlo.2ArY9qPpBjS5gJfNckO	Aluno	alexandre.jose@fmatch.com	Alexandre	José Nogueira	\N	\N	\N	\N	\N	INPASA AGROINDUSTRIAL S/A	\N
84	Jose_Sergio	$2a$10$FPrVg0CI1onuom0Nvj92KeZRArFVnxSxpf7X5jW0I4FoV90CEdnEK	Aluno	Jose.Sergio@fmatch.com	Jose	Sergio de Almeida Pacheco	\N	\N	\N	\N	\N	INPASA AGROINDUSTRIAL S/A	\N
85	Patrick_Alisson	$2a$10$5C0m0nqvjGNErGJ0etOFWei8qpzXCd0Iu.UuT8hBs4H/ovw5jGbIe	Aluno	Patrick.alisson@fmatch.com	Patrick	Alisson Duarte Barreiro	\N	\N	\N	\N	\N	INPASA AGROINDUSTRIAL S/A	\N
86	Paulo_Rafael	$2a$10$dj9jF5VrGK.Y26acGjUVNehkAo/XRCUVc.g1Q4WfVSjxMumoa9TbS	Aluno	Paulo.Rafael@fmatch.com	Paulo	Rafael Antunes Ajala	\N	\N	\N	\N	\N	INPASA AGROINDUSTRIAL S/A	\N
93	Pelirfe	$2a$10$b1p/EY7Z8qi53KlO.CbanOFPyTS5j.Sq.r3vvEwSmfcwsZwYPtfD.	Aluno	f_galves@yahoo.com.br	Felipe	Gilioli	\N	\N	\N	\N	\N	\N	\N
94	Tralli	$2a$10$oLPVAdCjYl6dXN1/Mhndge/Q8YoZQnWCJYUYiSue7k8xmzKhhIV1.	Aluno	carlos.tralli@usinasantafe.com.br	Carlos Fabiano	Tralli	\N	\N	\N	\N	\N	\N	\N
56	MatheusFMATCH	$2a$10$/PsvOGZ0wr1Wm0uS3jGKgOTXGTEBRYnsQsTAo8WZQvomncrN4/C8G	Admin	miguel.matheus@hotmail.com	\N	\N	\N	\N	\N	\N	\N	\N	\N
97	aluno3_teste	$2a$10$BUliEttQjUhx/TlJrzzlu.021R1iJ3YWHv1TYwJXUUEUbHqdYLYZS	Aluno	aluno3@testeacesso.com	Pedro	Tres	\N	\N	\N	\N	\N	Empresa Teste Acesso Total	\N
99	marcos.santos	$2a$10$iEM0d.M8DGGR1E2TTk4IcuwdHHrhYKLJk28PUH37kbu8k/vvv4EFS	Aluno	marcostenebra.2@gmail.com	Marcos	Adriano Magalhães dos Santos	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
100	alexsandro.chaves	$2a$10$oCXXYOsDff5XSVTQ3Yw/..g4ChKq/BnIUqF9B2hdP96/yHMpV9Xq.	Aluno	chavesalexsandro349@gmail.com	Alexsandro	Chaves	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
101	gabriel.leite	$2a$10$Nman9N7CBz0K8xvOJM43OOEMyZ/StImY.brdinlQPXV23h/0XBDBa	Aluno	gabrielfodex2004@gmail.com	Gabriel	da Silva Leite	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
102	jefferson.santos	$2a$10$uUqypYhJTqN/vB90H0EeXOzriOqN/tujwS9Z0mMVzNgugxKnzOkt6	Aluno	jeffersilsantos@gmail.com	Jefferson	Silva dos Santos	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
103	matheus.oliveira	$2a$10$1RJ.L8zCV/JMGjho8GVJeOvTK5TlcHj.DwJRqT.mB9tTSr8cUN8B.	Aluno	matheuscamposs7@gmail.com	Matheus	Campos Conde de Oliveira	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
104	otavio.silva	$2a$10$PHxpZQrRbKn2wGQ3ygtFuuHMlAwtn27Vcs7YhS305yIwlsju/qihW	Aluno	otavio17jacson19@gmail.com	Otavio	Jacson Alfredo da Silva	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
105	patrick.ribeiro	$2a$10$Qukp4/gOnvglDmVuLKWWm.MOigGhS.mEtrGxCX8bmt/wg8dIasFai	Aluno	patrickteles2016@gmail.com	Patrick	Teodoro Teles Ribeiro	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
106	ronald.santos	$2a$10$GeId/DRgQQTsXnmAw6//5ufvQogubosVJy4MZwZs85bkk4gFIgEiy	Aluno	ronaldsantos040903@gmail.com	Ronald	Pedro Ferreira dos Santos	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
107	ryan.silva	$2a$10$IJ5e8RuZEZO7eU.VSJi.cOttsZH4NSK8h0Mc2FKX0ifyFGoUyYmV2	Aluno	ryanamario429@gmail.com	Ryan	Amario da Silva	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
108	abel.junior	$2a$10$qp/Ew0kuRkhUlxARbEOf/.e0vqq/o/Z6.JfPYW.pPXhAwDxr6G9Me	Aluno	junioramariodasilva@gmail.com	Abel	Antonio da Silva Junior	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
98	jose.baron	$2a$10$mSRAhTQ7HNTM6PrARy4p7OtlQDKyHpPHye2b6Y/tE4rSfn2tgDSaq	Aluno	jose.baron@grupozambianco.com.br	Jose	Pedro Baron Junior	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
109	joao.boni	$2a$10$VKYpLA2W4ztA4ix/7Cxs1OVSnC111nOKYPeZ6/jlg8dHhe6DufLgi	Aluno	joaopaulomilaniboni@gmail.com	Joao	Paulo Milani Boni	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
110	robson.augusto	$2a$10$B/YuyGRgm.TdA6sfb/bNiOO10dxkrqUE57MGtJXaqb9tcEMVWiqkq	Aluno	augustorobson621@gmail.com	Robson	Aparecido Augusto	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
111	willian.goncalves	$2a$10$bKHU2bdv5DE/Eh3x96HU2OphpL2m8tTzuh0f5uH0Z8RzFFG.hqE9G	Aluno	willianparis834@gmail.com	Willian	Paris Gonçalves	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
112	ruan.souza	$2a$10$chVE9gMLM9AtRCyq5uVu3OfHkWRJ72SyqB.iy6bfuY35Iet/WwHjO	Aluno	ruanpablons.souza@gmail.com	Ruan	Pablo Nascimento de Souza	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
113	iury.silva	$2a$10$427fLF.rDkXuxKUrbRFGDeb7/fhApr3jnsD/EMW8EFdjFyoR97CYm	Aluno	augustoiury969@gmail.com	Iury	Augusto Silva	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
114	barbara.lima	$2a$10$QhCPRPRS6PrjvZ7HbK/bye1MOT5XncdX5UaJengJNTGnMNp40CLgS	Aluno	barbaradiomar@hotmail.com	Barbara	Diomar Silva de Lima	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
115	steffany.rocha	$2a$10$4S.FaNAYu8PNqQLKYr2SZulmJUIAGY3ydQ92/zlubN.A5d.GGaixy	Aluno	steffanygabrielle47@gmail.com	Steffany	Gabrielle Silveira Rocha	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
116	gelton.pereira	$2a$10$1g2IZMbem6pLNo8SXaCX2OgH.ONwlKkGLozyeqJD5OjMOQqvT1K4O	Aluno	gelton.silvasp@gmail.com	Gelton	da Silva Pereira	\N	\N	\N	\N	\N	Guilherme - GRUPO ZAMBIANCO	\N
\.


--
-- Name: Courses_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public."Courses_id_seq"', 1, false);


--
-- Name: aulas_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.aulas_id_seq', 29, true);


--
-- Name: avaliacoes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.avaliacoes_id_seq', 134, true);


--
-- Name: compras_cursos_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.compras_cursos_id_seq', 986, true);


--
-- Name: cursos_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.cursos_id_seq', 14, true);


--
-- Name: empresas_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.empresas_id_seq', 13, true);


--
-- Name: historico_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.historico_id_seq', 407, true);


--
-- Name: progresso_cursos_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.progresso_cursos_id_seq', 293, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.users_id_seq', 116, true);


--
-- Name: Courses Courses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."Courses"
    ADD CONSTRAINT "Courses_pkey" PRIMARY KEY (id);


--
-- Name: aulas aulas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aulas
    ADD CONSTRAINT aulas_pkey PRIMARY KEY (id);


--
-- Name: avaliacoes avaliacoes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.avaliacoes
    ADD CONSTRAINT avaliacoes_pkey PRIMARY KEY (id);


--
-- Name: cnpj_tentativas cnpj_tentativas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cnpj_tentativas
    ADD CONSTRAINT cnpj_tentativas_pkey PRIMARY KEY (cnpj);


--
-- Name: compras_cursos compras_cursos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compras_cursos
    ADD CONSTRAINT compras_cursos_pkey PRIMARY KEY (id);


--
-- Name: cursos cursos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cursos
    ADD CONSTRAINT cursos_pkey PRIMARY KEY (id);


--
-- Name: empresas empresas_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.empresas
    ADD CONSTRAINT empresas_email_key UNIQUE (email);


--
-- Name: empresas empresas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.empresas
    ADD CONSTRAINT empresas_pkey PRIMARY KEY (id);


--
-- Name: historico historico_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.historico
    ADD CONSTRAINT historico_pkey PRIMARY KEY (id);


--
-- Name: progresso_cursos progresso_cursos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.progresso_cursos
    ADD CONSTRAINT progresso_cursos_pkey PRIMARY KEY (id);


--
-- Name: historico unique_compra_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.historico
    ADD CONSTRAINT unique_compra_id UNIQUE (compra_id);


--
-- Name: progresso_cursos unique_user_curso; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.progresso_cursos
    ADD CONSTRAINT unique_user_curso UNIQUE (user_id, curso_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: aulas aulas_curso_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aulas
    ADD CONSTRAINT aulas_curso_id_fkey FOREIGN KEY (curso_id) REFERENCES public.cursos(id);


--
-- Name: avaliacoes avaliacoes_curso_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.avaliacoes
    ADD CONSTRAINT avaliacoes_curso_id_fkey FOREIGN KEY (curso_id) REFERENCES public.cursos(id);


--
-- Name: compras_cursos compras_cursos_curso_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compras_cursos
    ADD CONSTRAINT compras_cursos_curso_id_fkey FOREIGN KEY (curso_id) REFERENCES public.cursos(id);


--
-- Name: compras_cursos compras_cursos_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compras_cursos
    ADD CONSTRAINT compras_cursos_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: historico historico_curso_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.historico
    ADD CONSTRAINT historico_curso_id_fkey FOREIGN KEY (curso_id) REFERENCES public.cursos(id);


--
-- Name: progresso_cursos progresso_cursos_curso_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.progresso_cursos
    ADD CONSTRAINT progresso_cursos_curso_id_fkey FOREIGN KEY (curso_id) REFERENCES public.cursos(id);


--
-- Name: progresso_cursos progresso_cursos_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.progresso_cursos
    ADD CONSTRAINT progresso_cursos_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: users users_empresa_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_empresa_id_fkey FOREIGN KEY (empresa_id) REFERENCES public.empresas(id);


--
-- PostgreSQL database dump complete
--

\unrestrict NnOsueo89e0pQRp7cSSvqLANFOVbO0D3jW6J2Z8Rgn8d25SBS0zrCG8eAXOMfD2

