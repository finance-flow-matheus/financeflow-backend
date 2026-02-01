
-- Script de Criação do Banco de Dados FinanceFlow
-- Execute este script no console SQL do seu Railway Postgres

-- 1. Tabela de Usuários
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabela de Contas
CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    currency VARCHAR(3) NOT NULL CHECK (currency IN ('BRL', 'EUR')),
    balance DECIMAL(15, 2) DEFAULT 0.00,
    is_investment BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Tabela de Categorias
CREATE TABLE categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('INCOME', 'EXPENSE'))
);

-- 4. Tabela de Fontes de Renda
CREATE TABLE income_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL
);

-- 5. Tabela de Transações
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    category_id UUID REFERENCES categories(id),
    income_source_id UUID REFERENCES income_sources(id),
    description TEXT NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    date DATE NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('INCOME', 'EXPENSE')),
    is_fixed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Tabela de Operações de Câmbio/Transferência
CREATE TABLE exchange_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    source_account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    destination_account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    source_amount DECIMAL(15, 2) NOT NULL,
    destination_amount DECIMAL(15, 2) NOT NULL,
    date DATE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Tabela de Orçamentos (Budgets)
CREATE TABLE budgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL, -- Pode ser ID de categoria ou fonte
    entity_type VARCHAR(10) CHECK (entity_type IN ('category', 'source')),
    amount DECIMAL(15, 2) NOT NULL,
    currency VARCHAR(3) NOT NULL CHECK (currency IN ('BRL', 'EUR'))
);

-- 8. Tabela de Metas (Goals)
CREATE TABLE goals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    account_id UUID REFERENCES accounts(id),
    name VARCHAR(255) NOT NULL,
    target_amount DECIMAL(15, 2) NOT NULL,
    deadline DATE,
    category VARCHAR(50) CHECK (category IN ('travel', 'house', 'emergency', 'car', 'education', 'other'))
);

-- 9. Tabela de Bens e Ativos Físicos (Assets)
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    value DECIMAL(15, 2) NOT NULL,
    currency VARCHAR(3) NOT NULL CHECK (currency IN ('BRL', 'EUR')),
    category VARCHAR(50) CHECK (category IN ('property', 'vehicle', 'jewelry', 'equipment', 'other'))
);

-- 10. Tabela de Passivos/Dívidas (Liabilities)
CREATE TABLE liabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    currency VARCHAR(3) NOT NULL CHECK (currency IN ('BRL', 'EUR')),
    category VARCHAR(50) CHECK (category IN ('loan', 'credit_card', 'mortgage', 'other'))
);
