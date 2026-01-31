const { Pool } = require('pg');

// Configurar conexão com PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Criar tabelas
const createTables = async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Tabela de usuários
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        reset_token VARCHAR(255),
        reset_token_expires BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de contas
    await client.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        currency VARCHAR(3) NOT NULL,
        balance DECIMAL(15, 2) DEFAULT 0,
        is_emergency_fund BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de categorias
    await client.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        color VARCHAR(7),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de fontes de renda
    await client.query(`
      CREATE TABLE IF NOT EXISTS income_sources (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de transações
    await client.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
        category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
        income_source_id INTEGER REFERENCES income_sources(id) ON DELETE SET NULL,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(15, 2) NOT NULL,
        description TEXT,
        date DATE NOT NULL,
        is_recurring BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de operações de câmbio
    await client.query(`
      CREATE TABLE IF NOT EXISTS exchange_operations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        from_account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
        to_account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
        from_amount DECIMAL(15, 2) NOT NULL,
        to_amount DECIMAL(15, 2) NOT NULL,
        from_currency VARCHAR(3) NOT NULL,
        to_currency VARCHAR(3) NOT NULL,
        exchange_rate DECIMAL(10, 6) NOT NULL,
        date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ========== NOVAS TABELAS ==========

    // Tabela de metas financeiras
    await client.query(`
      CREATE TABLE IF NOT EXISTS financial_goals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        target_amount DECIMAL(15, 2) NOT NULL,
        current_amount DECIMAL(15, 2) DEFAULT 0,
        currency VARCHAR(3) NOT NULL DEFAULT 'BRL',
        deadline DATE,
        category VARCHAR(100),
        status VARCHAR(50) DEFAULT 'in_progress',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de investimentos
    await client.query(`
      CREATE TABLE IF NOT EXISTS investments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(100) NOT NULL,
        amount DECIMAL(15, 2) NOT NULL,
        current_value DECIMAL(15, 2) NOT NULL,
        currency VARCHAR(3) NOT NULL,
        purchase_date DATE NOT NULL,
        broker VARCHAR(255),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de ativos
    await client.query(`
      CREATE TABLE IF NOT EXISTS assets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(100) NOT NULL,
        value DECIMAL(15, 2) NOT NULL,
        currency VARCHAR(3) NOT NULL,
        purchase_date DATE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de passivos (dívidas)
    await client.query(`
      CREATE TABLE IF NOT EXISTS liabilities (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(100) NOT NULL,
        amount DECIMAL(15, 2) NOT NULL,
        interest_rate DECIMAL(5, 2),
        due_date DATE,
        monthly_payment DECIMAL(15, 2),
        currency VARCHAR(3) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de transações recorrentes
    await client.query(`
      CREATE TABLE IF NOT EXISTS recurring_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
        category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(15, 2) NOT NULL,
        description TEXT,
        frequency VARCHAR(50) NOT NULL,
        next_date DATE NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de orçamentos
    await client.query(`
      CREATE TABLE IF NOT EXISTS budgets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        category_id INTEGER REFERENCES categories(id) ON DELETE CASCADE,
        month INTEGER NOT NULL,
        year INTEGER NOT NULL,
        limit_amount DECIMAL(15, 2) NOT NULL,
        currency VARCHAR(3) NOT NULL DEFAULT 'BRL',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, category_id, month, year, currency)
      )
    `);

    // Tabela de conquistas
    await client.query(`
      CREATE TABLE IF NOT EXISTS achievements (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        achievement_type VARCHAR(100) NOT NULL,
        unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        streak_count INTEGER DEFAULT 0
      )
    `);

    // Tabela de snapshots financeiros mensais
    await client.query(`
      CREATE TABLE IF NOT EXISTS financial_snapshots (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        month INTEGER NOT NULL,
        year INTEGER NOT NULL,
        total_assets DECIMAL(15, 2) DEFAULT 0,
        total_liabilities DECIMAL(15, 2) DEFAULT 0,
        net_worth DECIMAL(15, 2) DEFAULT 0,
        total_income DECIMAL(15, 2) DEFAULT 0,
        total_expenses DECIMAL(15, 2) DEFAULT 0,
        savings_rate DECIMAL(5, 2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, month, year)
      )
    `);

    await client.query('COMMIT');
    console.log('✅ Tabelas criadas com sucesso!');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Erro ao criar tabelas:', error);
    throw error;
  } finally {
    client.release();
  }
};

// Inserir dados iniciais para um novo usuário
const insertInitialData = async (userId) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Criar contas padrão
    const accountsResult = await client.query(`
      INSERT INTO accounts (user_id, name, type, currency, balance)
      VALUES 
        ($1, 'Conta Corrente BRL', 'checking', 'BRL', 0),
        ($1, 'Poupança BRL', 'savings', 'BRL', 0),
        ($1, 'Conta EUR', 'checking', 'EUR', 0)
      RETURNING id
    `, [userId]);

    // Criar categorias padrão
    await client.query(`
      INSERT INTO categories (user_id, name, type, color)
      VALUES 
        ($1, 'Salário', 'income', '#10b981'),
        ($1, 'Freelance', 'income', '#3b82f6'),
        ($1, 'Investimentos', 'income', '#8b5cf6'),
        ($1, 'Alimentação', 'expense', '#ef4444'),
        ($1, 'Transporte', 'expense', '#f59e0b'),
        ($1, 'Moradia', 'expense', '#8b5cf6'),
        ($1, 'Saúde', 'expense', '#06b6d4'),
        ($1, 'Educação', 'expense', '#3b82f6'),
        ($1, 'Lazer', 'expense', '#ec4899'),
        ($1, 'Seguros', 'expense', '#6366f1'),
        ($1, 'Outros', 'expense', '#64748b')
    `, [userId]);

    // Criar fontes de renda padrão
    await client.query(`
      INSERT INTO income_sources (user_id, name, description)
      VALUES 
        ($1, 'Empresa Principal', 'Salário mensal'),
        ($1, 'Freelance', 'Trabalhos extras'),
        ($1, 'Investimentos', 'Dividendos e rendimentos')
    `, [userId]);

    await client.query('COMMIT');
    console.log('✅ Dados iniciais inseridos para usuário:', userId);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Erro ao inserir dados iniciais:', error);
    throw error;
  } finally {
    client.release();
  }
};

module.exports = {
  pool,
  createTables,
  insertInitialData
};
