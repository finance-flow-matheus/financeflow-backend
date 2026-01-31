require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { pool, createTables, insertInitialData } = require('./database');
const { 
  hashPassword, 
  comparePassword, 
  generateToken, 
  authMiddleware,
  sendPasswordResetEmail,
  generateResetToken 
} = require('./auth');

const app = express();
const PORT = process.env.PORT || 3001;

// Middlewares
app.use(cors());
app.use(bodyParser.json());

// Inicializar banco de dados
createTables().catch(console.error);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'FinanceFlow API is running' });
});

// ==================== AUTH ====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Verificar se email já existe
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    // Hash da senha
    const hashedPassword = await hashPassword(password);
    
    // Criar usuário
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id',
      [name, email, hashedPassword]
    );
    const userId = result.rows[0].id;
    
    // Criar dados iniciais
    await insertInitialData(userId);
    
    // Gerar token
    const token = generateToken(userId);
    
    res.json({ token, user: { id: userId, name, email } });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    const isValid = await comparePassword(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    const token = generateToken(user.id);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro ao fazer login' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (user) {
      const resetToken = generateResetToken();
      const expiresAt = Date.now() + 3600000; // 1 hora
      
      await pool.query(
        'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
        [resetToken, expiresAt, user.id]
      );
      
      await sendPasswordResetEmail(email, resetToken);
    }
    
    res.json({ message: 'Se o email existir, você receberá instruções de recuperação' });
  } catch (error) {
    console.error('Erro ao solicitar reset:', error);
    res.status(500).json({ error: 'Erro ao processar solicitação' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    const result = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > $2',
      [token, Date.now()]
    );
    const user = result.rows[0];
    
    if (!user) {
      return res.status(400).json({ error: 'Token inválido ou expirado' });
    }

    const hashedPassword = await hashPassword(newPassword);
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [hashedPassword, user.id]
    );
    
    res.json({ message: 'Senha redefinida com sucesso' });
  } catch (error) {
    console.error('Erro ao redefinir senha:', error);
    res.status(500).json({ error: 'Erro ao redefinir senha' });
  }
});

// ==================== ACCOUNTS ====================
app.get('/api/accounts', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM accounts WHERE user_id = $1 ORDER BY created_at', [req.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar contas:', error);
    res.status(500).json({ error: 'Erro ao buscar contas' });
  }
});

app.post('/api/accounts', authMiddleware, async (req, res) => {
  try {
    const { name, type, currency, balance } = req.body;
    const accountType = type || 'checking'; // Valor padrão: checking
    const result = await pool.query(
      'INSERT INTO accounts (user_id, name, type, currency, balance) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.userId, name, accountType, currency, balance || 0]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar conta:', error);
    res.status(500).json({ error: 'Erro ao criar conta' });
  }
});

app.put('/api/accounts/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, currency } = req.body;
    const result = await pool.query(
      'UPDATE accounts SET name = $1, type = $2, currency = $3 WHERE id = $4 AND user_id = $5 RETURNING *',
      [name, type, currency, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Conta não encontrada' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar conta:', error);
    res.status(500).json({ error: 'Erro ao atualizar conta' });
  }
});

app.delete('/api/accounts/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM accounts WHERE id = $1 AND user_id = $2', [id, req.userId]);
    res.json({ message: 'Conta deletada com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar conta:', error);
    res.status(500).json({ error: 'Erro ao deletar conta' });
  }
});

// ==================== CATEGORIES ====================
app.get('/api/categories', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM categories WHERE user_id = $1 ORDER BY name', [req.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar categorias:', error);
    res.status(500).json({ error: 'Erro ao buscar categorias' });
  }
});

app.post('/api/categories', authMiddleware, async (req, res) => {
  try {
    const { name, type, color } = req.body;
    const result = await pool.query(
      'INSERT INTO categories (user_id, name, type, color) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.userId, name, type, color]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar categoria:', error);
    res.status(500).json({ error: 'Erro ao criar categoria' });
  }
});

app.put('/api/categories/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, color } = req.body;
    const result = await pool.query(
      'UPDATE categories SET name = $1, type = $2, color = $3 WHERE id = $4 AND user_id = $5 RETURNING *',
      [name, type, color, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Categoria não encontrada' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar categoria:', error);
    res.status(500).json({ error: 'Erro ao atualizar categoria' });
  }
});

app.delete('/api/categories/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM categories WHERE id = $1 AND user_id = $2', [id, req.userId]);
    res.json({ message: 'Categoria deletada com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar categoria:', error);
    res.status(500).json({ error: 'Erro ao deletar categoria' });
  }
});

// ==================== INCOME SOURCES ====================
app.get('/api/income-sources', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM income_sources WHERE user_id = $1 ORDER BY name', [req.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar fontes:', error);
    res.status(500).json({ error: 'Erro ao buscar fontes de renda' });
  }
});

app.post('/api/income-sources', authMiddleware, async (req, res) => {
  try {
    const { name, description } = req.body;
    const result = await pool.query(
      'INSERT INTO income_sources (user_id, name, description) VALUES ($1, $2, $3) RETURNING *',
      [req.userId, name, description]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar fonte:', error);
    res.status(500).json({ error: 'Erro ao criar fonte de renda' });
  }
});

app.put('/api/income-sources/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description } = req.body;
    const result = await pool.query(
      'UPDATE income_sources SET name = $1, description = $2 WHERE id = $3 AND user_id = $4 RETURNING *',
      [name, description, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Fonte não encontrada' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar fonte:', error);
    res.status(500).json({ error: 'Erro ao atualizar fonte de renda' });
  }
});

app.delete('/api/income-sources/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM income_sources WHERE id = $1 AND user_id = $2', [id, req.userId]);
    res.json({ message: 'Fonte deletada com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar fonte:', error);
    res.status(500).json({ error: 'Erro ao deletar fonte de renda' });
  }
});

// ==================== TRANSACTIONS ====================
app.get('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM transactions WHERE user_id = $1 ORDER BY date DESC, created_at DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar transações:', error);
    res.status(500).json({ error: 'Erro ao buscar transações' });
  }
});

app.post('/api/transactions', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { accountId, categoryId, incomeSourceId, type, amount, description, date } = req.body;
    
    // Inserir transação
    const result = await client.query(
      'INSERT INTO transactions (user_id, account_id, category_id, income_source_id, type, amount, description, date) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.userId, accountId, categoryId, incomeSourceId, type, amount, description, date]
    );
    
    // Atualizar saldo da conta
    const balanceChange = type === 'income' ? amount : -amount;
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [balanceChange, accountId, req.userId]
    );
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao criar transação:', error);
    res.status(500).json({ error: 'Erro ao criar transação' });
  } finally {
    client.release();
  }
});

app.put('/api/transactions/:id', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    const { accountId, categoryId, incomeSourceId, type, amount, description, date } = req.body;
    
    // Buscar transação antiga
    const oldTx = await client.query('SELECT * FROM transactions WHERE id = $1 AND user_id = $2', [id, req.userId]);
    if (oldTx.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Transação não encontrada' });
    }
    
    const old = oldTx.rows[0];
    
    // Reverter saldo antigo
    const oldBalanceChange = old.type === 'income' ? -old.amount : old.amount;
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [oldBalanceChange, old.account_id, req.userId]
    );
    
    // Atualizar transação
    const result = await client.query(
      'UPDATE transactions SET account_id = $1, category_id = $2, income_source_id = $3, type = $4, amount = $5, description = $6, date = $7 WHERE id = $8 AND user_id = $9 RETURNING *',
      [accountId, categoryId, incomeSourceId, type, amount, description, date, id, req.userId]
    );
    
    // Aplicar novo saldo
    const newBalanceChange = type === 'income' ? amount : -amount;
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [newBalanceChange, accountId, req.userId]
    );
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao atualizar transação:', error);
    res.status(500).json({ error: 'Erro ao atualizar transação' });
  } finally {
    client.release();
  }
});

app.delete('/api/transactions/:id', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Buscar transação
    const result = await client.query('SELECT * FROM transactions WHERE id = $1 AND user_id = $2', [id, req.userId]);
    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Transação não encontrada' });
    }
    
    const transaction = result.rows[0];
    
    // Reverter saldo
    const balanceChange = transaction.type === 'income' ? -transaction.amount : transaction.amount;
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [balanceChange, transaction.account_id, req.userId]
    );
    
    // Deletar transação
    await client.query('DELETE FROM transactions WHERE id = $1 AND user_id = $2', [id, req.userId]);
    
    await client.query('COMMIT');
    res.json({ message: 'Transação deletada com sucesso' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao deletar transação:', error);
    res.status(500).json({ error: 'Erro ao deletar transação' });
  } finally {
    client.release();
  }
});

// ==================== EXCHANGES ====================
app.get('/api/exchanges', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM exchange_operations WHERE user_id = $1 ORDER BY date DESC, created_at DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar câmbios:', error);
    res.status(500).json({ error: 'Erro ao buscar operações de câmbio' });
  }
});

app.post('/api/exchanges', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { fromAccountId, toAccountId, fromAmount, toAmount, fromCurrency, toCurrency, exchangeRate, date } = req.body;
    
    // Inserir operação de câmbio
    const result = await client.query(
      'INSERT INTO exchange_operations (user_id, from_account_id, to_account_id, from_amount, to_amount, from_currency, to_currency, exchange_rate, date) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
      [req.userId, fromAccountId, toAccountId, fromAmount, toAmount, fromCurrency, toCurrency, exchangeRate, date]
    );
    
    // Atualizar saldos
    await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND user_id = $3',
      [fromAmount, fromAccountId, req.userId]
    );
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [toAmount, toAccountId, req.userId]
    );
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao criar câmbio:', error);
    res.status(500).json({ error: 'Erro ao criar operação de câmbio' });
  } finally {
    client.release();
  }
});

app.put('/api/exchanges/:id', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    const { fromAccountId, toAccountId, fromAmount, toAmount, fromCurrency, toCurrency, exchangeRate, date } = req.body;
    
    // Buscar operação antiga para reverter saldos
    const oldResult = await client.query('SELECT * FROM exchange_operations WHERE id = $1 AND user_id = $2', [id, req.userId]);
    if (oldResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Operação não encontrada' });
    }
    
    const oldExchange = oldResult.rows[0];
    
    // Reverter saldos antigos
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [oldExchange.from_amount, oldExchange.from_account_id, req.userId]
    );
    await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND user_id = $3',
      [oldExchange.to_amount, oldExchange.to_account_id, req.userId]
    );
    
    // Atualizar operação
    const result = await client.query(
      'UPDATE exchange_operations SET from_account_id = $1, to_account_id = $2, from_amount = $3, to_amount = $4, from_currency = $5, to_currency = $6, exchange_rate = $7, date = $8 WHERE id = $9 AND user_id = $10 RETURNING *',
      [fromAccountId, toAccountId, fromAmount, toAmount, fromCurrency, toCurrency, exchangeRate, date, id, req.userId]
    );
    
    // Aplicar novos saldos
    await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND user_id = $3',
      [fromAmount, fromAccountId, req.userId]
    );
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [toAmount, toAccountId, req.userId]
    );
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao atualizar câmbio:', error);
    res.status(500).json({ error: 'Erro ao atualizar operação de câmbio' });
  } finally {
    client.release();
  }
});

app.delete('/api/exchanges/:id', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Buscar operação
    const result = await client.query('SELECT * FROM exchange_operations WHERE id = $1 AND user_id = $2', [id, req.userId]);
    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Operação não encontrada' });
    }
    
    const exchange = result.rows[0];
    
    // Reverter saldos
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2 AND user_id = $3',
      [exchange.from_amount, exchange.from_account_id, req.userId]
    );
    await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND user_id = $3',
      [exchange.to_amount, exchange.to_account_id, req.userId]
    );
    
    // Deletar operação
    await client.query('DELETE FROM exchange_operations WHERE id = $1 AND user_id = $2', [id, req.userId]);
    
    await client.query('COMMIT');
    res.json({ message: 'Operação deletada com sucesso' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao deletar câmbio:', error);
    res.status(500).json({ error: 'Erro ao deletar operação de câmbio' });
  } finally {
    client.release();
  }
});

// ==================== FINANCIAL GOALS ====================
app.get('/api/goals', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM financial_goals WHERE user_id = $1 ORDER BY deadline',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar metas:', error);
    res.status(500).json({ error: 'Erro ao buscar metas' });
  }
});

app.post('/api/goals', authMiddleware, async (req, res) => {
  try {
    const { name, targetAmount, currentAmount, deadline, category } = req.body;
    const result = await pool.query(
      'INSERT INTO financial_goals (user_id, name, target_amount, current_amount, deadline, category) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.userId, name, targetAmount, currentAmount || 0, deadline, category]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar meta:', error);
    res.status(500).json({ error: 'Erro ao criar meta' });
  }
});

app.put('/api/goals/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, targetAmount, currentAmount, deadline, category, status } = req.body;
    const result = await pool.query(
      'UPDATE financial_goals SET name = $1, target_amount = $2, current_amount = $3, deadline = $4, category = $5, status = $6 WHERE id = $7 AND user_id = $8 RETURNING *',
      [name, targetAmount, currentAmount, deadline, category, status, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Meta não encontrada' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar meta:', error);
    res.status(500).json({ error: 'Erro ao atualizar meta' });
  }
});

app.delete('/api/goals/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM financial_goals WHERE id = $1 AND user_id = $2', [id, req.userId]);
    res.json({ message: 'Meta deletada com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar meta:', error);
    res.status(500).json({ error: 'Erro ao deletar meta' });
  }
});

// ==================== INVESTMENTS ====================
app.get('/api/investments', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM investments WHERE user_id = $1 ORDER BY purchase_date DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar investimentos:', error);
    res.status(500).json({ error: 'Erro ao buscar investimentos' });
  }
});

app.post('/api/investments', authMiddleware, async (req, res) => {
  try {
    const { name, type, amount, currentValue, currency, purchaseDate, broker, notes } = req.body;
    const result = await pool.query(
      'INSERT INTO investments (user_id, name, type, amount, current_value, currency, purchase_date, broker, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
      [req.userId, name, type, amount, currentValue || amount, currency, purchaseDate, broker, notes]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar investimento:', error);
    res.status(500).json({ error: 'Erro ao criar investimento' });
  }
});

app.put('/api/investments/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, amount, currentValue, currency, purchaseDate, broker, notes } = req.body;
    const result = await pool.query(
      'UPDATE investments SET name = $1, type = $2, amount = $3, current_value = $4, currency = $5, purchase_date = $6, broker = $7, notes = $8 WHERE id = $9 AND user_id = $10 RETURNING *',
      [name, type, amount, currentValue, currency, purchaseDate, broker, notes, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Investimento não encontrado' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar investimento:', error);
    res.status(500).json({ error: 'Erro ao atualizar investimento' });
  }
});

app.delete('/api/investments/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM investments WHERE id = $1 AND user_id = $2', [id, req.userId]);
    res.json({ message: 'Investimento deletado com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar investimento:', error);
    res.status(500).json({ error: 'Erro ao deletar investimento' });
  }
});

app.get('/api/investments/allocation', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT type, SUM(current_value) as total FROM investments WHERE user_id = $1 GROUP BY type',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar alocação:', error);
    res.status(500).json({ error: 'Erro ao buscar alocação' });
  }
});

// ==================== ASSETS ====================
app.get('/api/assets', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM assets WHERE user_id = $1 ORDER BY created_at DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar ativos:', error);
    res.status(500).json({ error: 'Erro ao buscar ativos' });
  }
});

app.post('/api/assets', authMiddleware, async (req, res) => {
  try {
    const { name, type, value, currency, purchaseDate, description } = req.body;
    const result = await pool.query(
      'INSERT INTO assets (user_id, name, type, value, currency, purchase_date, description) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.userId, name, type, value, currency, purchaseDate, description]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar ativo:', error);
    res.status(500).json({ error: 'Erro ao criar ativo' });
  }
});

app.put('/api/assets/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, value, currency, purchaseDate, description } = req.body;
    const result = await pool.query(
      'UPDATE assets SET name = $1, type = $2, value = $3, currency = $4, purchase_date = $5, description = $6 WHERE id = $7 AND user_id = $8 RETURNING *',
      [name, type, value, currency, purchaseDate, description, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Ativo não encontrado' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar ativo:', error);
    res.status(500).json({ error: 'Erro ao atualizar ativo' });
  }
});

app.delete('/api/assets/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM assets WHERE id = $1 AND user_id = $2', [id, req.userId]);
    res.json({ message: 'Ativo deletado com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar ativo:', error);
    res.status(500).json({ error: 'Erro ao deletar ativo' });
  }
});

// ==================== LIABILITIES ====================
app.get('/api/liabilities', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM liabilities WHERE user_id = $1 ORDER BY due_date',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar passivos:', error);
    res.status(500).json({ error: 'Erro ao buscar passivos' });
  }
});

app.post('/api/liabilities', authMiddleware, async (req, res) => {
  try {
    const { name, type, amount, interestRate, dueDate, monthlyPayment, currency, description } = req.body;
    const result = await pool.query(
      'INSERT INTO liabilities (user_id, name, type, amount, interest_rate, due_date, monthly_payment, currency, description) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
      [req.userId, name, type, amount, interestRate, dueDate, monthlyPayment, currency, description]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar passivo:', error);
    res.status(500).json({ error: 'Erro ao criar passivo' });
  }
});

app.put('/api/liabilities/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, amount, interestRate, dueDate, monthlyPayment, currency, description } = req.body;
    const result = await pool.query(
      'UPDATE liabilities SET name = $1, type = $2, amount = $3, interest_rate = $4, due_date = $5, monthly_payment = $6, currency = $7, description = $8 WHERE id = $9 AND user_id = $10 RETURNING *',
      [name, type, amount, interestRate, dueDate, monthlyPayment, currency, description, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Passivo não encontrado' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar passivo:', error);
    res.status(500).json({ error: 'Erro ao atualizar passivo' });
  }
});

app.delete('/api/liabilities/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM liabilities WHERE id = $1 AND user_id = $2', [id, req.userId]);
    res.json({ message: 'Passivo deletado com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar passivo:', error);
    res.status(500).json({ error: 'Erro ao deletar passivo' });
  }
});

// ==================== BUDGETS ====================
app.get('/api/budgets', authMiddleware, async (req, res) => {
  try {
    const { month, year } = req.query;
    let query = 'SELECT b.*, c.name as category_name, c.color as category_color FROM budgets b LEFT JOIN categories c ON b.category_id = c.id WHERE b.user_id = $1';
    const params = [req.userId];
    
    if (month && year) {
      query += ' AND b.month = $2 AND b.year = $3';
      params.push(month, year);
    }
    
    query += ' ORDER BY c.name';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar orçamentos:', error);
    res.status(500).json({ error: 'Erro ao buscar orçamentos' });
  }
});

app.post('/api/budgets', authMiddleware, async (req, res) => {
  try {
    const { categoryId, month, year, limitAmount } = req.body;
    const result = await pool.query(
      'INSERT INTO budgets (user_id, category_id, month, year, limit_amount) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, category_id, month, year) DO UPDATE SET limit_amount = $5 RETURNING *',
      [req.userId, categoryId, month, year, limitAmount]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar orçamento:', error);
    res.status(500).json({ error: 'Erro ao criar orçamento' });
  }
});

app.get('/api/budgets/status', authMiddleware, async (req, res) => {
  try {
    const { month, year } = req.query;
    const currentMonth = month || new Date().getMonth() + 1;
    const currentYear = year || new Date().getFullYear();
    
    // Buscar orçamentos do mês
    const budgets = await pool.query(
      'SELECT b.*, c.name as category_name, c.color as category_color FROM budgets b LEFT JOIN categories c ON b.category_id = c.id WHERE b.user_id = $1 AND b.month = $2 AND b.year = $3',
      [req.userId, currentMonth, currentYear]
    );
    
    // Buscar gastos reais do mês por categoria
    const expenses = await pool.query(
      "SELECT category_id, SUM(amount) as spent FROM transactions WHERE user_id = $1 AND type = 'expense' AND EXTRACT(MONTH FROM date) = $2 AND EXTRACT(YEAR FROM date) = $3 GROUP BY category_id",
      [req.userId, currentMonth, currentYear]
    );
    
    const expenseMap = {};
    expenses.rows.forEach(e => {
      expenseMap[e.category_id] = parseFloat(e.spent);
    });
    
    const result = budgets.rows.map(budget => ({
      ...budget,
      spent: expenseMap[budget.category_id] || 0,
      remaining: parseFloat(budget.limit_amount) - (expenseMap[budget.category_id] || 0),
      percentage: ((expenseMap[budget.category_id] || 0) / parseFloat(budget.limit_amount)) * 100
    }));
    
    res.json(result);
  } catch (error) {
    console.error('Erro ao buscar status do orçamento:', error);
    res.status(500).json({ error: 'Erro ao buscar status do orçamento' });
  }
});

// ==================== METRICS ====================
app.get('/api/metrics/dashboard', authMiddleware, async (req, res) => {
  try {
    const currentMonth = new Date().getMonth() + 1;
    const currentYear = new Date().getFullYear();
    
    // Total em contas
    const accountsResult = await pool.query(
      'SELECT currency, SUM(balance) as total FROM accounts WHERE user_id = $1 GROUP BY currency',
      [req.userId]
    );
    
    // Total em investimentos
    const investmentsResult = await pool.query(
      'SELECT currency, SUM(current_value) as total FROM investments WHERE user_id = $1 GROUP BY currency',
      [req.userId]
    );
    
    // Total em ativos
    const assetsResult = await pool.query(
      'SELECT currency, SUM(value) as total FROM assets WHERE user_id = $1 GROUP BY currency',
      [req.userId]
    );
    
    // Total em passivos
    const liabilitiesResult = await pool.query(
      'SELECT currency, SUM(amount) as total FROM liabilities WHERE user_id = $1 GROUP BY currency',
      [req.userId]
    );
    
    // Receitas e despesas do mês
    const monthlyTransactions = await pool.query(
      "SELECT type, SUM(amount) as total FROM transactions WHERE user_id = $1 AND EXTRACT(MONTH FROM date) = $2 AND EXTRACT(YEAR FROM date) = $3 GROUP BY type",
      [req.userId, currentMonth, currentYear]
    );
    
    const income = monthlyTransactions.rows.find(t => t.type.toLowerCase() === 'income')?.total || 0;
    const expenses = monthlyTransactions.rows.find(t => t.type.toLowerCase() === 'expense')?.total || 0;
    
    // Calcular totais por moeda
    const byCurrency = {};
    
    accountsResult.rows.forEach(r => {
      if (!byCurrency[r.currency]) byCurrency[r.currency] = { assets: 0, liabilities: 0 };
      byCurrency[r.currency].assets += parseFloat(r.total);
    });
    
    investmentsResult.rows.forEach(r => {
      if (!byCurrency[r.currency]) byCurrency[r.currency] = { assets: 0, liabilities: 0 };
      byCurrency[r.currency].assets += parseFloat(r.total);
    });
    
    assetsResult.rows.forEach(r => {
      if (!byCurrency[r.currency]) byCurrency[r.currency] = { assets: 0, liabilities: 0 };
      byCurrency[r.currency].assets += parseFloat(r.total);
    });
    
    liabilitiesResult.rows.forEach(r => {
      if (!byCurrency[r.currency]) byCurrency[r.currency] = { assets: 0, liabilities: 0 };
      byCurrency[r.currency].liabilities += parseFloat(r.total);
    });
    
    // Calcular métricas
    const metrics = {};
    
    // Se não há dados, criar estrutura padrão para BRL
    if (Object.keys(byCurrency).length === 0) {
      byCurrency['BRL'] = { assets: 0, liabilities: 0 };
    }
    
    Object.keys(byCurrency).forEach(currency => {
      const data = byCurrency[currency];
      metrics[currency] = {
        totalAssets: data.assets,
        totalLiabilities: data.liabilities,
        netWorth: data.assets - data.liabilities,
        debtRatio: data.assets > 0 ? (data.liabilities / data.assets) * 100 : 0
      };
    });
    
    // Índice de poupança
    const savingsRate = income > 0 ? ((income - expenses) / income) * 100 : 0;
    
    // Reserva de emergência (considerando apenas BRL)
    const brlAccounts = accountsResult.rows.find(r => r.currency === 'BRL')?.total || 0;
    const emergencyFundMonths = expenses > 0 ? brlAccounts / expenses : 0;
    
    res.json({
      byCurrency: metrics,
      monthly: {
        income: parseFloat(income),
        expenses: parseFloat(expenses),
        balance: parseFloat(income) - parseFloat(expenses),
        savingsRate: savingsRate.toFixed(2)
      },
      emergencyFund: {
        months: emergencyFundMonths.toFixed(1),
        amount: parseFloat(brlAccounts)
      }
    });
  } catch (error) {
    console.error('Erro ao calcular métricas:', error);
    res.status(500).json({ error: 'Erro ao calcular métricas' });
  }
});

// ==================== REPORTS ====================
app.get('/api/reports/category-breakdown', authMiddleware, async (req, res) => {
  try {
    const { month, year, type } = req.query;
    const currentMonth = month || new Date().getMonth() + 1;
    const currentYear = year || new Date().getFullYear();
    const txType = type || 'expense';
    
    const result = await pool.query(
      "SELECT c.name, c.color, SUM(t.amount) as total FROM transactions t LEFT JOIN categories c ON t.category_id = c.id WHERE t.user_id = $1 AND t.type = $2 AND EXTRACT(MONTH FROM t.date) = $3 AND EXTRACT(YEAR FROM t.date) = $4 GROUP BY c.name, c.color ORDER BY total DESC",
      [req.userId, txType, currentMonth, currentYear]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao gerar relatório:', error);
    res.status(500).json({ error: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/monthly-trend', authMiddleware, async (req, res) => {
  try {
    const { months } = req.query;
    const monthsCount = months || 6;
    
    const result = await pool.query(
      "SELECT EXTRACT(YEAR FROM date) as year, EXTRACT(MONTH FROM date) as month, type, SUM(amount) as total FROM transactions WHERE user_id = $1 AND date >= CURRENT_DATE - INTERVAL '$2 months' GROUP BY year, month, type ORDER BY year, month",
      [req.userId, monthsCount]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao gerar tendência:', error);
    res.status(500).json({ error: 'Erro ao gerar tendência' });
  }
});

// ==================== ACHIEVEMENTS ====================
app.get('/api/achievements', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM achievements WHERE user_id = $1 ORDER BY unlocked_at DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar conquistas:', error);
    res.status(500).json({ error: 'Erro ao buscar conquistas' });
  }
});

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 API rodando em http://0.0.0.0:${PORT}`);
});
