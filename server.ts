
import express from 'express'; // Apenas ilustrativo, use express real no seu repo de back
import { Pool } from 'pg';

// O Railway injeta a variável DATABASE_URL automaticamente
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Fix: Use type assertion to any to resolve collision where 'express' was identified as React types
const app = (express as any)();
// Fix: Use type assertion to any to resolve "property json does not exist"
app.use((express as any).json());

// Exemplo de rota de Listagem de Contas
app.get('/api/accounts', async (req: any, res: any) => {
  const userId = req.user.id; // Obtido via middleware de JWT
  try {
    const result = await pool.query(
      'SELECT id, name, currency, balance, is_investment as "isInvestment" FROM accounts WHERE user_id = $1',
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Erro ao buscar contas" });
  }
});

// Exemplo de criação de transação com atualização de saldo (Trigger ou Transaction SQL)
app.post('/api/transactions', async (req: any, res: any) => {
  const { accountId, amount, type, description, date, categoryId } = req.body;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    
    // 1. Insere a transação
    const transResult = await client.query(
      'INSERT INTO transactions (user_id, account_id, amount, type, description, date, category_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.id, accountId, amount, type, description, date, categoryId]
    );

    // 2. Atualiza o saldo da conta
    const balanceAdjustment = type === 'INCOME' ? amount : -amount;
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2',
      [balanceAdjustment, accountId]
    );

    await client.query('COMMIT');
    res.status(201).json(transResult.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ message: "Erro ao processar transação" });
  } finally {
    client.release();
  }
});
