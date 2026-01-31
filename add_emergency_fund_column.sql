-- Adicionar coluna is_emergency_fund na tabela accounts
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS is_emergency_fund BOOLEAN DEFAULT FALSE;
