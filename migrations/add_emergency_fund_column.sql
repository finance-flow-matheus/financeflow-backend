-- Migration: Add is_emergency_fund column to accounts table
-- Date: 2026-02-01
-- Description: Adds support for marking accounts as emergency fund

-- Add column if it doesn't exist
ALTER TABLE accounts 
ADD COLUMN IF NOT EXISTS is_emergency_fund BOOLEAN DEFAULT false;

-- Update existing accounts to have default value
UPDATE accounts 
SET is_emergency_fund = false 
WHERE is_emergency_fund IS NULL;

-- Add index for better query performance
CREATE INDEX IF NOT EXISTS idx_accounts_emergency_fund 
ON accounts(user_id, is_emergency_fund) 
WHERE is_emergency_fund = true;

-- Verify the column was added
SELECT column_name, data_type, column_default 
FROM information_schema.columns 
WHERE table_name = 'accounts' 
AND column_name = 'is_emergency_fund';
