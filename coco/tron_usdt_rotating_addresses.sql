WITH anchors AS (
  SELECT anchor_block
  FROM (VALUES
    (71748031),(75406554),(76818526),(63308211),(74678358),
    (59527801),(78802645),(64680221),(78360081),(65399936),
    (67057821),(73737818),(64452622),(64219886),(73312314),
    (60301079),(72878047),(59700550),(63585292),(60748545),
    (72414990),(58697651),(68528546),(76162316),(78498043),
    (71167669),(75197813),(66117300),(68703698),(67547254),
    (77150830),(78814641),(76754944),(71569290),(65595482),
    (68125459),(58428932),(66390824),(60993045),(58479317),
    (66478400),(64963337),(73224739),(58191429),(74968676),
    (72692099),(76325470),(71540498)
  ) AS t(anchor_block)
),
-- Identify valid throwaway/rotating addresses
validated_throwaway_addresses AS (
  WITH usdt_inflows AS (
    SELECT 
      "to" as address,
      SUM(amount) as total_received,
      MAX(block_time) as last_received_time
    FROM tokens_tron.transfers
    WHERE contract_address = 0xa614f803b6fd780986a42c78ec9c7f77e6ded13c
      AND "to" IS NOT NULL
    GROUP BY "to"
  ),
  usdt_outflows AS (
    SELECT 
      "from" as address,
      SUM(amount) as total_sent,
      MAX(block_time) as last_sent_time
    FROM tokens_tron.transfers
    WHERE contract_address = 0xa614f803b6fd780986a42c78ec9c7f77e6ded13c
      AND "from" IS NOT NULL
    GROUP BY "from"
  ),
  usdt_balances AS (
    SELECT 
      COALESCE(inf.address, out.address) as address,
      COALESCE(inf.total_received, 0) - COALESCE(out.total_sent, 0) as usdt_balance,
      GREATEST(inf.last_received_time, out.last_sent_time) as last_usdt_activity
    FROM usdt_inflows inf
    FULL OUTER JOIN usdt_outflows out ON inf.address = out.address
  ),
  addresses_with_low_trx AS (
    SELECT "to" as address
    FROM tron.transactions
    WHERE "to" IS NOT NULL
    GROUP BY "to"
    HAVING MAX(value / 1e6) <= 100
  )
  SELECT ub.address
  FROM usdt_balances ub
  INNER JOIN addresses_with_low_trx lt ON ub.address = lt.address
  WHERE ub.usdt_balance < 1
    AND ub.usdt_balance >= 0
    AND ub.last_usdt_activity >= CURRENT_TIMESTAMP - INTERVAL '1095' DAY
    AND ub.last_usdt_activity < CURRENT_TIMESTAMP - INTERVAL '730' DAY
),
target_blocks AS (
  SELECT DISTINCT a.anchor_block + (offset * 120) AS block_number
  FROM anchors a
  CROSS JOIN UNNEST(SEQUENCE(0, 239)) AS t(offset)
),
total_txs AS (
  SELECT
    tx.block_number,
    COUNT(*) AS total_txs_in_block
  FROM tron.transactions tx
  WHERE tx.block_number IN (SELECT block_number FROM target_blocks)
  GROUP BY tx.block_number
),
windowed AS (
  SELECT
    a.anchor_block,
    t.block_number,
    t.block_number - a.anchor_block AS rho_offset,
    
    -- Count only transactions from valid throwaway/rotating addresses
    COUNT(CASE WHEN vta.address IS NOT NULL THEN 1 END) AS throwaway_txs,
    
    MAX(tt.total_txs_in_block) AS total_txs_in_block
  FROM anchors a
  JOIN tokens_tron.transfers t
    ON t.block_number >= a.anchor_block
    AND t.block_number < a.anchor_block + 28800
    AND t.contract_address = 0xa614f803b6fd780986a42c78ec9c7f77e6ded13c
    AND t.amount > 0
  LEFT JOIN validated_throwaway_addresses vta ON t."to" = vta.address OR t."from" = vta.address
  JOIN total_txs tt ON tt.block_number = t.block_number
  GROUP BY a.anchor_block, t.block_number
),
smoothed AS (
  SELECT
    rho_offset,
    AVG(throwaway_txs) AS avg_throwaway_txs,
    AVG(throwaway_txs * 1.0 / NULLIF(total_txs_in_block, 0)) * 100 AS pct_throwaway
  FROM windowed
  GROUP BY rho_offset
),
moving_avg AS (
  SELECT
    rho_offset,
    
    AVG(avg_throwaway_txs) OVER (
      ORDER BY rho_offset
      ROWS BETWEEN 20 PRECEDING AND CURRENT ROW
    ) AS moving_avg_throwaway_txs,
    
    AVG(pct_throwaway) OVER (
      ORDER BY rho_offset
      ROWS BETWEEN 20 PRECEDING AND CURRENT ROW
    ) AS moving_avg_pct_throwaway
    
  FROM smoothed
)
SELECT
  rho_offset AS rho,
  moving_avg_throwaway_txs,
  moving_avg_pct_throwaway
FROM moving_avg
ORDER BY rho