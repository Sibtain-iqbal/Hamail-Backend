# Understanding Your Trading States (Plain-English Guide)

This guide explains, in simple terms, how the system reads your recent trading behavior, assigns a psychological "state," and generates helpful forecasts, insights, and alerts. No math or code needed—just how it works and what to do with it.

## What is a "state" and why it matters

Your state is a short description of how you're currently approaching the market based on your recent activity. We use it to surface what to watch out for and what to lean into.

- STABLE: You're following your plan and staying consistent.
- OVEREXTENDED: You're doing too much—too many trades or trading outside your chosen sessions.
- AGGRESSIVE: You're taking on more risk than your plan allows, often after losses.
- HESITANT: You're cutting winners too soon or not letting targets play out.

The goal is not to label you, but to reflect your recent behavior so you can self-correct faster.

## What data we look at

We only use your own data—specifically:

- Your recent trades (timing, profit/loss, risk used, whether you exited early, etc.).
- Your trading plan (risk per trade, max trades per day, preferred sessions, target risk/reward, etc.).

We focus on your last handful of trades so the feedback feels timely and actionable.

## How we read recent behavior (without the tech)

Think of it like a quick checkup after each session:

- We skim your last trades (roughly up to ten) to see patterns.
- We compare what happened to what your plan says you want to do.
- We look for signals such as:
  - Taking more trades in a day than you planned.
  - Trading outside your preferred sessions.
  - Using more risk per trade than your plan allows.
  - Hitting stop losses frequently.
  - Exiting early or consistently taking partial targets too soon.
- We then pick the state that best describes the overall pattern right now.

If we don’t have enough data (for example, you’re just getting started or there’s no plan yet), we default to STABLE with a neutral confidence and tell you to log trades and set a plan.

## The four states in everyday language

- STABLE

  - You’re sticking to your rules. Your risk and sessions look aligned with your plan. Keep going.
  - What to do: Maintain your routine, review your best setups, and keep notes.

- OVEREXTENDED

  - You’re pushing beyond your plan—too many trades or trading at times you don’t normally trade.
  - What to do: Respect your daily trade cap, avoid off-hours entries, and reset if you feel FOMO.

- AGGRESSIVE

  - Risk is creeping up. This often happens after a losing streak or when trying to make it back quickly.
  - What to do: Cut position sizes back to plan levels, take a pause between trades, and stick to your stops.

- HESITANT
  - You’re leaving money on the table by exiting winners early or not letting valid targets play out.
  - What to do: Predefine target rules, consider scaling out, and review examples of well-managed winners.

## Confidence: how sure the system is

Along with your state, you’ll see a confidence score. Higher confidence means your recent behavior clearly points to that state. It’s influenced by how closely you’ve followed your plan and how consistent your recent outcomes are. If you see a middling or lower confidence, take it as a nudge rather than a verdict.

## State history: a timeline of your mindset

We build a simple timeline showing when your state noticeably changed. If your confidence jumps or your state flips (e.g., from STABLE to AGGRESSIVE), we record that moment and include a short trigger like “Profitable trade,” “Losing trade,” or “Early exit.”

You also get a quick summary:

- How many times your state changed.
- Which state appeared most often.
- How steady your confidence has been.

## Session forecast: today’s risk-of-bias radar

For a given session (like LONDON or NY), we look at your recent behavior in that session and flag likely biases, such as:

- Revenge trading risk after a run of recent losses.
- Risk escalation when position sizing creeps above plan.
- Session drift if you frequently trade outside your preferred times.

We then give a simple forecast—Positive, Neutral, or Negative—plus tailored suggestions (e.g., reduce risk, trade only during planned hours, pause after losses).

## Performance insights: supportive, not judgmental

You’ll get a small set of friendly insights:

- Positive reinforcements when you’re doing well (e.g., strong plan adherence or healthy win rate).
- Constructive suggestions when we spot opportunities (e.g., exiting too early, drifting from the plan).

We make sure you always get something helpful to build on and at least one suggestion to improve.

## Dashboard at a glance: what the tiles mean

- Summary stats: How many trades, win rate, total profit/loss, average risk/reward, best and worst trades.
- Trends: Whether your P&L, win rate, or average risk is trending up, down, or stable compared to your recent past.
- Alerts: Quick warnings or celebrations that matter right now (e.g., win rate is unusually low, average risk too high, behavior looks AGGRESSIVE/HESITANT/OVEREXTENDED).

## How to use this in your daily routine

- Before the session: Check your current state and the session forecast. If it says “risk is climbing,” start smaller.
- During the session: Stick to the plan. If a warning appears (e.g., overtrading), take a 5–10 minute break.
- After the session: Review your state history and insights. Write one sentence about what you’ll do differently tomorrow.

## FAQs

- Why did I get AGGRESSIVE?

  - You likely increased risk above your plan or had several quick stop-loss hits. The fix is to reset size to plan and slow down entries.

- Why did I get HESITANT?

  - You’re probably exiting profitable trades too early or not reaching your usual targets. Consider predefined target rules and practice holding with smaller size.

- Can I be both overtrading and hesitant?

  - Yes—this happens. We pick the state that best captures the dominant pattern right now and surface indicators to explain why.

- What if I don’t agree with my state?
  - Treat it as a conversation starter with your journal. If it keeps showing up and you disagree, adjust your plan or review trade tags to see what the data says.

## A final note

This system isn’t judging your strategy; it mirrors your recent behavior against your own plan. The idea is to catch small drifts early so you can make steady, confident progress.

---

## Technical Calculation Details

The sections below define the exact inputs, formulas, thresholds, and rules used by the engine. Small code excerpts are included for traceability.

### Notation and Inputs

- N: number of trades considered for a calculation
- Trades fields: `profitLoss`, `riskPercentUsed` (nullable), `riskRewardAchieved` (nullable), `targetPercentAchieved` (nullable), `exitedEarly`, `stopLossHit`, `session`, `entryTime`, `mt5DealId` (optional), `mt5Symbol` (optional)
- Plan fields: `maxTradesPerDay`, `riskPercentPerTrade`, `targetRiskRewardRatio`, `preferredSessions`
- Sessions are compared in uppercase; plan sessions are values from `TradingSessions`.
- **Null handling**: Nullable fields (`riskPercentUsed`, `riskRewardAchieved`, `targetPercentAchieved`) are excluded from all calculations. Averages, counts, and comparisons only consider trades with non-null values.

### Psychological State Calculation

- Data window: N = min(10, recent trades available). If N < 5, compute state but cap confidence at 40.
- Metrics (over the last N trades):

  - wins = count(`profitLoss > 0`)
  - winRate = wins / N
  - avgRiskUsed = average(`riskPercentUsed`) - **only calculated from trades where `riskPercentUsed != null`**
  - avgRR = average(`riskRewardAchieved`) - **only calculated from trades where `riskRewardAchieved != null`**
  - medianTargetPct = median(`targetPercentAchieved`) - **only calculated from trades where `targetPercentAchieved != null`**
  - nearTargetHits = count(`targetPercentAchieved != null AND targetPercentAchieved >= 80`)
  - earlyExits = count(`exitedEarly == true` OR (`profitLoss > 0` AND `targetPercentAchieved != null` AND `targetPercentAchieved` BETWEEN 30 AND 80))
  - riskBreaches = count(`riskPercentUsed != null AND riskPercentUsed > planRisk * 1.5`)
  - daysWithTrades = number of distinct calendar days in the N trades
  - outsideSessionDays = number of days with ≥ 1 trade outside preferred sessions
  - exceededDays = number of days where tradesThatDay > `maxTradesPerDay`
  - recentAvgRisk = average(`riskPercentUsed`) over trades where `riskPercentUsed != null`
  - riskSpike = at least 2 of last 3 trades with `riskPercentUsed != null AND riskPercentUsed > max(planRisk*1.3, recentAvgRisk*1.3)`

- Plan adherence (0–100), weighted and reweighted if inputs are missing:

  - riskDiscipline = `1 - riskBreaches / max(1, N)` (weight 0.40)
  - sessionAdherence = `1 - outsideSessionDays / max(1, daysWithTrades)` (weight 0.25)
  - tradeCountDiscipline = `1 - exceededDays / max(1, daysWithTrades)` (weight 0.25)
  - targetProgress = `min(1, nearTargetHits / max(1, N))` (weight 0.10)
  - planAdherence = `round( 100 * weightedAverage(components, weightsPresent) )`

- State mapping (priority order: OVEREXTENDED > AGGRESSIVE > HESITANT > STABLE):

  - OVEREXTENDED if `(exceededDays/daysWithTrades >= 0.33)` OR `(outsideSessionDays/daysWithTrades >= 0.33)`
  - AGGRESSIVE if `riskSpike == true` OR `(riskBreaches/N >= 0.25)` OR `(avgRiskUsed > planRisk*1.25)`
  - HESITANT if `(earlyExits/N >= 0.4)` OR `(medianTargetPct < 60 AND winRate <= 0.6)`
  - STABLE otherwise

- Confidence (10–95), with small-N cap:

  - `sampleFactor = min(N,10)/10`
  - `discipline = planAdherence/100`
  - `signalStrength = max( |avgRiskUsed/planRisk - 1|, |winRate - 0.5|*2, |medianTargetPct/100 - 0.6| )`
  - `confidence = clamp( round( 100*(0.5*discipline + 0.3*sampleFactor + 0.2*signalStrength) ), 10, 95 )`
  - If `N < 5`, then `confidence = min(confidence, 40)`

- No-data fallback: return STABLE with `confidence = 50` and `planAdherence = 50` and a neutral indicator when there is no plan or no trades.

#### Worked Example (State)

Given:

- Plan: `riskPercentPerTrade = 1.5`, `maxTradesPerDay = 5`, `targetRiskRewardRatio = 2.0`, `preferredSessions = [LONDON, NY]`
- Last N=10 trades: wins=6, avgRiskUsed=1.8, avgRR=1.4, avgTargetAchieved=75, earlyExits=3, stopLossHits=2, outsideSession=2, riskBreaches=2, exceededDays=0, lastRisk=2.6, recentAverageRisk≈1.8

Then:

- winRate = 6/10 = 0.60
- riskSpike = (2.6 > 1.8*1.5=2.7) OR (2.6 > 1.5*1.5=2.25) → true (second condition)
- nearTargetHits (assume) = 6
- planAdherence components = [1-0.2, 1-0.2, 1-0/3, min(1, 6/10)] = [0.8, 0.8, 1.0, 0.6]
- planAdherence = round(average(0.8, 0.8, 1.0, 0.6) _ 100) = round(0.8 _ 100) = 80
- State: not OVEREXTENDED (outsideSession=0.2 < 0.25, exceededDays=0). AGGRESSIVE because `riskSpike` is true.
- Confidence = clamp(round(80*0.6 + 60*0.2 + (1.4/2.0)\*20), 10, 95)
  = clamp(round(48 + 12 + 14), 10, 95) = clamp(74, 10, 95) = 74

Result: `AGGRESSIVE`, confidence `74`, planAdherence `80`.

### State History Calculation

- Sort all candidate trades by `entryTime` ascending.
- For i from 0..end, define recent window `trades[max(0, i-4)..i]` (up to 5 trades) and compute state.
- Change detection rule: record a history point if state label changes OR `|confidenceDelta| > 15`.
- Summary:
  - totalChanges = number of recorded history points
  - mostCommonState = mode of recorded states (fallback: STABLE)
  - averageConfidence = mean of recorded confidences (fallback: 50)
  - volatility = stddev(confidences) scaled to [0, 1] with 0.01 resolution

```430:436:src/services/analysis.service.js
for (let i = 0; i < sortedTrades.length && history.length < limit; i += 1) {
  const trade = sortedTrades[i];
  const recentTrades = sortedTrades.slice(Math.max(0, i - 4), i + 1);
  const state = analyzePsychologicalState(recentTrades, plan);

  if (!lastState || lastState.state !== state.state || Math.abs(lastState.confidence - state.confidence) > 15) {
```

Volatility formula:

```466:471:src/services/analysis.service.js
const variance =
  confidences.length > 0
    ? confidences.reduce((sum, conf) => sum + (conf - averageConfidence) ** 2, 0) / confidences.length
    : 0;
const volatility = Math.round((Math.sqrt(variance) / 100) * 100) / 100;
```

Notes: Since confidence is on 0–100, `sqrt(variance)` is also on 0–100; dividing by 100 scales volatility to 0–1, rounding to two decimals via integer/100 resolution.

### Session Forecast Calculation

- Inputs: up to the last 20 trades in the requested `session` (uppercased), the plan, and current state.
- Heuristics:
  - `recentLossStreak = last 3 trades are losses (and N >= 3)`
  - `avgRisk > plan.riskPercentPerTrade * 1.25` - **calculated only from trades where `riskPercentUsed != null`**
  - `outsideSessionTrades / N >= 0.2`
- Accumulated effects:
  - If recentLossStreak → predictedBias: “Revenge trading risk”; `riskLevel = HIGH`
  - If avgRisk above threshold → predictedBias: “Risk escalation tendency”; `riskLevel = HIGH`
  - If outsideSession ratio above threshold → predictedBias: “Session drift”; `riskLevel >= MEDIUM`
- Forecast mapping: if `riskLevel = HIGH` → `NEGATIVE`; if `LOW` → `POSITIVE`; else `NEUTRAL`.

```213:232:src/services/analysis.service.js
if (recentLossStreak) {
  predictedBias = 'Revenge trading risk';
  riskLevel = RiskLevel.HIGH;
  recommendations.push('Consider pausing before new entries; reset after losses');
}

if (avgRisk > plan.riskPercentPerTrade * 1.25) {
  predictedBias = predictedBias === 'NEUTRAL' ? 'Risk escalation tendency' : predictedBias;
  riskLevel = RiskLevel.HIGH;
  recommendations.push('Reduce risk per trade to plan level');
}

if (outsideSessionTrades / totalTrades >= 0.2) {
  predictedBias = predictedBias === 'NEUTRAL' ? 'Session drift' : predictedBias;
  if (riskLevel !== RiskLevel.HIGH) riskLevel = RiskLevel.MEDIUM;
  recommendations.push('Trade only in preferred sessions for this period');
}
```

### Performance Insights Calculation

- Period trades (by date range) + plan.
- Stats:
  - `winRate = round( wins / total * 100 )`
  - `avgRR = round( average(riskRewardAchieved), 2 )` - **only calculated from trades where `riskRewardAchieved != null`**
  - Plan adherence (period):
    - `riskBreachesRatio = count(riskPercentUsed != null AND riskPercentUsed > plan * 1.5) / total`
    - `outsideSessionRatio = count(!preferredSessions.includes(session)) / total`
    - `planAdherence = round( ((1 - riskBreachesRatio) + (1 - outsideSessionRatio)) / 2 * 100 )`
- Insights:
  - Positive if `planAdherence >= 70` else if `winRate >= 60`
  - Constructive if `earlyExitsRatio >= 0.3` else if `planAdherence < 60`
  - Guarantee at least one POSITIVE and one CONSTRUCTIVE
  - `earlyExitsRatio` only counts trades where `targetPercentAchieved != null` OR `exitedEarly == true`

```312:318:src/services/analysis.service.js
const planAdherence = Math.round(
  ((1 -
    trades.filter((t) => t.riskPercentUsed > plan.riskPercentPerTrade * 1.5).length / totalTrades +
    (1 - trades.filter((t) => !plan.preferredSessions.includes(t.session)).length / totalTrades)) /
    2) *
    100
);
```

### Dashboard Metrics and Alerts

- Summary stats: standard totals and averages (winRate in percent, average risk–reward calculated only from trades with non-null `riskRewardAchieved`, best/worst by `profitLoss`).
- Trends: split data into two halves; compare P&L sums, win rates, and average risk (calculated only from trades with non-null `riskPercentUsed`) to classify UP/DOWN/STABLE.
- Alerts (key thresholds):
  - Win rate ≥ 0.7 → success; ≤ 0.3 → warning
  - Avg risk > 3 → warning; < 1 → info (calculated only from trades with non-null `riskPercentUsed`)
  - Recent win rate deviates from overall by ±0.2 → success/warning
  - State-specific alerts for AGGRESSIVE, HESITANT, OVEREXTENDED

```248:266:src/services/dashboard.service.js
// Win rate alerts
if (winRate >= 0.7) {
  alerts.push({
    type: 'SUCCESS',
    message: 'Excellent win rate achieved',
    priority: 'MEDIUM',
  });
} else if (winRate <= 0.3) {
  alerts.push({
    type: 'WARNING',
    message: 'Low win rate - review trading strategy',
    priority: 'HIGH',
  });
}
```

```268:281:src/services/dashboard.service.js
// Risk management alerts
if (avgRisk > 3) {
  alerts.push({
    type: 'WARNING',
    message: 'Risk per trade above recommended level',
    priority: 'HIGH',
  });
} else if (avgRisk < 1) {
  alerts.push({
    type: 'INFO',
    message: 'Consider increasing position sizes gradually',
    priority: 'LOW',
  });
}
```

```298:317:src/services/dashboard.service.js
// Psychological state alerts (updated states)
if (psychologicalState.state === 'AGGRESSIVE') {
  alerts.push({
    type: 'WARNING',
    message: 'Aggressive behavior detected - reduce risk to plan level',
    priority: 'HIGH',
  });
} else if (psychologicalState.state === 'HESITANT') {
  alerts.push({
    type: 'INFO',
    message: 'Hesitancy detected - define clear exit rules and trust them',
    priority: 'MEDIUM',
  });
} else if (psychologicalState.state === 'OVEREXTENDED') {
  alerts.push({
    type: 'WARNING',
    message: 'Overextended - respect daily trade cap and session plan',
    priority: 'HIGH',
  });
}
```

### Windows, Rounding, and Clamping Summary

- State: last 10 trades, confidence clamped to [10, 95]
- History: sliding window of up to 5 trades per step; volatility scaled to [0, 1] (two decimals)
- Forecast: last 20 trades for the requested session
- Insights: by period (WEEK, MONTH, QUARTER, YEAR)
- Rounding: integers unless noted; averages rounded to 2 decimals where surfaced
