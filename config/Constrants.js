export const MaxAttempts = Number(process.env.MAX_ATTEMPTS);
export const UserBlockedUntil = Number(process.env.USER_BLOCKED_UNTIL) || 15*60*1000;