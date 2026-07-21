# 💰 Cost Safety Guide — keeping this project at $0

This is **Milestone 0**, and we do it *before* creating anything in AWS. Read the short reality
section first — it corrects a couple of common misunderstandings — then follow the checklist.

---

## The reality (verified against official AWS docs, 2026)

1. **AWS IoT Core is *not* "Always Free."** It's free for **12 months**, then pay-as-you-go — but at
   this project's volume (a handful of alerts a day) that's *pennies* per month, not dollars.
2. **The services this project leans on long-term *are* always free:** **Lambda** (1M requests/mo),
   **SNS email** (1,000 emails/mo), and **basic CloudWatch** (10 alarms, 5 GB logs/mo). These never
   expire.
3. **Your account is on AWS's new (2025) Free plan** — the "$100 credit / ~185-day trial." Important:
   a Free-plan account **auto-closes at ~6 months** (or when credits run out, whichever comes first).
   You then get **90 days** to upgrade to a Paid plan before AWS permanently deletes it.
   - **While on the Free plan you literally cannot be charged** — paid usage is simply blocked. So
     the billing alarms below are mostly a *good habit* now, and become truly important **only if you
     later upgrade to Paid**.
4. **Realistic cost of this project:** **$0.00 for the first year.** If you keep it running past then
   (on a Paid plan), it's roughly **$0.00–$0.05/month**.

**The things that actually bill people are traps, never the IoT traffic:**

| Trap | Cost | Rule |
|---|---|---|
| **NAT Gateway** | ~$32/month, even idle | ❌ Never create one. Our Lambda is non-VPC and needs no NAT. |
| **SMS alerts** | Per-message, + KSA needs company-only sender-ID registration | ❌ We use **email**, not SMS. |
| **Device Defender** | Free for 1 month, then charges | ❌ Don't enable it (or turn it off after the trial). |
| **EC2 / RDS / Elastic IP** | Hourly | ❌ Not needed — this project is fully serverless. |
| **CloudWatch Logs > 5 GB/mo** | $0.50/GB | ✅ We set log retention to 7 days. |

---

## The $0 checklist (Milestone 0)

Do these in order. Each is free. Run all project resources in **`EU (Frankfurt) = eu-central-1`**
(closer to you in Saudi Arabia, fully supported; the per-unit cost difference vs. the cheapest US
region is negligible at this volume). **One exception:** the CloudWatch *billing alarm* (step 4) must
be created in **`us-east-1`** — that's the only region where AWS publishes billing metrics. The
Zero-spend budget (step 3) is **global**, so it protects you regardless of region and is your main
net.

### 1. Set your region to `EU (Frankfurt) / eu-central-1`
Top-right corner of the AWS console → region dropdown → **Europe (Frankfurt)**. Keep it there for
*everything in this project* — mixing regions splits your free tier and can add data-transfer
charges. (You'll switch to **US East (N. Virginia)** only briefly in step 4 to view the billing
alarm, then switch back.)

### 2. Turn on billing visibility + Free Tier alerts
- Sign in as **root** → click your account name (top-right) → **Billing and Cost Management**.
- **Billing preferences** → enable:
  - ☑️ **Receive AWS Free Tier alerts** → enter your email (`your-email@example.com` or preferred).
  - ☑️ **Receive CloudWatch billing alerts** (this lets us create a billing alarm in step 4).
- Save.

### 3. Create a **Zero-spend budget** (the friendliest safety net — and it earns a $20 credit)
- **Billing and Cost Management** → **Budgets** → **Create budget**.
- Choose **Use a template (simplified)** → **Zero spend budget**.
- Enter your email for alerts → **Create budget**.
- ✅ This emails you the moment *any* charge above $0 appears. Budget monitoring is free, and creating
  a budget is one of AWS's 5 credit-earning "activities" (worth $20 toward your credits).

### 4. Verify / set a CloudWatch billing alarm (this one lives in `us-east-1`)
Billing metrics exist **only** in us-east-1, so switch the region selector to **US East (N.
Virginia)** just for this step (then switch back to Frankfurt afterward). You mentioned you already
created a **$0.01** billing alert — let's confirm it's healthy:
- With the region on **us-east-1**, open **CloudWatch** → **Alarms**.
- You should see your billing alarm. If it says **"Insufficient data"** that's normal early on (it
  just means no billing metric has published yet); it should not be in **ALARM**.
- If you *don't* have one, create it: **Create alarm** → **Select metric** → **Billing** → **Total
  Estimated Charge** → **USD** → threshold **Greater than 1** (a $1 threshold is calmer than $0.01,
  which trips on rounding noise) → send notification to an SNS topic tied to your email → confirm the
  subscription email AWS sends you.

> A $0.01 threshold is fine as an ultra-sensitive trip-wire, but expect it to be noisy. Either is OK
> — the Zero-spend budget in step 3 is the real workhorse.

### 5. Secure the account (good practice, interview-worthy)
- **Enable MFA on the root user:** **IAM** → your root user → **Security credentials** → **Assign MFA
  device** → use an authenticator app (Google Authenticator, Authy, etc.).
- **Create an IAM admin user for daily use** so you're not using root day-to-day: **IAM** → **Users**
  → **Create user** → attach **AdministratorAccess** → sign in as that user from now on. (Least-
  privilege for the *device* comes later in M3; this is about *you*.)

---

## ✅ M0 done when

- Region is **us-east-1**.
- **Zero-spend budget** exists and is active.
- A **billing alarm** exists (yours, verified — not in ALARM state).
- **Free Tier alerts** are enabled.
- **Root MFA** is on and you have an **IAM admin user**.

That's three independent nets (budget + billing alarm + free-tier alerts) plus account hardening.
With these in place, you effectively cannot be surprised by a bill.

---

## 🗓️ The ~month-5 decision (we'll revisit together)

Because the Free-plan account closes at ~6 months, around **month 5** you'll decide:
- **(a) Let it close** — record your demo video + finish the docs while everything's live, then let
  the account close. **Zero charges, ever.** Perfect if the project is "done" for portfolio purposes.
- **(b) Upgrade to Paid** — keeps it running. Real billing switches on, but at this volume it's
  pennies/month, and the safety nets above protect you.

You don't need to decide now. I'll remind you when we get there.

---

## ✅ On the Paid plan — the $0 guardrails (enable / never-enable)

Once you upgrade to Paid, the "charges are blocked" guardrail is gone, so these matter. At this
project's volume you stay in the always-free tier, but keep this discipline:

**ENABLE (all free):**
- **Zero-spend budget** (Billing → Budgets) alerting your email — your #1 tripwire.
- **Billing alarm** in `us-east-1` (you have one) + **Free-Tier usage alerts**.
- **DynamoDB TTL** on attribute `ttl` (bounds history storage forever).
- **Lambda RESERVED concurrency** on `wids-alert-handler` *(optional — new accounts with a low
  concurrency limit can't set this; skip it, the low account limit + token + budget already cover you)*.
- **CloudWatch Logs retention = 7 days** on both Lambda log groups.

**NEVER create / enable (these bill):**
- **NAT Gateway, EC2, RDS, Elastic IP** — none are needed.
- **DynamoDB**: on-demand mode, auto-scaling above 25, GSIs, Global Tables, PITR/backups. Keep it
  **Provisioned ≤ 25/25**.
- **SNS SMS** (email only) · **IoT Device Defender** · **AWS WAF**.
- **Lambda PROVISIONED concurrency** — ⚠️ NOT the same as *Reserved*. Reserved (a cap) is free;
  **Provisioned bills hourly**. Only ever set *Reserved*.
- More than **10 CloudWatch alarms / 10 custom metrics / 3 dashboards**, or high-resolution alarms.
- Joining **AWS Organizations / Control Tower / Partner Network** (can silently change billing).

---

## 🔍 Weekly habit (30 seconds)

Open **Billing and Cost Management** → **Free Tier** page → glance at usage bars (all should be tiny),
and check **Bills** shows **$0.00**. Done.
