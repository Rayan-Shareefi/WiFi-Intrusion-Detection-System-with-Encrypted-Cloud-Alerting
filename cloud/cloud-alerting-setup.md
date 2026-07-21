# Cloud Alerting — IoT Rule → Lambda → SNS Email (Milestone 5)

**Goal:** when the device publishes to `wids/alerts`, automatically email you (which also shows as a
phone notification). The pipeline:

```
IoT Rule (filters)  ->  Lambda (formats the message)  ->  SNS topic  ->  your email / phone
```

Everything is in **eu-central-1**, serverless, and inside the **always-free** tiers (Lambda 1M
requests/mo, SNS 1,000 emails/mo).

> ⚠️ **Do NOT put the Lambda in a VPC.** It doesn't need one, and a VPC would require a paid NAT
> gateway (~$32/mo) — the single most common accidental AWS bill. The default (non-VPC) Lambda has
> free outbound access to SNS.

**Order matters:** SNS topic first (the Lambda needs its ARN), then the Lambda, then the IoT Rule.

---

## Part 1 — SNS topic + email subscription
1. Console → **Simple Notification Service (SNS)** → **Topics → Create topic**.
2. Type = **Standard**, Name = **`wids-alerts`** → **Create topic**.
3. **Copy the topic ARN** shown at the top (looks like `arn:aws:sns:eu-central-1:ACCOUNT_ID:wids-alerts`)
   — you'll use it twice below.
4. On the topic page → **Create subscription** → Protocol **Email** → Endpoint = your email
   (`your-email@example.com`) → **Create subscription**.
5. **Open your inbox and click "Confirm subscription"** in the AWS email. Until you confirm, no alerts
   can be delivered.

## Part 2 — Lambda function
1. Console → **Lambda → Create function → Author from scratch**.
2. Function name **`wids-alert-handler`**, Runtime **Python 3.13** (or the latest Python), leave
   architecture default → **Create function**.
3. In the **Code** tab, select all in `lambda_function.py`, delete it, and paste the contents of
   [`lambda/lambda_function.py`](lambda/lambda_function.py). Click **Deploy**.
4. **Configuration → Environment variables → Edit → Add environment variable:**
   - Key: `SNS_TOPIC_ARN`
   - Value: the topic ARN from Part 1 → **Save**.
5. **Grant it permission to publish to SNS:**
   - **Configuration → Permissions** → click the **Role name** link (opens IAM in a new tab).
   - **Add permissions → Create inline policy → JSON** → paste
     [`lambda/lambda-sns-policy.json`](lambda/lambda-sns-policy.json) (confirm the ARN matches your
     topic) → **Next** → name it `wids-sns-publish` → **Create policy**.
6. *(Optional, keeps logs tidy + free)* CloudWatch → **Log groups** →
   `/aws/lambda/wids-alert-handler` → **Actions → Edit retention setting → 7 days**.

## Part 3 — IoT Rule (route the message to the Lambda)
1. Console → **AWS IoT Core → Message routing → Rules → Create rule**.
2. Rule name **`wids_alert_rule`** → **Next**.
3. **SQL statement:**
   ```sql
   SELECT * FROM 'wids/alerts' WHERE event <> 'device_online'
   ```
   (Forwards real alerts and your `t` test; skips the boot heartbeat so it doesn't email you on every
   power-up.)
4. **Next → Rule actions → Lambda** → choose **`wids-alert-handler`** → **Next → Create**. The console
   automatically allows AWS IoT to invoke your Lambda.

## Part 4 — Test end to end
1. On the device, type **`t`** in the Serial Monitor (fires a `test_trigger`).
2. Within a few seconds: an **email** titled **"[WIDS] Test alert (manual trigger) detected"** lands in
   your inbox and pings your phone. 🎉
3. To watch it work: **Lambda → Monitor → View CloudWatch logs** shows each invocation and the
   "Emailed alert" line.

## ✅ M5 done when
Typing `t` on the device results in an alert **email on your phone**. That's the entire project working
end to end: sensor → encrypted cloud → your pocket.

---

## Troubleshooting
- **No email at all** → is the SNS subscription **Confirmed**? (SNS → Subscriptions — status must be
  "Confirmed", not "PendingConfirmation".) Check spam/promotions.
- **Lambda ran but no email** → `SNS_TOPIC_ARN` env var wrong, or the inline `sns:Publish` policy is
  missing/misspelled. The Lambda's **CloudWatch logs** will show the exact error.
- **Rule never fires** → the topic must be exactly `wids/alerts`; confirm the device still shows up in
  the MQTT test client. Check **IoT Core → Monitor** or the rule's error action.
- **You get emailed on every boot** → the `WHERE event <> 'device_online'` clause is missing from the
  rule SQL.
- **Cost worry** → nothing here leaves the free tier at your volume. Just never add a VPC/NAT gateway.
