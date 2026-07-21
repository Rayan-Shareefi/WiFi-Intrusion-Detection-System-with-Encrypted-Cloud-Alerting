# 🛠️ Hardening & Features — Console Steps

Applies the security-review fixes and features. **Code is already updated** in the repo — you just
re-deploy the Lambda, re-upload the firmware, and do the small console steps below.

> 💯 **Cost:** everything here stays **$0** — Lambda, SNS, CloudWatch (10 alarms / 10 custom metrics
> free), and DynamoDB (always-free 25 GB + 25 provisioned RCU/WCU). **The one thing to get right:**
> create the DynamoDB table in **Provisioned** capacity within the free tier (steps below) — *not*
> On-Demand, which has no always-free request tier.

Order: re-deploy Lambda code → (optional) DynamoDB table → update Lambda IAM + env → alarms → IoT Rule.

---

## 1. Re-deploy the Lambda + re-upload the firmware
- **Lambda:** open `wids-alert-handler` → **Code** → paste the updated
  [`cloud/lambda/lambda_function.py`](../cloud/lambda/lambda_function.py) → **Deploy**.
- **Firmware:** re-upload [`firmware/WIDS_ESP32/WIDS_ESP32.ino`](../firmware/WIDS_ESP32/WIDS_ESP32.ino).
  (New: frame-length guard, a 30-min heartbeat, per-type cooldowns, a missed-alert counter.)

At this point email alerts still work exactly as before. The steps below light up the extras.

---

## 2. (Optional, but recommended) DynamoDB history table — backend for the dashboard/app
1. Console → **DynamoDB → Tables → Create table**.
2. **Table name:** `WidsAlerts`
3. **Partition key:** `device` — type **String**
4. **Sort key:** `ts` — type **⚠️ Number** (the dropdown defaults to *String* — you MUST change it)

   > **If `ts` is created as String, every write silently fails** and the table stays empty forever.
   > DynamoDB rejects a Number value for a String key, and the Lambda catches the error so your email
   > alerts keep working — the only clue is a `save_alert error: ... ValidationException` line in the
   > Lambda's CloudWatch logs. Fix = delete the table and recreate it with `ts` as **Number**
   > (it's empty, so nothing is lost).

5. **Table settings → Customize** → **Read/write capacity = Provisioned** → **turn OFF auto-scaling**
   → set **Read = 1** and **Write = 1** capacity units. *(Well inside the always-free 25/25 → $0.)*
6. **Create table.**

Then tell the Lambda to use it:
- Lambda → **Configuration → Environment variables** → add `TABLE_NAME` = `WidsAlerts` → **Save**.

*(If you skip this, the Lambda just doesn't write history — email still works.)*

---

## 3. Update the Lambda's IAM permissions
The Lambda now also writes a metric and (optionally) history.
- Lambda → **Configuration → Permissions** → click the **role name** (opens IAM).
- Edit the existing `wids-sns-publish` inline policy (or add a new one) → **JSON** → paste
  [`cloud/lambda/lambda-sns-policy.json`](../cloud/lambda/lambda-sns-policy.json) (SNS publish +
  `cloudwatch:PutMetricData` + `dynamodb:PutItem`) → **Save**.

---

## 3b. Update the IoT Rule SQL (do this — it's what makes the metric appear)
The original rule filtered out the boot ping, which also blocked the liveness signal. The Lambda now
decides what to email on its own, so the filter is no longer needed.
1. **AWS IoT Core → Message routing → Rules → `wids_alert_rule` → Edit**.
2. Change the SQL to simply:
   ```sql
   SELECT * FROM 'wids/alerts'
   ```
   *(Dropping `WHERE event <> 'device_online'`. Don't worry — the Lambda treats `device_online`,
   `heartbeat` and `device_list` as liveness pings and never emails them.)*
3. **Update**.

---

## 4. "Sensor offline" alarm (feature F6 — dead-man's switch)
Detects if the ESP32 stops sending its 30-min heartbeat.

> ⚠️ **The `WIDS` namespace won't exist until the device publishes its first liveness ping.**
> CloudWatch only creates a custom metric once a datapoint arrives. So do these first:
> 1. Steps 1–3b above (Lambda re-deployed **with the new code**, IAM includes
>    `cloudwatch:PutMetricData`, rule SQL updated), **and**
> 2. **re-upload the firmware**, then **reboot the ESP32**.
>
> On boot the device publishes `device_online` + `device_list` → the Lambda emits the metric →
> within **1–2 minutes** `WIDS` appears under **CloudWatch → Metrics → Custom namespaces**.

Once the metric exists:
1. Console → **CloudWatch → All alarms → Create alarm → Select metric**.
2. **Custom namespaces → WIDS → Metrics with no dimensions → `HeartbeatReceived`** → **Select metric**.
3. **Statistic = Sum**, **Period = 1 hour**.
4. Condition: **Lower/Equal** threshold, **≤ 0** (i.e., no heartbeats in the last hour).
5. **Additional configuration → Treat missing data as = Breaching** (this is what makes "silence"
   trigger the alarm).
6. **Notification → send to the `wids-alerts` SNS topic** → name it `wids-sensor-offline` → **Create**.

Now if the device loses power or WiFi for over an hour, you get an email.

### 🔍 Still can't find `WIDS` / `HeartbeatReceived`?
Work down this list — it's almost always one of these:
- **Wrong region.** CloudWatch must be on **Europe (Frankfurt) eu-central-1**.
- **Looking in the wrong place.** It's under **Metrics → Custom namespaces → WIDS**, *not* under the
  AWS namespaces.
- **Lambda not re-deployed** with the new code (the metric call only exists in the updated version).
- **Missing IAM permission** — the role needs `cloudwatch:PutMetricData` (step 3).
- **Device hasn't published.** Open **Lambda → Monitor → View CloudWatch logs**: you should see
  `Received event: {...}`. No log lines at all = the message never reached the Lambda (check the rule).
  A `metric error:` line = the IAM permission is missing.
- **Too soon.** Give it 1–2 minutes after the first datapoint.

---

## 5. "Runaway device" alarm (finding F4 — protects your $0)
1. **CloudWatch → Create alarm → Select metric → Lambda → By Function Name →
   `wids-alert-handler` → Invocations**.
2. **Statistic = Sum**, **Period = 1 hour**, threshold **Greater > 100** (tune to taste).
3. Notify the `wids-alerts` topic → name it `wids-runaway-lambda` → **Create**.

Catches a misbehaving/compromised device before it could ever dent the free tier.

---

## 6. IoT Rule error action (finding F3 — no silent drops) — *optional*
1. **AWS IoT Core → Message routing → Rules → `wids_alert_rule` → Edit**.
2. Scroll to **Error action → Add error action → Republish to AWS IoT topic**, topic `wids/errors`.
3. **IAM role (required for this action):** the dropdown starts empty and the action shows as invalid
   until you pick one. Click **Create new role**, name it e.g. `wids-rule-error-role` → **Create**.
   AWS attaches the right policy automatically and selects it. *(IAM roles are free.)*
4. **Update**.

> 💡 This step is genuinely **optional** — the console labels it so, and nothing else depends on it.
> If the IAM role is a hassle, click **Remove** on the error action and save.
>
> To actually *see* errors, subscribe to `wids/errors` in the **MQTT test client** (republished
> messages aren't stored anywhere). Choosing the **CloudWatch Logs** error action instead keeps a
> durable record — also fine, and it needs a role the same way.

Now if the Lambda action ever fails, the message isn't lost silently.

---

## ✅ Done when
- Re-deployed Lambda + re-uploaded firmware.
- (If using history) `WidsAlerts` table exists, `TABLE_NAME` env set, IAM updated.
- `wids-sensor-offline` and `wids-runaway-lambda` alarms show **OK** (not "Insufficient data" after a
  heartbeat arrives).
- Billing/Free-Tier page still shows **$0**.

## Alarm count check (stay in the free tier)
Free tier = **10 alarms**. You now have: billing alarm + sensor-offline + runaway-lambda = **3**.
Plenty of headroom.
