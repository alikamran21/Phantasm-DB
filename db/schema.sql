-- =====================================================================
-- Phantasm-DB: Complete Schema (Original Structure + Expanded Seed Data)
-- 3 Schemas: public (real EHR), monitor (SIEM), shadow_vault (honeypot)
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================================
-- SCHEMAS
-- =====================================================================
CREATE SCHEMA IF NOT EXISTS public;
CREATE SCHEMA IF NOT EXISTS monitor;
CREATE SCHEMA IF NOT EXISTS shadow_vault;

-- =====================================================================
-- PUBLIC SCHEMA — Real EHR Data
-- =====================================================================

-- 1. Central auth (OTP lookup by email)
CREATE TABLE IF NOT EXISTS public.users (
    user_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(255) UNIQUE NOT NULL,
    role       VARCHAR(20) CHECK (role IN ('doctor','patient','admin')) NOT NULL,
    is_active  BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. OTP codes for MFA login
CREATE TABLE IF NOT EXISTS public.otp_requests (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
    otp_code   VARCHAR(6) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used    BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_ip INET
);

-- 3. Doctors
CREATE TABLE IF NOT EXISTS public.doctors (
    doc_id         VARCHAR(20) PRIMARY KEY,
    user_id        UUID UNIQUE REFERENCES public.users(user_id) ON DELETE CASCADE,
    full_name      VARCHAR(150),
    specialization VARCHAR(150)
);

-- 4. Patients
CREATE TABLE IF NOT EXISTS public.patients (
    mrn               VARCHAR(20) PRIMARY KEY,
    user_id           UUID UNIQUE REFERENCES public.users(user_id) ON DELETE CASCADE,
    doc_id            VARCHAR(20) REFERENCES public.doctors(doc_id),
    full_name         VARCHAR(150),
    primary_diagnosis TEXT,
    active_treatment  TEXT,
    status            VARCHAR(50) DEFAULT 'Active',
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Clinical notes (time-series therapy logs)
CREATE TABLE IF NOT EXISTS public.clinical_notes (
    note_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mrn        VARCHAR(20) REFERENCES public.patients(mrn) ON DELETE CASCADE,
    doc_id     VARCHAR(20) REFERENCES public.doctors(doc_id),
    notes_text TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Appointments
CREATE TABLE IF NOT EXISTS public.appointments (
    appt_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mrn          VARCHAR(20) REFERENCES public.patients(mrn),
    doc_id       VARCHAR(20) REFERENCES public.doctors(doc_id),
    scheduled_at TIMESTAMPTZ,
    is_urgent    BOOLEAN DEFAULT FALSE,
    status       VARCHAR(20) DEFAULT 'Scheduled'
);

-- 7. Daily tasks (patient compliance)
CREATE TABLE IF NOT EXISTS public.daily_tasks (
    task_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mrn              VARCHAR(20) REFERENCES public.patients(mrn),
    task_title       TEXT,
    task_description TEXT,
    is_done          BOOLEAN DEFAULT FALSE,
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================================
-- MONITOR SCHEMA — Admin SIEM (auto-populated via triggers)
-- =====================================================================

CREATE TABLE IF NOT EXISTS monitor.threat_actors (
    threat_id    SERIAL PRIMARY KEY,
    ip_address   INET,
    reason       TEXT,
    threat_level VARCHAR(20) DEFAULT 'medium',
    flagged_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS monitor.forensic_ledger (
    ledger_id    BIGSERIAL PRIMARY KEY,
    threat_id    INT REFERENCES monitor.threat_actors(threat_id),
    action_type  TEXT,
    target_table TEXT,
    query_text   TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS monitor.security_alerts (
    alert_id    SERIAL PRIMARY KEY,
    threat_id   INT REFERENCES monitor.threat_actors(threat_id),
    alert_title TEXT,
    description TEXT,
    is_resolved BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS monitor.login_activity (
    login_id        BIGSERIAL PRIMARY KEY,
    email_attempted VARCHAR(255),
    ip_address      INET,
    is_success      BOOLEAN DEFAULT FALSE,
    attempt_time    TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================================
-- SHADOW VAULT — Honeypot (mirrors public schema with fake data)
-- =====================================================================

CREATE TABLE IF NOT EXISTS shadow_vault.patients (LIKE public.patients INCLUDING ALL);
CREATE TABLE IF NOT EXISTS shadow_vault.clinical_notes (LIKE public.clinical_notes INCLUDING ALL);
CREATE TABLE IF NOT EXISTS shadow_vault.appointments (LIKE public.appointments INCLUDING ALL);
CREATE TABLE IF NOT EXISTS shadow_vault.daily_tasks (LIKE public.daily_tasks INCLUDING ALL);

-- Throttle config for honeypot
CREATE TABLE IF NOT EXISTS shadow_vault.system_state (
    config_key   TEXT PRIMARY KEY,
    config_value INT
);
INSERT INTO shadow_vault.system_state VALUES ('throttle_delay_ms', 1000)
    ON CONFLICT (config_key) DO NOTHING;

-- =====================================================================
-- MONITOR FUNCTIONS
-- =====================================================================

CREATE OR REPLACE FUNCTION monitor.get_threat_id()
RETURNS INT AS $$
DECLARE tid INT;
BEGIN
    SELECT threat_id INTO tid FROM monitor.threat_actors ORDER BY flagged_at DESC LIMIT 1;
    RETURN tid;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION monitor.log_attack(action TEXT, tbl TEXT, payload TEXT)
RETURNS VOID AS $$
DECLARE tid INT;
BEGIN
    tid := monitor.get_threat_id();
    INSERT INTO monitor.forensic_ledger(threat_id, action_type, target_table, query_text)
    VALUES (tid, action, tbl, payload);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION monitor.raise_alert(title TEXT, alert_desc TEXT)
RETURNS VOID AS $$
DECLARE tid INT;
BEGIN
    tid := monitor.get_threat_id();
    INSERT INTO monitor.security_alerts(threat_id, alert_title, description)
    VALUES (tid, title, alert_desc);
END;
$$ LANGUAGE plpgsql;

-- =====================================================================
-- TRIGGER FUNCTION — Fires on every shadow_vault write
-- =====================================================================

CREATE OR REPLACE FUNCTION monitor.track_shadow_changes()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM monitor.log_attack(TG_OP, TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
        CASE WHEN TG_OP = 'DELETE' THEN row_to_json(OLD)::TEXT
             ELSE row_to_json(NEW)::TEXT END);

    IF TG_OP IN ('DELETE','UPDATE') THEN
        PERFORM monitor.raise_alert(
            TG_OP || ' on honeypot',
            'Attacker triggered ' || TG_OP || ' on ' || TG_TABLE_NAME
        );
    END IF;

    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all shadow tables
DROP TRIGGER IF EXISTS trg_shadow_patients   ON shadow_vault.patients;
DROP TRIGGER IF EXISTS trg_shadow_notes      ON shadow_vault.clinical_notes;
DROP TRIGGER IF EXISTS trg_shadow_appt       ON shadow_vault.appointments;

CREATE TRIGGER trg_shadow_patients
AFTER INSERT OR UPDATE OR DELETE ON shadow_vault.patients
FOR EACH ROW EXECUTE FUNCTION monitor.track_shadow_changes();

CREATE TRIGGER trg_shadow_notes
AFTER INSERT OR UPDATE OR DELETE ON shadow_vault.clinical_notes
FOR EACH ROW EXECUTE FUNCTION monitor.track_shadow_changes();

CREATE TRIGGER trg_shadow_appt
AFTER INSERT OR UPDATE OR DELETE ON shadow_vault.appointments
FOR EACH ROW EXECUTE FUNCTION monitor.track_shadow_changes();

-- Honeypot throttle function
CREATE OR REPLACE FUNCTION shadow_vault.apply_delay()
RETURNS VOID AS $$
DECLARE delay INT;
BEGIN
    SELECT config_value INTO delay FROM shadow_vault.system_state WHERE config_key = 'throttle_delay_ms';
    PERFORM pg_sleep(delay / 1000.0);
END;
$$ LANGUAGE plpgsql;


-- =====================================================================
-- SEED DATA: AUTHENTICATION USERS
-- =====================================================================

-- Admin user
INSERT INTO public.users (user_id, email, role) VALUES 
('c0000001-0000-0000-0000-000000000001', 'admin@serenity.care', 'admin')
ON CONFLICT (email) DO NOTHING;

-- Doctor users
INSERT INTO public.users (user_id, email, role) VALUES
('a1b2c3d4-0001-0001-0001-000000000001', 'fatima.rehman@serenity.care',   'doctor'),
('a1b2c3d4-0002-0002-0002-000000000002', 'ali.kamran.doc@serenity.care',  'doctor'),
('a1b2c3d4-0003-0003-0003-000000000003', 'sarah.jenkins.doc@serenity.care','doctor')
ON CONFLICT (email) DO NOTHING;

-- Patient users
INSERT INTO public.users (user_id, email, role) VALUES
('b0000001-0000-0000-0000-000000000001', 'ali.kamran@patient.serenity.care',    'patient'),
('b0000002-0000-0000-0000-000000000002', 'elena.rostova@patient.serenity.care', 'patient'),
('b0000003-0000-0000-0000-000000000003', 'michael.chang@patient.serenity.care', 'patient'),
('b0000004-0000-0000-0000-000000000004', 'ayesha.tariq@patient.serenity.care',  'patient'),
('b0000005-0000-0000-0000-000000000005', 'robert.hayes@patient.serenity.care',  'patient'),
('b0000006-0000-0000-0000-000000000006', 'sarah.jenkins@patient.serenity.care', 'patient'),
('b0000007-0000-0000-0000-000000000007', 'david.chen@patient.serenity.care',    'patient'),
('b0000008-0000-0000-0000-000000000008', 'omar.farooq@patient.serenity.care',   'patient'),
('b0000009-0000-0000-0000-000000000009', 'rachel.adams@patient.serenity.care',  'patient'),
('b0000010-0000-0000-0000-000000000010', 'james.wilson@patient.serenity.care',  'patient'),
('b0000011-0000-0000-0000-000000000011', 'marcus.vance@patient.serenity.care',  'patient'),
('b0000012-0000-0000-0000-000000000012', 'liam.wright@patient.serenity.care',   'patient'),
('b0000013-0000-0000-0000-000000000013', 'chloe.bennett@patient.serenity.care', 'patient'),
('b0000014-0000-0000-0000-000000000014', 'daniel.thorne@patient.serenity.care', 'patient'),
('b0000015-0000-0000-0000-000000000015', 'zara.malik@patient.serenity.care',    'patient')
ON CONFLICT (email) DO NOTHING;

-- =====================================================================
-- SEED DATA: DOCTORS
-- =====================================================================

INSERT INTO public.doctors (doc_id, user_id, full_name, specialization) VALUES
('DOC-001', 'a1b2c3d4-0001-0001-0001-000000000001', 'Dr. Fatima Rehman',  'Consultant Psychiatrist – Anxiety & Mood Disorders'),
('DOC-002', 'a1b2c3d4-0002-0002-0002-000000000002', 'Dr. Ali Kamran',     'Consultant Psychiatrist – Trauma & Psychosis'),
('DOC-003', 'a1b2c3d4-0003-0003-0003-000000000003', 'Dr. Sarah Jenkins',  'Consultant Psychiatrist – Personality & Eating Disorders')
ON CONFLICT (doc_id) DO NOTHING;


-- =====================================================================
-- SEED DATA: PATIENTS (Mapped directly to doc_id)
-- =====================================================================

INSERT INTO public.patients (mrn, user_id, doc_id, full_name, primary_diagnosis, active_treatment, status) VALUES
-- Dr. Fatima Rehman's Patients
('PT-101',  'b0000001-0000-0000-0000-000000000001', 'DOC-001', 'Ali Kamran', 'Generalized Anxiety Disorder (GAD)', 'Escitalopram 10mg (morning) / Zolpidem 5mg (bedtime, max 14 days)', 'High Risk'),
('PT-4211', 'b0000002-0000-0000-0000-000000000002', 'DOC-001', 'Elena Rostova', 'Borderline Personality Disorder (BPD)', 'DBT Intensive Programme / Dialectical Behaviour Therapy', 'Critical'),
('PT-8832', 'b0000003-0000-0000-0000-000000000003', 'DOC-001', 'Michael Chang', 'Severe Obsessive-Compulsive Disorder (OCD)', 'Fluoxetine 60mg (morning)', 'Review'),
('PT-1198', 'b0000004-0000-0000-0000-000000000004', 'DOC-001', 'Ayesha Tariq', 'Complex PTSD (C-PTSD)', 'Venlafaxine 100mg (morning) / Prazosin 2mg (bedtime for nightmares)', 'High Risk'),
('PT-7045', 'b0000005-0000-0000-0000-000000000005', 'DOC-001', 'Robert Hayes', 'Narcissistic Personality Disorder (NPD)', 'No pharmacological treatment; Psychodynamic Therapy only', 'Stable'),

-- Dr. Ali Kamran's Patients
('PT-2099', 'b0000006-0000-0000-0000-000000000006', 'DOC-002', 'Sarah Jenkins', 'Major Depressive Disorder (MDD)', 'Sertraline 50mg (morning)', 'Stable'),
('PT-5502', 'b0000007-0000-0000-0000-000000000007', 'DOC-002', 'David Chen', 'PTSD – Combat Related', 'Prazosin 2mg (bedtime)', 'Stable'),
('PT-6610', 'b0000008-0000-0000-0000-000000000008', 'DOC-002', 'Omar Farooq', 'Schizoaffective Disorder – Bipolar Type', 'Paliperidone 15mg (morning) / Divalproex (Depakote) 500mg twice daily', 'Critical'),
('PT-3321', 'b0000009-0000-0000-0000-000000000009', 'DOC-002', 'Rachel Adams', 'Severe Clinical Depression with Suicidal Ideation', 'Bupropion XL 150mg (morning) / Mirtazapine 15mg (bedtime)', 'High Risk'),
('PT-9012', 'b0000010-0000-0000-0000-000000000010', 'DOC-002', 'James Wilson', 'Intermittent Explosive Disorder (IED)', 'Oxcarbazepine 300mg twice daily', 'Review'),

-- Dr. Sarah Jenkins's Patients
('PT-3105', 'b0000011-0000-0000-0000-000000000011', 'DOC-003', 'Marcus Vance', 'Bipolar II Disorder', 'Lithium Carbonate 400mg twice daily', 'Review'),
('PT-7734', 'b0000012-0000-0000-0000-000000000012', 'DOC-003', 'Liam Wright', 'Substance-Induced Psychosis (Cannabis)', 'Olanzapine 10mg (bedtime)', 'Review'),
('PT-4488', 'b0000013-0000-0000-0000-000000000013', 'DOC-003', 'Chloe Bennett', 'Anorexia Nervosa – Restricting Type (Severe)', 'Olanzapine 5mg (bedtime) / Nutritional supplements (Ensure Plus 3x daily)', 'Critical'),
('PT-5120', 'b0000014-0000-0000-0000-000000000014', 'DOC-003', 'Daniel Thorne', 'Antisocial Personality Disorder (ASPD)', 'No pharmacological treatment; Structured Psychotherapy (Schema-focused)', 'Stable'),
('PT-8201', 'b0000015-0000-0000-0000-000000000015', 'DOC-003', 'Zara Malik', 'Dissociative Identity Disorder (DID)', 'Quetiapine 50mg (bedtime for sleep regulation)', 'Review')
ON CONFLICT (mrn) DO NOTHING;


-- =====================================================================
-- SEED DATA: CLINICAL NOTES
-- =====================================================================

INSERT INTO public.clinical_notes (mrn, doc_id, notes_text) VALUES
('PT-101',  'DOC-001', 'Session 14 – Patient reports persistent anxiety and nightly insomnia averaging 3–4 hrs sleep. Somatic symptoms (tachycardia) present. Anxious attachment traits and fear of abandonment noted. CBT thought-record exercise assigned. Response to Escitalopram being monitored; no SSRI side-effects reported so far. Next milestone: reassess Zolpidem after 14-day window.'),
('PT-4211', 'DOC-001', 'Session 22 – Active self-harm monitoring in place. Mandatory daily check-ins required per protocol. Identity disturbance and emotional dysregulation remain primary concerns. DBT skills (TIPP, DEAR MAN) being practised. Family session scheduled for next month. Safety plan reviewed and signed.'),
('PT-8832', 'DOC-001', 'Session 45 – ERP (Exposure and Response Prevention) continuing. Patient showing incremental improvement in contamination obsessions. Work-related compulsions persist. Fluoxetine at maximum therapeutic dose. Referral to OCD specialist clinic under consideration for augmentation therapy.'),
('PT-1198', 'DOC-001', 'Session 8 – Severe night terrors and hypervigilance reported. Trauma processing via EMDR commenced. Patient exhibiting high distress; do not leave unattended during facility visits per clinical protocol. Prazosin showing early positive effect on nightmare frequency.'),
('PT-7045', 'DOC-001', 'Session 3 – Court-mandated attendance. Patient uncooperative; displays entitlement and lack of insight. Therapeutic alliance building remains primary goal. Motivational interviewing approach adopted. Progress notes shared with referring legal team per consent form.'),
('PT-2099', 'DOC-002', 'Session 4 – Patient reports low mood, social withdrawal, and fatigue. PHQ-9 score: 14 (moderate). Sertraline initiated 3 weeks ago; partial response noted. Behavioural activation and journaling assigned. Next session: review PHQ-9 and consider dose titration.'),
('PT-5502', 'DOC-002', 'Session 11 – Nightmare frequency reduced from nightly to 2–3x/week. PCL-5 improving. CPT (Cognitive Processing Therapy) modules progressing well. Patient re-engaged with family activities. Prazosin to continue; review in 4 weeks.'),
('PT-6610', 'DOC-002', 'Session 32 – Persecutory delusions and grandiose ideation persistent. Inpatient evaluation being arranged. Medication compliance confirmed via pill count. Family psychoeducation session completed. Risk: HIGH. Requires supervised living arrangement until next assessment.'),
('PT-3321', 'DOC-002', 'Session 19 – Missed last two scheduled check-ins. Emergency contact notified. PHQ-9 score: 21 (severe). Patient reports passive SI without active plan. Safety contract renewed. Local crisis team on alert. Inpatient admission being evaluated.'),
('PT-9012', 'DOC-002', 'Session 6 – Anger management exercises (STOP technique, cool-down protocols) assigned. Patient verbally threatened staff member last session; security protocol activated. Guard presence mandatory for all future sessions. Partner also expressing fear; couples counselling referral made.'),
('PT-3105', 'DOC-003', 'Session 9 – Hypomanic episode reported by family (decreased sleep, increased spending). Lithium level: 0.6 mEq/L – slightly subtherapeutic. Dose increase to 600mg twice daily advised. Mood diary assigned. Patient education on lithium toxicity signs provided.'),
('PT-7734', 'DOC-003', 'Session 12 – Mandatory drug screening required prior to next session. Abstinence reported but not yet verified. Psychotic symptoms resolving with Olanzapine. Motivational enhancement therapy (MET) commenced for cannabis use. Probation officer updated per court order.'),
('PT-4488', 'DOC-003', 'Session 54 – BMI: 14.2 – below critical threshold. Medical monitoring daily. Involuntary tube-feeding protocol being prepared per eating disorder protocol. Inpatient admission to specialist unit imminent. Next of kin notified.'),
('PT-5120', 'DOC-003', 'Session 2 – Parole board requirement. Zero insight into impact of actions. Therapeutic goals limited to court-stipulated attendance and minimal harm reduction. All sessions documented verbatim for legal record. Keep sessions brief.'),
('PT-8201', 'DOC-003', 'Session 88 – New alter ("Lena") emerged in session 86. Integration work ongoing. No imminent risk. Complex trauma history being processed via Parts work. Continuous progress monitoring; trauma timeline being constructed collaboratively.')
ON CONFLICT DO NOTHING;


-- =====================================================================
-- SEED DATA: APPOINTMENTS
-- =====================================================================

INSERT INTO public.appointments (mrn, doc_id, scheduled_at, is_urgent, status) VALUES
('PT-101',  'DOC-001', '2026-04-28 09:00:00+00', FALSE, 'Scheduled'),
('PT-4211', 'DOC-001', '2026-04-30 08:15:00+00', FALSE, 'Scheduled'),
('PT-8832', 'DOC-001', '2026-05-01 05:00:00+00', FALSE, 'Scheduled'),
('PT-1198', 'DOC-001', '2026-05-03 10:30:00+00', TRUE,  'Scheduled'),
('PT-7045', 'DOC-001', '2026-05-05 04:00:00+00', FALSE, 'Scheduled'),
('PT-2099', 'DOC-002', '2026-04-30 09:30:00+00', FALSE, 'Scheduled'),
('PT-5502', 'DOC-002', '2026-05-01 05:45:00+00', FALSE, 'Scheduled'),
('PT-6610', 'DOC-002', '2026-04-29 06:00:00+00', TRUE,  'Scheduled'),
('PT-3321', 'DOC-002', '2026-04-30 09:00:00+00', TRUE,  'Scheduled'),
('PT-9012', 'DOC-002', '2026-05-02 11:15:00+00', FALSE, 'Scheduled'),
('PT-3105', 'DOC-003', '2026-04-29 04:00:00+00', FALSE, 'Scheduled'),
('PT-7734', 'DOC-003', '2026-05-02 06:00:00+00', FALSE, 'Scheduled'),
('PT-4488', 'DOC-003', '2026-04-27 03:30:00+00', TRUE,  'Scheduled'),
('PT-5120', 'DOC-003', '2026-05-01 08:00:00+00', FALSE, 'Scheduled'),
('PT-8201', 'DOC-003', '2026-05-03 05:00:00+00', FALSE, 'Scheduled')
ON CONFLICT DO NOTHING;


-- =====================================================================
-- SEED DATA: DAILY TASKS
-- =====================================================================

INSERT INTO public.daily_tasks (mrn, task_title, task_description, is_done) VALUES
('PT-101', 'Morning Medication', 'Take 1x Escitalopram 10mg with breakfast. Do not skip.', FALSE),
('PT-101', '5-4-3-2-1 Grounding Technique', 'During any moment of acute anxiety: name 5 things you see, 4 you can touch, 3 you hear, 2 you smell, 1 you taste.', FALSE),
('PT-101', 'CBT Thought Record Journal', 'Write down one anxious or jealous thought today: the trigger, the automatic thought, and a balanced counter-thought.', FALSE),
('PT-4211', 'Daily DBT Check-In Call', 'Call the clinic check-in line between 09:00–10:00 AM. Mandatory per safety plan.', FALSE),
('PT-4211', 'TIPP Skill Practice', 'Use TIPP (Temperature, Intense Exercise, Paced Breathing, Progressive Relaxation) when urges arise. Log in diary.', FALSE),
('PT-4211', 'Emotion Diary Card', 'Complete your DBT diary card for today. Rate each emotion 0–5 and note any self-harm urges.', FALSE),
('PT-8832', 'Morning Medication', 'Take 1x Fluoxetine 60mg with breakfast.', FALSE),
('PT-8832', 'ERP Exercise – Tier 2 Item', 'Complete today''s assigned ERP hierarchy item. Resist compulsion for full 45 minutes. Record distress level (SUDS).', FALSE),
('PT-8832', 'OCD Thought Log', 'Write down any obsessional thoughts. Label them as OCD, do not engage. Practice defusion.', FALSE),
('PT-1198', 'Morning Medication', 'Take 1x Venlafaxine 100mg with breakfast. Take 1x Prazosin 2mg at bedtime.', FALSE),
('PT-1198', 'Box Breathing (Pranayama) – 5 Minutes', 'Inhale 4s → Hold 4s → Exhale 4s → Hold 4s. Repeat for 5 minutes before sleep to regulate nervous system.', FALSE),
('PT-1198', 'Grounding Journal Entry', 'Write 3 safe things about your current environment. If a flashback occurs, use the safe-place visualisation from session.', FALSE),
('PT-7045', 'Reflective Journaling', 'Write one paragraph today describing how your actions affected another person. Practise perspective-taking.', FALSE),
('PT-7045', 'Attend Scheduled Session', 'Mandatory court-ordered attendance. Confirm attendance via portal by 08:00 AM on session day.', FALSE),
('PT-7045', 'Empathy Mapping Exercise', 'Choose one recent interpersonal conflict. Write what the other person likely felt. No justifications.', FALSE),
('PT-2099', 'Morning Medication', 'Take 1x Sertraline 50mg with breakfast.', FALSE),
('PT-2099', 'Behavioural Activation – 20 Min Activity', 'Do one pleasurable or purposeful activity today (walk, phone a friend, cook). Record in mood diary.', FALSE),
('PT-2099', 'Mood & Thought Journal', 'Write 3 automatic negative thoughts and one evidence-based reframe for each.', FALSE),
('PT-5502', 'Bedtime Medication', 'Take 1x Prazosin 2mg 30 minutes before sleep.', FALSE),
('PT-5502', 'CPT Module Practice', 'Review your Stuck Points worksheet. Identify one stuck point and work through the challenging questions sheet.', FALSE),
('PT-5502', 'Sleep Log', 'Record sleep onset time, wake times, and nightmare occurrence (Y/N) in your sleep diary each morning.', FALSE),
('PT-6610', 'Morning Medication (CRITICAL)', 'Take 1x Paliperidone 15mg and 1x Divalproex 500mg with breakfast. Medication must not be skipped.', FALSE),
('PT-6610', 'Evening Medication', 'Take 1x Divalproex 500mg with dinner.', FALSE),
('PT-6610', 'Reality Testing Log', 'If you experience a suspicious thought or belief, write it down. Rate your conviction 0–10. Show to your support person.', FALSE),
('PT-3321', 'Morning Medication', 'Take 1x Bupropion XL 150mg with breakfast. Take 1x Mirtazapine 15mg at bedtime.', FALSE),
('PT-3321', 'Safety Check-In', 'Text or call your designated support contact by 10:00 AM. Log contact made in portal.', FALSE),
('PT-3321', 'Crisis Plan Review', 'Re-read your personal safety plan. Identify your three warning signs today. Note any SI thoughts in your mood diary.', FALSE),
('PT-9012', 'Morning Medication', 'Take 1x Oxcarbazepine 300mg with breakfast and 1x Oxcarbazepine 300mg with dinner.', FALSE),
('PT-9012', 'STOP Technique Practice', 'When anger rises: Stop → Take a breath → Observe your feeling → Proceed mindfully. Log any anger episodes.', FALSE),
('PT-9012', 'Cool-Down Protocol Log', 'Record today''s anger intensity (0–10). Note triggers and which cool-down strategy you used.', FALSE),
('PT-3105', 'Morning Medication', 'Take 1x Lithium Carbonate 600mg with breakfast. Take 1x Lithium Carbonate 600mg with dinner (NEW DOSE).', FALSE),
('PT-3105', 'Mood Diary Entry', 'Rate today''s mood on a scale of -3 (depressed) to +3 (hypomanic). Record sleep hours and any impulsive urges.', FALSE),
('PT-3105', 'Lithium Toxicity Self-Check', 'Check for: nausea, tremor, blurred vision, unsteady gait, confusion. If any present, contact clinic immediately.', FALSE),
('PT-7734', 'Evening Medication', 'Take 1x Olanzapine 10mg at bedtime.', FALSE),
('PT-7734', 'Abstinence Check', 'Record: Did you use cannabis today? (Y/N). If yes, contact your MET counsellor immediately.', FALSE),
('PT-7734', 'MET Decisional Balance Exercise', 'List one benefit and one cost of cannabis use today. Add to your running log sheet from session.', FALSE),
('PT-4488', 'Nutritional Supplement – 3x Daily (CRITICAL)', 'Drink 1x Ensure Plus with each meal (breakfast, lunch, dinner). Non-negotiable. Record in nutrition log.', FALSE),
('PT-4488', 'Evening Medication', 'Take 1x Olanzapine 5mg at bedtime.', FALSE),
('PT-4488', 'Meals Log & Body Image Journal', 'Record all food/drink consumed today. Write one body-neutral affirmation. Share log at next session.', FALSE),
('PT-5120', 'Confirm Session Attendance', 'Confirm attendance for this week''s scheduled session via portal before 08:00 AM. Court reporting requires this log.', FALSE),
('PT-5120', 'Schema Journal', 'Write one example today of noticing an old maladaptive schema (e.g. Entitlement, Predatory) being triggered. Do not act on it.', FALSE),
('PT-5120', 'Harm Reduction Log', 'List one situation today where you chose not to manipulate or deceive. Record what you did instead.', FALSE),
('PT-8201', 'Evening Medication', 'Take 1x Quetiapine 50mg at bedtime for sleep regulation.', FALSE),
('PT-8201', 'Parts Journal – Daily Check-In', 'Ask each known part: "How are you today?" Write their response. Note any new voices or perspectives.', FALSE),
('PT-8201', 'Grounding After Dissociation', 'If you experience a dissociative episode, use the 5-senses grounding card. Log: duration, trigger, and which part was present.', FALSE)
ON CONFLICT DO NOTHING;

-- =====================================================================
-- SEED DATA: SHADOW VAULT (HONEYPOT LURES)
-- =====================================================================

INSERT INTO shadow_vault.patients (mrn, user_id, doc_id, full_name, primary_diagnosis, active_treatment, status) VALUES
  ('PT-SHADOW-001', 'f2222222-2222-2222-2222-222222222222', 'DOC-001', 'Eleanor Voss', 'Generalised Anxiety Disorder (F41.1)', 'Sertraline 50mg', 'Stable'),
  ('PT-SHADOW-002', 'f2222222-2222-2222-2222-222222222222', 'DOC-001', 'Marcus Delray', 'Major Depressive Disorder (F32.1)', 'Fluoxetine 20mg', 'Active'),
  ('PT-SHADOW-003', 'f2222222-2222-2222-2222-222222222222', 'DOC-001', 'Priya Nair', 'Bipolar II Disorder (F31.81)', 'Lamotrigine 100mg', 'Stable')
ON CONFLICT DO NOTHING;