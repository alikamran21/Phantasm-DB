-- ============================================================
--  PHANTASM-DB | Serenity Psychiatric Care EHR
--  FILE: database/production/serenity_production_schema.sql
--  PURPOSE: Production relational schema for Doctor & Patient portals
--  AUTHOR: Serenity EHR Backend
--  NOTE: IDs and Names in this schema are REAL production credentials.
--        The Honeypot (doctor_trap / patient_trap) uses the SAME
--        doctor/patient IDs & names but all other data is fabricated
--        (fake appointments, fake notes, different MRNs range).
-- ============================================================

-- ============================================================
-- SECTION 0: DATABASE SETUP
-- ============================================================
-- Run this as a superuser once:
-- CREATE DATABASE serenity_ehr;
-- \c serenity_ehr

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- for gen_random_uuid(), crypt()

-- ============================================================
-- SECTION 1: ENUMERATIONS (DOMAIN TYPES)
-- ============================================================

CREATE TYPE user_role         AS ENUM ('doctor', 'patient', 'admin');
CREATE TYPE patient_status    AS ENUM ('Stable', 'Review', 'High Risk', 'Critical', 'Inactive');
CREATE TYPE appt_status       AS ENUM ('Scheduled', 'Completed', 'Cancelled', 'Rescheduled', 'No-Show', 'Urgent');
CREATE TYPE task_status       AS ENUM ('PENDING', 'DONE', 'SKIPPED');
CREATE TYPE otp_purpose       AS ENUM ('login', 'password_reset', 'account_verify');

-- ============================================================
-- SECTION 2: CORE AUTHENTICATION TABLE
-- ============================================================
-- All three roles (doctor, patient, admin) authenticate through
-- this single table. The role field drives routing_engine.py.

CREATE TABLE auth_users (
    user_id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT            NOT NULL UNIQUE,
    role            user_role       NOT NULL,
    -- Hashed OTP (bcrypt via pgcrypto). Never store plaintext.
    otp_hash        TEXT            NULL,
    otp_expires_at  TIMESTAMPTZ     NULL,
    otp_purpose     otp_purpose     NULL,
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    last_login      TIMESTAMPTZ     NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE auth_users IS
    'Unified auth entry for all roles. OTP is emailed and stored as a bcrypt hash. '
    'Routing engine reads the role to redirect after OTP verification.';

-- ============================================================
-- SECTION 3: DOCTORS TABLE
-- ============================================================

CREATE TABLE doctors (
    doc_id          TEXT            PRIMARY KEY,   -- e.g. 'DOC-001'
    user_id         UUID            NOT NULL UNIQUE REFERENCES auth_users(user_id) ON DELETE CASCADE,
    full_name       TEXT            NOT NULL,
    specialization  TEXT            NOT NULL DEFAULT 'Consultant Psychiatrist',
    phone           TEXT            NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE doctors IS
    'Provider directory. doc_id is the human-readable identifier shown in UI. '
    'user_id is the FK into auth_users for login linkage.';

-- ============================================================
-- SECTION 4: PATIENTS TABLE
-- ============================================================

CREATE TABLE patients (
    mrn             TEXT            PRIMARY KEY,   -- Medical Record Number e.g. 'PT-101'
    user_id         UUID            NOT NULL UNIQUE REFERENCES auth_users(user_id) ON DELETE CASCADE,
    full_name       TEXT            NOT NULL,
    date_of_birth   DATE            NULL,
    gender          TEXT            NULL,
    phone           TEXT            NULL,
    -- Medical core (read-only for patient, writable by doctor)
    primary_diagnosis       TEXT    NULL,
    active_treatment        TEXT    NULL,   -- prescriptions / therapy plan
    clinical_notes          TEXT    NULL,   -- cumulative session notes
    status                  patient_status NOT NULL DEFAULT 'Review',
    total_sessions          INTEGER NOT NULL DEFAULT 0,
    -- Fee tracking
    consultation_fee_paid   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE patients IS
    'Core patient record. Medical fields are updated only by the assigned doctor via '
    'the provider portal. Patients have read-only access to their own diagnosis/rx.';

-- ============================================================
-- SECTION 5: DOCTOR–PATIENT ASSIGNMENT (RBAC CORE)
-- ============================================================

CREATE TABLE doctor_patients (
    doc_id          TEXT            NOT NULL REFERENCES doctors(doc_id)  ON DELETE CASCADE,
    mrn             TEXT            NOT NULL REFERENCES patients(mrn)    ON DELETE CASCADE,
    assigned_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (doc_id, mrn)
);

COMMENT ON TABLE doctor_patients IS
    'The RBAC linking table. A doctor can ONLY read/write patients whose MRN '
    'appears here under their doc_id. backend/app.py enforces this at every query.';

-- ============================================================
-- SECTION 6: APPOINTMENTS TABLE
-- ============================================================

CREATE TABLE appointments (
    appt_id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    mrn             TEXT            NOT NULL REFERENCES patients(mrn)   ON DELETE CASCADE,
    doc_id          TEXT            NOT NULL REFERENCES doctors(doc_id) ON DELETE CASCADE,
    scheduled_at    TIMESTAMPTZ     NOT NULL,
    duration_min    INTEGER         NOT NULL DEFAULT 45,
    status          appt_status     NOT NULL DEFAULT 'Scheduled',
    is_urgent       BOOLEAN         NOT NULL DEFAULT FALSE,
    notes           TEXT            NULL,   -- doctor's post-session remarks
    created_by_role user_role       NOT NULL DEFAULT 'doctor',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE appointments IS
    'Scheduling table. Both doctor and patient portals read/write here. '
    'Patients can request/cancel; doctors can schedule/delay/cancel. '
    'is_urgent = TRUE maps to the "Crisis Booking" flag in patient portal.';

-- ============================================================
-- SECTION 7: DAILY TASKS TABLE (JIRA-STYLE TREATMENT CHECKLIST)
-- ============================================================

CREATE TABLE patient_tasks (
    task_id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    mrn             TEXT            NOT NULL REFERENCES patients(mrn) ON DELETE CASCADE,
    doc_id          TEXT            NOT NULL REFERENCES doctors(doc_id),
    title           TEXT            NOT NULL,
    description     TEXT            NULL,
    status          task_status     NOT NULL DEFAULT 'PENDING',
    task_date       DATE            NOT NULL DEFAULT CURRENT_DATE,
    completed_at    TIMESTAMPTZ     NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE patient_tasks IS
    'Daily treatment compliance tasks assigned by the doctor. '
    'Patients check/uncheck via portal; Save Progress Log sets status to DONE. '
    'Doctors monitor compliance from the provider portal detail view.';

-- ============================================================
-- SECTION 8: DOCUMENT UPLOADS & OCR EXTRACTIONS
-- ============================================================

CREATE TABLE patient_documents (
    doc_uuid        UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    mrn             TEXT            NOT NULL REFERENCES patients(mrn) ON DELETE CASCADE,
    uploaded_by     UUID            NOT NULL REFERENCES auth_users(user_id),
    file_name       TEXT            NOT NULL,
    file_path       TEXT            NOT NULL,   -- server-side storage path
    mime_type       TEXT            NOT NULL DEFAULT 'application/pdf',
    ocr_text        TEXT            NULL,       -- extracted text appended to clinical_notes
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SECTION 9: AUDIT LOG (HONEYPOT ALERT INTEGRATION)
-- ============================================================

CREATE TABLE audit_log (
    log_id          BIGSERIAL       PRIMARY KEY,
    user_id         UUID            NULL REFERENCES auth_users(user_id),
    action          TEXT            NOT NULL,
    target_table    TEXT            NULL,
    target_id       TEXT            NULL,
    ip_address      INET            NULL,
    user_agent      TEXT            NULL,
    is_suspicious   BOOLEAN         NOT NULL DEFAULT FALSE,
    metadata        JSONB           NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_log IS
    'Full forensic trail. honeypot.py and alerts.py write here when intruder '
    'activity is detected on the trap portals. is_suspicious = TRUE triggers '
    'admin dashboard alert.';

-- ============================================================
-- SECTION 10: OTP RATE-LIMITING
-- ============================================================

CREATE TABLE otp_attempts (
    attempt_id      BIGSERIAL       PRIMARY KEY,
    email           TEXT            NOT NULL,
    ip_address      INET            NULL,
    success         BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SECTION 11: INDEXES FOR QUERY PERFORMANCE
-- ============================================================

CREATE INDEX idx_doctor_patients_doc   ON doctor_patients(doc_id);
CREATE INDEX idx_doctor_patients_mrn   ON doctor_patients(mrn);
CREATE INDEX idx_appointments_mrn      ON appointments(mrn);
CREATE INDEX idx_appointments_doc      ON appointments(doc_id);
CREATE INDEX idx_appointments_scheduled ON appointments(scheduled_at DESC);
CREATE INDEX idx_tasks_mrn_date        ON patient_tasks(mrn, task_date DESC);
CREATE INDEX idx_audit_user            ON audit_log(user_id);
CREATE INDEX idx_audit_suspicious      ON audit_log(is_suspicious) WHERE is_suspicious = TRUE;
CREATE INDEX idx_otp_email_time        ON otp_attempts(email, created_at DESC);

-- ============================================================
-- SECTION 12: AUTO-UPDATE TRIGGER FOR updated_at
-- ============================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auth_users_updated_at
    BEFORE UPDATE ON auth_users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_patients_updated_at
    BEFORE UPDATE ON patients
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_appointments_updated_at
    BEFORE UPDATE ON appointments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_tasks_updated_at
    BEFORE UPDATE ON patient_tasks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- SECTION 13: SEED DATA — 3 DOCTORS
-- ============================================================
-- Passwords/OTPs are NEVER stored here. auth_users.otp_hash is
-- populated at login-time by the Python backend via bcrypt.
-- Emails below are real portal login emails.

INSERT INTO auth_users (user_id, email, role) VALUES
    ('a1b2c3d4-0001-0001-0001-000000000001', 'fatima.rehman@serenity.care',   'doctor'),
    ('a1b2c3d4-0002-0002-0002-000000000002', 'ali.kamran.doc@serenity.care',   'doctor'),
    ('a1b2c3d4-0003-0003-0003-000000000003', 'sarah.jenkins.doc@serenity.care','doctor');

INSERT INTO doctors (doc_id, user_id, full_name, specialization) VALUES
    ('DOC-001', 'a1b2c3d4-0001-0001-0001-000000000001', 'Dr. Fatima Rehman',  'Consultant Psychiatrist – Anxiety & Mood Disorders'),
    ('DOC-002', 'a1b2c3d4-0002-0002-0002-000000000002', 'Dr. Ali Kamran',     'Consultant Psychiatrist – Trauma & Psychosis'),
    ('DOC-003', 'a1b2c3d4-0003-0003-0003-000000000003', 'Dr. Sarah Jenkins',  'Consultant Psychiatrist – Personality & Eating Disorders');

-- ============================================================
-- SECTION 14: SEED DATA — 15 PATIENTS (auth_users + patients)
-- ============================================================
-- MRNs and full_names match the trap portals exactly.
-- All other data (emails, DOB, diagnosis etc.) is PRODUCTION data
-- and differs from the honeypot's fabricated records.

-- ── Auth accounts ──────────────────────────────────────────
INSERT INTO auth_users (user_id, email, role) VALUES
    -- Dr. Fatima Rehman's 5 patients
    ('b0000001-0000-0000-0000-000000000001', 'ali.kamran@patient.serenity.care',    'patient'),
    ('b0000002-0000-0000-0000-000000000002', 'elena.rostova@patient.serenity.care', 'patient'),
    ('b0000003-0000-0000-0000-000000000003', 'michael.chang@patient.serenity.care', 'patient'),
    ('b0000004-0000-0000-0000-000000000004', 'ayesha.tariq@patient.serenity.care',  'patient'),
    ('b0000005-0000-0000-0000-000000000005', 'robert.hayes@patient.serenity.care',  'patient'),
    -- Dr. Ali Kamran's 5 patients
    ('b0000006-0000-0000-0000-000000000006', 'sarah.jenkins@patient.serenity.care', 'patient'),
    ('b0000007-0000-0000-0000-000000000007', 'david.chen@patient.serenity.care',    'patient'),
    ('b0000008-0000-0000-0000-000000000008', 'omar.farooq@patient.serenity.care',   'patient'),
    ('b0000009-0000-0000-0000-000000000009', 'rachel.adams@patient.serenity.care',  'patient'),
    ('b0000010-0000-0000-0000-000000000010', 'james.wilson@patient.serenity.care',  'patient'),
    -- Dr. Sarah Jenkins's 5 patients
    ('b0000011-0000-0000-0000-000000000011', 'marcus.vance@patient.serenity.care',  'patient'),
    ('b0000012-0000-0000-0000-000000000012', 'liam.wright@patient.serenity.care',   'patient'),
    ('b0000013-0000-0000-0000-000000000013', 'chloe.bennett@patient.serenity.care', 'patient'),
    ('b0000014-0000-0000-0000-000000000014', 'daniel.thorne@patient.serenity.care', 'patient'),
    ('b0000015-0000-0000-0000-000000000015', 'zara.malik@patient.serenity.care',    'patient');

-- ── Patient medical records ────────────────────────────────
INSERT INTO patients
    (mrn, user_id, full_name, date_of_birth, gender,
     primary_diagnosis, active_treatment, clinical_notes,
     status, total_sessions, consultation_fee_paid)
VALUES

-- ── DOCTOR: Dr. Fatima Rehman ──────────────────────────────

('PT-101',
 'b0000001-0000-0000-0000-000000000001',
 'Ali Kamran', '1995-08-14', 'Male',
 'Generalized Anxiety Disorder (GAD)',
 'Escitalopram 10mg (morning) / Zolpidem 5mg (bedtime, max 14 days)',
 'Session 14 – Patient reports persistent anxiety and nightly insomnia averaging 3–4 hrs sleep. Somatic symptoms (tachycardia) present. '
 'Anxious attachment traits and fear of abandonment noted. CBT thought-record exercise assigned. '
 'Response to Escitalopram being monitored; no SSRI side-effects reported so far. '
 'Next milestone: reassess Zolpidem after 14-day window.',
 'High Risk', 14, TRUE),

('PT-4211',
 'b0000002-0000-0000-0000-000000000002',
 'Elena Rostova', '1990-03-22', 'Female',
 'Borderline Personality Disorder (BPD)',
 'DBT Intensive Programme / Dialectical Behaviour Therapy – weekly individual + group',
 'Session 22 – Active self-harm monitoring in place. Mandatory daily check-ins required per protocol. '
 'Identity disturbance and emotional dysregulation remain primary concerns. DBT skills (TIPP, DEAR MAN) being practised. '
 'Family session scheduled for next month. Safety plan reviewed and signed.',
 'Critical', 22, TRUE),

('PT-8832',
 'b0000003-0000-0000-0000-000000000003',
 'Michael Chang', '1988-11-05', 'Male',
 'Severe Obsessive-Compulsive Disorder (OCD)',
 'Fluoxetine 60mg (morning)',
 'Session 45 – ERP (Exposure and Response Prevention) continuing. Patient showing incremental improvement in contamination obsessions. '
 'Work-related compulsions persist. Fluoxetine at maximum therapeutic dose. '
 'Referral to OCD specialist clinic under consideration for augmentation therapy.',
 'Review', 45, TRUE),

('PT-1198',
 'b0000004-0000-0000-0000-000000000004',
 'Ayesha Tariq', '1997-06-30', 'Female',
 'Complex PTSD (C-PTSD)',
 'Venlafaxine 100mg (morning) / Prazosin 2mg (bedtime for nightmares)',
 'Session 8 – Severe night terrors and hypervigilance reported. Trauma processing via EMDR commenced. '
 'Patient exhibiting high distress; do not leave unattended during facility visits per clinical protocol. '
 'Prazosin showing early positive effect on nightmare frequency.',
 'High Risk', 8, FALSE),

('PT-7045',
 'b0000005-0000-0000-0000-000000000005',
 'Robert Hayes', '1975-09-18', 'Male',
 'Narcissistic Personality Disorder (NPD)',
 'No pharmacological treatment; Psychodynamic Therapy only',
 'Session 3 – Court-mandated attendance. Patient uncooperative; displays entitlement and lack of insight. '
 'Therapeutic alliance building remains primary goal. Motivational interviewing approach adopted. '
 'Progress notes shared with referring legal team per consent form.',
 'Stable', 3, TRUE),

-- ── DOCTOR: Dr. Ali Kamran ─────────────────────────────────

('PT-2099',
 'b0000006-0000-0000-0000-000000000006',
 'Sarah Jenkins', '1993-04-11', 'Female',
 'Major Depressive Disorder (MDD)',
 'Sertraline 50mg (morning)',
 'Session 4 – Patient reports low mood, social withdrawal, and fatigue. PHQ-9 score: 14 (moderate). '
 'Sertraline initiated 3 weeks ago; partial response noted. Behavioural activation and journaling assigned. '
 'Next session: review PHQ-9 and consider dose titration.',
 'Stable', 4, TRUE),

('PT-5502',
 'b0000007-0000-0000-0000-000000000007',
 'David Chen', '1985-12-03', 'Male',
 'PTSD – Combat Related',
 'Prazosin 2mg (bedtime)',
 'Session 11 – Nightmare frequency reduced from nightly to 2–3x/week. PCL-5 improving. '
 'CPT (Cognitive Processing Therapy) modules progressing well. Patient re-engaged with family activities. '
 'Prazosin to continue; review in 4 weeks.',
 'Stable', 11, TRUE),

('PT-6610',
 'b0000008-0000-0000-0000-000000000008',
 'Omar Farooq', '1982-07-25', 'Male',
 'Schizoaffective Disorder – Bipolar Type',
 'Paliperidone 15mg (morning) / Divalproex (Depakote) 500mg twice daily',
 'Session 32 – Persecutory delusions and grandiose ideation persistent. Inpatient evaluation being arranged. '
 'Medication compliance confirmed via pill count. Family psychoeducation session completed. '
 'Risk: HIGH. Requires supervised living arrangement until next assessment.',
 'Critical', 32, TRUE),

('PT-3321',
 'b0000009-0000-0000-0000-000000000009',
 'Rachel Adams', '1991-02-14', 'Female',
 'Severe Clinical Depression with Suicidal Ideation',
 'Bupropion XL 150mg (morning) / Mirtazapine 15mg (bedtime)',
 'Session 19 – Missed last two scheduled check-ins. Emergency contact notified. PHQ-9 score: 21 (severe). '
 'Patient reports passive SI without active plan. Safety contract renewed. '
 'Local crisis team on alert. Inpatient admission being evaluated.',
 'High Risk', 19, FALSE),

('PT-9012',
 'b0000010-0000-0000-0000-000000000010',
 'James Wilson', '1987-10-09', 'Male',
 'Intermittent Explosive Disorder (IED)',
 'Oxcarbazepine 300mg twice daily',
 'Session 6 – Anger management exercises (STOP technique, cool-down protocols) assigned. '
 'Patient verbally threatened staff member last session; security protocol activated. '
 'Guard presence mandatory for all future sessions. Partner also expressing fear; couples counselling referral made.',
 'Review', 6, TRUE),

-- ── DOCTOR: Dr. Sarah Jenkins ──────────────────────────────

('PT-3105',
 'b0000011-0000-0000-0000-000000000011',
 'Marcus Vance', '1980-05-16', 'Male',
 'Bipolar II Disorder',
 'Lithium Carbonate 400mg twice daily',
 'Session 9 – Hypomanic episode reported by family (decreased sleep, increased spending). '
 'Lithium level: 0.6 mEq/L – slightly subtherapeutic. Dose increase to 600mg twice daily advised. '
 'Mood diary assigned. Patient education on lithium toxicity signs provided.',
 'Review', 9, TRUE),

('PT-7734',
 'b0000012-0000-0000-0000-000000000012',
 'Liam Wright', '1999-08-20', 'Male',
 'Substance-Induced Psychosis (Cannabis)',
 'Olanzapine 10mg (bedtime)',
 'Session 12 – Mandatory drug screening required prior to next session. Abstinence reported but not yet verified. '
 'Psychotic symptoms resolving with Olanzapine. Motivational enhancement therapy (MET) commenced for cannabis use. '
 'Probation officer updated per court order.',
 'Review', 12, TRUE),

('PT-4488',
 'b0000013-0000-0000-0000-000000000013',
 'Chloe Bennett', '2001-01-07', 'Female',
 'Anorexia Nervosa – Restricting Type (Severe)',
 'Olanzapine 5mg (bedtime) / Nutritional supplements (Ensure Plus 3x daily)',
 'Session 54 – BMI: 14.2 – below critical threshold. Medical monitoring daily. '
 'Involuntary tube-feeding protocol being prepared per eating disorder protocol. '
 'Inpatient admission to specialist unit imminent. Next of kin notified.',
 'Critical', 54, TRUE),

('PT-5120',
 'b0000014-0000-0000-0000-000000000014',
 'Daniel Thorne', '1978-03-31', 'Male',
 'Antisocial Personality Disorder (ASPD)',
 'No pharmacological treatment; Structured Psychotherapy (Schema-focused)',
 'Session 2 – Parole board requirement. Zero insight into impact of actions. '
 'Therapeutic goals limited to court-stipulated attendance and minimal harm reduction. '
 'All sessions documented verbatim for legal record. Keep sessions brief.',
 'Stable', 2, FALSE),

('PT-8201',
 'b0000015-0000-0000-0000-000000000015',
 'Zara Malik', '1994-09-12', 'Female',
 'Dissociative Identity Disorder (DID)',
 'Quetiapine 50mg (bedtime for sleep regulation)',
 'Session 88 – New alter ("Lena") emerged in session 86. Integration work ongoing. '
 'No imminent risk. Complex trauma history being processed via Parts work. '
 'Continuous progress monitoring; trauma timeline being constructed collaboratively.',
 'Review', 88, TRUE);

-- ============================================================
-- SECTION 15: DOCTOR–PATIENT ASSIGNMENTS
-- ============================================================

INSERT INTO doctor_patients (doc_id, mrn) VALUES
    -- Dr. Fatima Rehman
    ('DOC-001', 'PT-101'),
    ('DOC-001', 'PT-4211'),
    ('DOC-001', 'PT-8832'),
    ('DOC-001', 'PT-1198'),
    ('DOC-001', 'PT-7045'),
    -- Dr. Ali Kamran
    ('DOC-002', 'PT-2099'),
    ('DOC-002', 'PT-5502'),
    ('DOC-002', 'PT-6610'),
    ('DOC-002', 'PT-3321'),
    ('DOC-002', 'PT-9012'),
    -- Dr. Sarah Jenkins
    ('DOC-003', 'PT-3105'),
    ('DOC-003', 'PT-7734'),
    ('DOC-003', 'PT-4488'),
    ('DOC-003', 'PT-5120'),
    ('DOC-003', 'PT-8201');

-- ============================================================
-- SECTION 16: APPOINTMENTS SEED DATA
-- ============================================================
-- scheduled_at uses PKT = UTC+5. Stored as TIMESTAMPTZ (UTC).
-- PKT offset applied: subtract 5 hours for UTC storage.

INSERT INTO appointments (mrn, doc_id, scheduled_at, duration_min, status, is_urgent) VALUES
    -- Dr. Fatima Rehman's patients
    ('PT-101',  'DOC-001', '2026-04-28 09:00:00+00', 45, 'Scheduled',  FALSE),
    ('PT-4211', 'DOC-001', '2026-04-30 08:15:00+00', 60, 'Scheduled',  FALSE),
    ('PT-8832', 'DOC-001', '2026-05-01 05:00:00+00', 45, 'Scheduled',  FALSE),
    ('PT-1198', 'DOC-001', '2026-05-03 10:30:00+00', 60, 'Scheduled',  TRUE),
    ('PT-7045', 'DOC-001', '2026-05-05 04:00:00+00', 30, 'Scheduled',  FALSE),
    -- Dr. Ali Kamran's patients
    ('PT-2099', 'DOC-002', '2026-04-30 09:30:00+00', 45, 'Scheduled',  FALSE),
    ('PT-5502', 'DOC-002', '2026-05-01 05:45:00+00', 45, 'Scheduled',  FALSE),
    ('PT-6610', 'DOC-002', '2026-04-29 06:00:00+00', 60, 'Scheduled',  TRUE),
    ('PT-3321', 'DOC-002', '2026-04-30 09:00:00+00', 60, 'Scheduled',  TRUE),
    ('PT-9012', 'DOC-002', '2026-05-02 11:15:00+00', 45, 'Scheduled',  FALSE),
    -- Dr. Sarah Jenkins's patients
    ('PT-3105', 'DOC-003', '2026-04-29 04:00:00+00', 45, 'Scheduled',  FALSE),
    ('PT-7734', 'DOC-003', '2026-05-02 06:00:00+00', 45, 'Scheduled',  FALSE),
    ('PT-4488', 'DOC-003', '2026-04-27 03:30:00+00', 60, 'Scheduled',  TRUE),
    ('PT-5120', 'DOC-003', '2026-05-01 08:00:00+00', 30, 'Scheduled',  FALSE),
    ('PT-8201', 'DOC-003', '2026-05-03 05:00:00+00', 60, 'Scheduled',  FALSE);

-- ============================================================
-- SECTION 17: DAILY TASKS SEED DATA (All 15 Patients)
-- ============================================================
-- task_date = CURRENT_DATE so tasks show as "today's plan" on first load.
-- Each patient has 3 tasks reflecting their actual treatment plan.

INSERT INTO patient_tasks (mrn, doc_id, title, description, status, task_date) VALUES

-- PT-101 Ali Kamran (GAD + Insomnia) – Dr. Fatima Rehman
('PT-101', 'DOC-001', 'Morning Medication',
 'Take 1x Escitalopram 10mg with breakfast. Do not skip.', 'PENDING', CURRENT_DATE),
('PT-101', 'DOC-001', '5-4-3-2-1 Grounding Technique',
 'During any moment of acute anxiety: name 5 things you see, 4 you can touch, 3 you hear, 2 you smell, 1 you taste.', 'PENDING', CURRENT_DATE),
('PT-101', 'DOC-001', 'CBT Thought Record Journal',
 'Write down one anxious or jealous thought today: the trigger, the automatic thought, and a balanced counter-thought.', 'PENDING', CURRENT_DATE),

-- PT-4211 Elena Rostova (BPD) – Dr. Fatima Rehman
('PT-4211', 'DOC-001', 'Daily DBT Check-In Call',
 'Call the clinic check-in line between 09:00–10:00 AM. Mandatory per safety plan.', 'PENDING', CURRENT_DATE),
('PT-4211', 'DOC-001', 'TIPP Skill Practice',
 'Use TIPP (Temperature, Intense Exercise, Paced Breathing, Progressive Relaxation) when urges arise. Log in diary.', 'PENDING', CURRENT_DATE),
('PT-4211', 'DOC-001', 'Emotion Diary Card',
 'Complete your DBT diary card for today. Rate each emotion 0–5 and note any self-harm urges.', 'PENDING', CURRENT_DATE),

-- PT-8832 Michael Chang (OCD) – Dr. Fatima Rehman
('PT-8832', 'DOC-001', 'Morning Medication',
 'Take 1x Fluoxetine 60mg with breakfast.', 'PENDING', CURRENT_DATE),
('PT-8832', 'DOC-001', 'ERP Exercise – Tier 2 Item',
 'Complete today''s assigned ERP hierarchy item. Resist compulsion for full 45 minutes. Record distress level (SUDS).', 'PENDING', CURRENT_DATE),
('PT-8832', 'DOC-001', 'OCD Thought Log',
 'Write down any obsessional thoughts. Label them as OCD, do not engage. Practice defusion.', 'PENDING', CURRENT_DATE),

-- PT-1198 Ayesha Tariq (C-PTSD) – Dr. Fatima Rehman
('PT-1198', 'DOC-001', 'Morning Medication',
 'Take 1x Venlafaxine 100mg with breakfast. Take 1x Prazosin 2mg at bedtime.', 'PENDING', CURRENT_DATE),
('PT-1198', 'DOC-001', 'Box Breathing (Pranayama) – 5 Minutes',
 'Inhale 4s → Hold 4s → Exhale 4s → Hold 4s. Repeat for 5 minutes before sleep to regulate nervous system.', 'PENDING', CURRENT_DATE),
('PT-1198', 'DOC-001', 'Grounding Journal Entry',
 'Write 3 safe things about your current environment. If a flashback occurs, use the safe-place visualisation from session.', 'PENDING', CURRENT_DATE),

-- PT-7045 Robert Hayes (NPD) – Dr. Fatima Rehman
('PT-7045', 'DOC-001', 'Reflective Journaling',
 'Write one paragraph today describing how your actions affected another person. Practise perspective-taking.', 'PENDING', CURRENT_DATE),
('PT-7045', 'DOC-001', 'Attend Scheduled Session',
 'Mandatory court-ordered attendance. Confirm attendance via portal by 08:00 AM on session day.', 'PENDING', CURRENT_DATE),
('PT-7045', 'DOC-001', 'Empathy Mapping Exercise',
 'Choose one recent interpersonal conflict. Write what the other person likely felt. No justifications.', 'PENDING', CURRENT_DATE),

-- PT-2099 Sarah Jenkins (MDD) – Dr. Ali Kamran
('PT-2099', 'DOC-002', 'Morning Medication',
 'Take 1x Sertraline 50mg with breakfast.', 'PENDING', CURRENT_DATE),
('PT-2099', 'DOC-002', 'Behavioural Activation – 20 Min Activity',
 'Do one pleasurable or purposeful activity today (walk, phone a friend, cook). Record in mood diary.', 'PENDING', CURRENT_DATE),
('PT-2099', 'DOC-002', 'Mood & Thought Journal',
 'Write 3 automatic negative thoughts and one evidence-based reframe for each.', 'PENDING', CURRENT_DATE),

-- PT-5502 David Chen (PTSD Combat) – Dr. Ali Kamran
('PT-5502', 'DOC-002', 'Bedtime Medication',
 'Take 1x Prazosin 2mg 30 minutes before sleep.', 'PENDING', CURRENT_DATE),
('PT-5502', 'DOC-002', 'CPT Module Practice',
 'Review your Stuck Points worksheet. Identify one stuck point and work through the challenging questions sheet.', 'PENDING', CURRENT_DATE),
('PT-5502', 'DOC-002', 'Sleep Log',
 'Record sleep onset time, wake times, and nightmare occurrence (Y/N) in your sleep diary each morning.', 'PENDING', CURRENT_DATE),

-- PT-6610 Omar Farooq (Schizoaffective) – Dr. Ali Kamran
('PT-6610', 'DOC-002', 'Morning Medication (CRITICAL)',
 'Take 1x Paliperidone 15mg and 1x Divalproex 500mg with breakfast. Medication must not be skipped.', 'PENDING', CURRENT_DATE),
('PT-6610', 'DOC-002', 'Evening Medication',
 'Take 1x Divalproex 500mg with dinner.', 'PENDING', CURRENT_DATE),
('PT-6610', 'DOC-002', 'Reality Testing Log',
 'If you experience a suspicious thought or belief, write it down. Rate your conviction 0–10. Show to your support person.', 'PENDING', CURRENT_DATE),

-- PT-3321 Rachel Adams (Severe Depression + SI) – Dr. Ali Kamran
('PT-3321', 'DOC-002', 'Morning Medication',
 'Take 1x Bupropion XL 150mg with breakfast. Take 1x Mirtazapine 15mg at bedtime.', 'PENDING', CURRENT_DATE),
('PT-3321', 'DOC-002', 'Safety Check-In',
 'Text or call your designated support contact by 10:00 AM. Log contact made in portal.', 'PENDING', CURRENT_DATE),
('PT-3321', 'DOC-002', 'Crisis Plan Review',
 'Re-read your personal safety plan. Identify your three warning signs today. Note any SI thoughts in your mood diary.', 'PENDING', CURRENT_DATE),

-- PT-9012 James Wilson (IED) – Dr. Ali Kamran
('PT-9012', 'DOC-002', 'Morning Medication',
 'Take 1x Oxcarbazepine 300mg with breakfast and 1x Oxcarbazepine 300mg with dinner.', 'PENDING', CURRENT_DATE),
('PT-9012', 'DOC-002', 'STOP Technique Practice',
 'When anger rises: Stop → Take a breath → Observe your feeling → Proceed mindfully. Log any anger episodes.', 'PENDING', CURRENT_DATE),
('PT-9012', 'DOC-002', 'Cool-Down Protocol Log',
 'Record today''s anger intensity (0–10). Note triggers and which cool-down strategy you used.', 'PENDING', CURRENT_DATE),

-- PT-3105 Marcus Vance (Bipolar II) – Dr. Sarah Jenkins
('PT-3105', 'DOC-003', 'Morning Medication',
 'Take 1x Lithium Carbonate 600mg with breakfast. Take 1x Lithium Carbonate 600mg with dinner (NEW DOSE).', 'PENDING', CURRENT_DATE),
('PT-3105', 'DOC-003', 'Mood Diary Entry',
 'Rate today''s mood on a scale of -3 (depressed) to +3 (hypomanic). Record sleep hours and any impulsive urges.', 'PENDING', CURRENT_DATE),
('PT-3105', 'DOC-003', 'Lithium Toxicity Self-Check',
 'Check for: nausea, tremor, blurred vision, unsteady gait, confusion. If any present, contact clinic immediately.', 'PENDING', CURRENT_DATE),

-- PT-7734 Liam Wright (Substance-Induced Psychosis) – Dr. Sarah Jenkins
('PT-7734', 'DOC-003', 'Evening Medication',
 'Take 1x Olanzapine 10mg at bedtime.', 'PENDING', CURRENT_DATE),
('PT-7734', 'DOC-003', 'Abstinence Check',
 'Record: Did you use cannabis today? (Y/N). If yes, contact your MET counsellor immediately.', 'PENDING', CURRENT_DATE),
('PT-7734', 'DOC-003', 'MET Decisional Balance Exercise',
 'List one benefit and one cost of cannabis use today. Add to your running log sheet from session.', 'PENDING', CURRENT_DATE),

-- PT-4488 Chloe Bennett (Anorexia Nervosa – Critical) – Dr. Sarah Jenkins
('PT-4488', 'DOC-003', 'Nutritional Supplement – 3x Daily (CRITICAL)',
 'Drink 1x Ensure Plus with each meal (breakfast, lunch, dinner). Non-negotiable. Record in nutrition log.', 'PENDING', CURRENT_DATE),
('PT-4488', 'DOC-003', 'Evening Medication',
 'Take 1x Olanzapine 5mg at bedtime.', 'PENDING', CURRENT_DATE),
('PT-4488', 'DOC-003', 'Meals Log & Body Image Journal',
 'Record all food/drink consumed today. Write one body-neutral affirmation. Share log at next session.', 'PENDING', CURRENT_DATE),

-- PT-5120 Daniel Thorne (ASPD) – Dr. Sarah Jenkins
('PT-5120', 'DOC-003', 'Confirm Session Attendance',
 'Confirm attendance for this week''s scheduled session via portal before 08:00 AM. Court reporting requires this log.', 'PENDING', CURRENT_DATE),
('PT-5120', 'DOC-003', 'Schema Journal',
 'Write one example today of noticing an old maladaptive schema (e.g. Entitlement, Predatory) being triggered. Do not act on it.', 'PENDING', CURRENT_DATE),
('PT-5120', 'DOC-003', 'Harm Reduction Log',
 'List one situation today where you chose not to manipulate or deceive. Record what you did instead.', 'PENDING', CURRENT_DATE),

-- PT-8201 Zara Malik (DID) – Dr. Sarah Jenkins
('PT-8201', 'DOC-003', 'Evening Medication',
 'Take 1x Quetiapine 50mg at bedtime for sleep regulation.', 'PENDING', CURRENT_DATE),
('PT-8201', 'DOC-003', 'Parts Journal – Daily Check-In',
 'Ask each known part: "How are you today?" Write their response. Note any new voices or perspectives.', 'PENDING', CURRENT_DATE),
('PT-8201', 'DOC-003', 'Grounding After Dissociation',
 'If you experience a dissociative episode, use the 5-senses grounding card. Log: duration, trigger, and which part was present.', 'PENDING', CURRENT_DATE);

-- ============================================================
-- SECTION 18: ADMIN USER SEED DATA
-- ============================================================

INSERT INTO auth_users (user_id, email, role) VALUES
    ('c0000001-0000-0000-0000-000000000001', 'admin@serenity.care', 'admin');

-- ============================================================
-- SECTION 19: USEFUL VIEWS FOR BACKEND API
-- ============================================================

-- View: Doctor's full caseload overview (used in provider portal sidebar + table)
CREATE OR REPLACE VIEW v_doctor_caseload AS
SELECT
    dp.doc_id,
    d.full_name                         AS doctor_name,
    p.mrn,
    p.full_name                         AS patient_name,
    p.primary_diagnosis,
    p.status                            AS patient_status,
    p.total_sessions,
    a.scheduled_at                      AS next_appointment,
    a.is_urgent,
    a.status                            AS appt_status,
    p.consultation_fee_paid
FROM doctor_patients dp
JOIN doctors  d  ON d.doc_id = dp.doc_id
JOIN patients p  ON p.mrn   = dp.mrn
LEFT JOIN LATERAL (
    SELECT scheduled_at, is_urgent, status
    FROM appointments
    WHERE mrn = dp.mrn AND doc_id = dp.doc_id AND status = 'Scheduled'
    ORDER BY scheduled_at ASC
    LIMIT 1
) a ON TRUE;

-- View: Patient portal dashboard (what a logged-in patient sees)
CREATE OR REPLACE VIEW v_patient_dashboard AS
SELECT
    p.mrn,
    p.full_name,
    p.primary_diagnosis,
    p.active_treatment,
    p.status                            AS patient_status,
    p.total_sessions,
    d.full_name                         AS attending_provider,
    a.scheduled_at                      AS next_appointment,
    a.is_urgent,
    a.status                            AS appt_status,
    (
        SELECT COUNT(*) FROM patient_tasks t
        WHERE t.mrn = p.mrn AND t.task_date = CURRENT_DATE
    )                                   AS total_tasks_today,
    (
        SELECT COUNT(*) FROM patient_tasks t
        WHERE t.mrn = p.mrn AND t.task_date = CURRENT_DATE AND t.status = 'DONE'
    )                                   AS completed_tasks_today
FROM patients p
JOIN doctor_patients dp  ON dp.mrn    = p.mrn
JOIN doctors d           ON d.doc_id  = dp.doc_id
LEFT JOIN LATERAL (
    SELECT scheduled_at, is_urgent, status
    FROM appointments
    WHERE mrn = p.mrn AND status = 'Scheduled'
    ORDER BY scheduled_at ASC
    LIMIT 1
) a ON TRUE;

-- View: Today's tasks per patient (used by patient portal task checklist)
CREATE OR REPLACE VIEW v_today_tasks AS
SELECT
    task_id,
    mrn,
    doc_id,
    title,
    description,
    status,
    task_date,
    completed_at
FROM patient_tasks
WHERE task_date = CURRENT_DATE
ORDER BY mrn, created_at ASC;

-- ============================================================
-- SECTION 20: ROW-LEVEL SECURITY (RLS) POLICY STUBS
-- ============================================================
-- Enable RLS after setting up app roles in PostgreSQL.
-- The Python backend connects as app_user (not superuser).
-- app_user is granted SELECT/INSERT/UPDATE/DELETE per role context.
-- Example stubs shown below; enable after role setup.

/*
ALTER TABLE patients        ENABLE ROW LEVEL SECURITY;
ALTER TABLE patient_tasks   ENABLE ROW LEVEL SECURITY;
ALTER TABLE appointments    ENABLE ROW LEVEL SECURITY;

-- Doctors can only see patients linked to their doc_id
CREATE POLICY doctor_sees_own_patients ON patients
    FOR ALL USING (
        mrn IN (
            SELECT mrn FROM doctor_patients
            WHERE doc_id = current_setting('app.current_doc_id')
        )
    );

-- Patients can only see their own row
CREATE POLICY patient_sees_own_row ON patients
    FOR SELECT USING (
        mrn = current_setting('app.current_mrn')
    );
*/

-- ============================================================
-- END OF FILE
-- To apply: psql -U postgres -d serenity_ehr -f serenity_production_schema.sql
-- ============================================================
