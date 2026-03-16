-- WinEVT plugin migration: auth_events OCSF view

CREATE OR REPLACE VIEW auth_events AS
SELECT
    r.id AS record_id,
    r.case_id,
    r.record_type,
    r.ts,
    (r.raw->>'EventID')::int AS event_id,
    r.raw->>'Channel' AS channel,
    r.raw->>'Computer' AS computer,
    r.raw->'EventData'->>'TargetUserName' AS target_user,
    r.raw->'EventData'->>'TargetDomainName' AS target_domain,
    r.raw->'EventData'->>'SubjectUserName' AS subject_user,
    (r.raw->'EventData'->>'LogonType')::int AS logon_type,
    r.raw->'EventData'->>'IpAddress' AS source_ip,
    r.raw->'EventData'->>'WorkstationName' AS workstation,
    r.raw->'EventData'->>'LogonProcessName' AS logon_process,
    r.raw->'EventData'->>'AuthenticationPackageName' AS auth_package,
    r.raw->'EventData'->>'Image' AS process_image,
    r.raw->'EventData'->>'CommandLine' AS command_line,
    r.raw->'EventData'->>'ParentImage' AS parent_image,
    (r.raw->'EventData'->>'ProcessId')::int AS process_id
FROM records r
WHERE r.record_type IN ('win_evt_security', 'win_evt_sysmon');