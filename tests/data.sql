INSERT INTO user (username, name, email, report_time, password)
VALUES (
        'test',
        'John D. Test',
        'john@test.com',
        0,
        'pbkdf2:sha256:150000$ajoktrjP$8428b90fddf4c238b05682009b3543195729ff8970456056891c5de3a01e79c9'
    ),
    -- PW: test
    (
        'other',
        'Edsger Dijkstra',
        'ed@test.com',
        100,
        'pbkdf2:sha256:150000$KEqLWLyo$5ad16c0a71b1bf6595a06df8e76d5fd12030a1d25dfc2c17f8add2de437830b1'
    );
-- PW: test2
INSERT INTO activity (
        name,
        parent_activity,
        is_alias,
        is_placeholder,
        user_id
    )
VALUES ('productive_time', NULL, false, true, 1),
    ('work', 1, false, false, 1),
    ('homework', 1, false, false, 1),
    ('math', 3, false, false, 1),
    ('maths', 4, true, false, 1),
    ('history', 3, false, false, 1),
    ('sleep', NULL, false, false, 1),
    ('programming', NULL, false, false, 2);
INSERT INTO timelog (
        user_id,
        activity_id,
        source,
        nominal_time,
        nominal_time_timezone_offset
    )
VALUES (1, 4, 'web', '2021-01-01 00:00:00', -25200.0),
    (1, 6, 'phone', '2021-01-01 01:00:00', -25200.0),
    (1, 7, 'web', '2021-01-01 02:00:00', -25200.0),
    (2, 8, 'pda', '2021-01-01 02:00:00', -25200.0);