UPDATE findings
SET status = CASE
    WHEN status = '' THEN 'open'
    WHEN status = 'pending' THEN 'open'
    WHEN status = 'dismissed' THEN 'false-positive'
    ELSE status
END;
