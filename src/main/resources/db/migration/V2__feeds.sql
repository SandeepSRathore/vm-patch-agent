-- Outcome of the last run of each feed, for the dashboard.
CREATE TABLE feed_status (
    feed         VARCHAR(16) PRIMARY KEY,
    last_attempt TIMESTAMP WITH TIME ZONE,
    last_success TIMESTAMP WITH TIME ZONE,
    last_error   VARCHAR(2000),
    summary      VARCHAR(500)
);

-- MSRC monthly CVRF documents already ingested. Fixes are filtered to this VM's build when stored, so a document is
-- re-read when the build line changes (in-place OS upgrade) or MSRC revises it.
CREATE TABLE msrc_document (
    id           VARCHAR(16) PRIMARY KEY,
    release_date VARCHAR(40),
    os_build     INT NOT NULL,
    fetched_at   TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE msrc_fix (
    cve              VARCHAR(32)  NOT NULL,
    title            VARCHAR(500),
    product_id       VARCHAR(32)  NOT NULL,
    product_name     VARCHAR(300),
    os_product       BOOLEAN      NOT NULL,
    kb               VARCHAR(16)  NOT NULL,
    fixed_build      VARCHAR(300),
    supersedes_kb    VARCHAR(16),
    restart_required VARCHAR(16),
    severity         VARCHAR(16),
    cvss             DOUBLE PRECISION,
    exploited        BOOLEAN      NOT NULL,
    document_id      VARCHAR(16)  NOT NULL
);

CREATE INDEX msrc_fix_document ON msrc_fix (document_id);

-- NVD data is fetched per catalogued product (CPE vendor:product) for apps installed on this VM.
CREATE TABLE nvd_product (
    cpe          VARCHAR(200) PRIMARY KEY,
    synced_until TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE nvd_cve (
    cpe           VARCHAR(200) NOT NULL,
    cve           VARCHAR(32)  NOT NULL,
    published     VARCHAR(40),
    last_modified VARCHAR(40),
    cvss          DOUBLE PRECISION,
    summary       VARCHAR(4000),
    PRIMARY KEY (cpe, cve)
);

CREATE TABLE nvd_range (
    cpe             VARCHAR(200) NOT NULL,
    cve             VARCHAR(32)  NOT NULL,
    exact_version   VARCHAR(64),
    start_including VARCHAR(64),
    start_excluding VARCHAR(64),
    end_including   VARCHAR(64),
    end_excluding   VARCHAR(64)
);

CREATE INDEX nvd_range_cve ON nvd_range (cpe, cve);

-- CISA Known Exploited Vulnerabilities catalog, replaced whole on each new catalog version.
CREATE TABLE kev (
    cve        VARCHAR(32) PRIMARY KEY,
    name       VARCHAR(500),
    date_added DATE,
    due_date   DATE,
    ransomware VARCHAR(16)
);
