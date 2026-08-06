ALTER TABLE device_fingerprints ADD COLUMN browser_cookie TEXT NOT NULL DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN http_headers TEXT NOT NULL DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN tcp_syn TEXT NOT NULL DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN tls_clienthello TEXT NOT NULL DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN quic_initial TEXT NOT NULL DEFAULT '';
