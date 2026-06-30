-- Geo/ASN enrichment for source IPs (public metadata only).
ALTER TABLE ip_profiles ADD COLUMN country_code TEXT;
ALTER TABLE ip_profiles ADD COLUMN asn INTEGER;
ALTER TABLE ip_profiles ADD COLUMN as_name TEXT;
