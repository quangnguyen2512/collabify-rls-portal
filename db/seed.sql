-- =============================================================================
-- Collabify Development Seed Fixtures
-- Matches the deterministic UUIDs used by the In-Memory RLS Store & Demo UI.
-- =============================================================================

BEGIN;

-- Tenants
INSERT INTO tenants (id, slug, custom_domain, name, status) VALUES
  ('11111111-1111-4111-8111-111111111111', 'acme', 'portal.acmecreative.io', 'Acme Creative Studio', 'active'),
  ('22222222-2222-4222-8222-222222222222', 'velvet', 'review.velvetmotion.tv', 'Velvet Motion Lab', 'active'),
  ('33333333-3333-4333-8333-333333333333', 'suspended-co', NULL, 'Suspended Agency Co', 'suspended')
ON CONFLICT (id) DO NOTHING;

-- Demo Agency Users (demo password for local sandbox only: "collabify-demo-pass")
INSERT INTO users (id, email, full_name, password_hash) VALUES
  ('aaaa1111-1111-4111-8111-111111111111', 'alice@acme.studio', 'Alice Chen (Acme Owner)', 'demo:collabify-demo-pass'),
  ('bbbb2222-2222-4222-8222-222222222222', 'bob@velvet.tv', 'Bob Ramirez (Velvet Owner)', 'demo:collabify-demo-pass')
ON CONFLICT (id) DO NOTHING;

-- Tenant Memberships
INSERT INTO tenant_memberships (id, tenant_id, user_id, role) VALUES
  ('cccc1111-1111-4111-8111-111111111111', '11111111-1111-4111-8111-111111111111', 'aaaa1111-1111-4111-8111-111111111111', 'owner'),
  ('cccc2222-2222-4222-8222-222222222222', '22222222-2222-4222-8222-222222222222', 'bbbb2222-2222-4222-8222-222222222222', 'owner')
ON CONFLICT (id) DO NOTHING;

-- Client Portals
INSERT INTO client_portals (id, tenant_id, name, client_name, status) VALUES
  ('10000000-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'Q4 Product Launch Film', 'Northstar Robotics', 'active'),
  ('10000000-0000-4000-8000-000000000002', '11111111-1111-4111-8111-111111111111', 'Brand Guidelines Cutdowns', 'Solstice Skincare', 'active'),
  ('20000000-0000-4000-8000-000000000001', '22222222-2222-4222-8222-222222222222', 'Series A Investor Teaser (Confidential)', 'Hyperion AI', 'active')
ON CONFLICT (id) DO NOTHING;

-- Seeded Completed Video Assets
INSERT INTO video_assets (
  id, tenant_id, portal_id, upload_id, filename, object_key,
  content_type, size_bytes, expected_part_count, status, manifest_sha256
) VALUES
  (
    '50000000-0000-4000-8000-000000000001',
    '11111111-1111-4111-8111-111111111111',
    '10000000-0000-4000-8000-000000000001',
    'upl_acme_seed_001',
    'launch_cut_v3.mp4',
    'tenants/11111111-1111-4111-8111-111111111111/portals/10000000-0000-4000-8000-000000000001/videos/50000000-0000-4000-8000-000000000001/launch_cut_v3.mp4',
    'video/mp4',
    262144000,
    5,
    'READY',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  ),
  (
    '60000000-0000-4000-8000-000000000001',
    '22222222-2222-4222-8222-222222222222',
    '20000000-0000-4000-8000-000000000001',
    'upl_velvet_seed_001',
    'series_a_embargoed_master.mov',
    'tenants/22222222-2222-4222-8222-222222222222/portals/20000000-0000-4000-8000-000000000001/videos/60000000-0000-4000-8000-000000000001/series_a_embargoed_master.mov',
    'video/quicktime',
    1845493760,
    20,
    'READY',
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
  )
ON CONFLICT (id) DO NOTHING;

COMMIT;
