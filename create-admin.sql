-- Create Super Administrator User
-- Email: lamado@roiblueprint.com
-- Password: 1Prim@ry12
-- Role: admin

INSERT INTO users (id, email, password_hash, name, role, created_at, updated_at)
VALUES (
  lower(hex(randomblob(16))),
  'lamado@roiblueprint.com',
  'MTVHwm1rS3RAbCsycjGakqwmY1dLN-tsmH8dGFfWDec',
  'Leo Amado',
  'admin',
  unixepoch(),
  unixepoch()
)
ON CONFLICT(email) DO UPDATE SET
  password_hash = excluded.password_hash,
  name = excluded.name,
  role = excluded.role,
  updated_at = unixepoch();
