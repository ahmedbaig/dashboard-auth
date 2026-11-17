CREATE TABLE users (
  id            bigserial PRIMARY KEY,
  email         text        NOT NULL UNIQUE,
  name          text        NOT NULL DEFAULT '',
  disabled      boolean     NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

CREATE TABLE password_credentials (
  user_id    bigint      PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  hash       text        NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
  user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role    text   NOT NULL,
  PRIMARY KEY (user_id, role)
);

CREATE TABLE user_features (
  user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  feature text   NOT NULL,
  PRIMARY KEY (user_id, feature)
);
