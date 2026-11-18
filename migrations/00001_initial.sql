-- +goose Up
CREATE TABLE pools (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE servers (id uuid PRIMARY KEY, data jsonb NOT NULL,
 pool_id uuid GENERATED ALWAYS AS ((data->>'pool_id')::uuid) STORED REFERENCES pools(id));
CREATE TABLE instances (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE UNIQUE INDEX instance_subnet ON instances ((data->>'subnet'));
CREATE TABLE endpoints (id uuid PRIMARY KEY, data jsonb NOT NULL,
 instance_id uuid GENERATED ALWAYS AS ((data->>'instance_id')::uuid) STORED UNIQUE REFERENCES instances(id));
CREATE TABLE placements (id uuid PRIMARY KEY, data jsonb NOT NULL,
 instance_id uuid GENERATED ALWAYS AS ((data->>'instance_id')::uuid) STORED REFERENCES instances(id),
 pool_id uuid GENERATED ALWAYS AS ((data->>'pool_id')::uuid) STORED REFERENCES pools(id));
CREATE TABLE deployments (id uuid PRIMARY KEY, data jsonb NOT NULL,
 instance_id uuid GENERATED ALWAYS AS ((data->>'instance_id')::uuid) STORED REFERENCES instances(id),
 server_id uuid GENERATED ALWAYS AS ((data->>'server_id')::uuid) STORED REFERENCES servers(id),
 UNIQUE (instance_id,server_id));
CREATE TABLE users (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE identities (id uuid PRIMARY KEY, data jsonb NOT NULL,
 user_id uuid GENERATED ALWAYS AS ((data->>'user_id')::uuid) STORED REFERENCES users(id));
CREATE UNIQUE INDEX identity_external ON identities ((data->>'provider'),(data->>'external_id'));
CREATE TABLE grants (id uuid PRIMARY KEY, data jsonb NOT NULL,
 user_id uuid GENERATED ALWAYS AS ((data->>'user_id')::uuid) STORED REFERENCES users(id),
 instance_id uuid GENERATED ALWAYS AS ((data->>'instance_id')::uuid) STORED REFERENCES instances(id),UNIQUE(user_id,instance_id));
CREATE TABLE devices (id uuid PRIMARY KEY, data jsonb NOT NULL,
 user_id uuid GENERATED ALWAYS AS ((data->>'user_id')::uuid) STORED REFERENCES users(id),
 instance_id uuid GENERATED ALWAYS AS ((data->>'instance_id')::uuid) STORED REFERENCES instances(id));
CREATE UNIQUE INDEX device_address ON devices(instance_id,(data->>'address'));
CREATE UNIQUE INDEX device_request ON devices(user_id,(data->>'request_id'));
CREATE TABLE operations (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE INDEX operation_status ON operations((data->>'status'),(data->>'available_at'));
CREATE TABLE audit (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE INDEX audit_time ON audit((data->>'at'));
-- +goose Down
DROP TABLE audit,operations,devices,grants,identities,users,deployments,placements,endpoints,instances,servers,pools;
