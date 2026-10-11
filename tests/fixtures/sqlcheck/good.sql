CREATE TABLE users (id bigint PRIMARY KEY, email varchar(120) UNIQUE, password_hash text, balance numeric(12,2));
CREATE TABLE posts (id bigint PRIMARY KEY, user_id bigint REFERENCES users(id));
SELECT id, email FROM users u JOIN posts p ON p.user_id = u.id WHERE u.email LIKE 'a%';
UPDATE users SET email = 'x' WHERE id = 1;
SELECT count(*) FROM users WHERE EXISTS (SELECT * FROM posts);
