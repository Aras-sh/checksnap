-- SELECT * in a comment must not fire; neither must 'DELETE FROM x' in a string
CREATE TABLE orders (
  id integer,
  customer_id integer,
  price float,
  password varchar(255),
  email varchar(255),
  name varchar(255)
);
SELECT * FROM orders o, customers c WHERE o.customer_id = c.id;
DELETE FROM orders;
