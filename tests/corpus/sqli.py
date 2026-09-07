# SQL injection (safe corpus sample — not exploitable)
user_input = "admin' OR '1'='1"
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
