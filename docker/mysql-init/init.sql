-- Create users table with test data
CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(100),
  role VARCHAR(20) DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert vulnerable test accounts
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@test.com', 'admin'),
('user1', 'password', 'user1@test.com', 'user'),
('testuser', 'test123', 'test@test.com', 'user'),
('john', '12345', 'john@test.com', 'user');

-- Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT,
  amount DECIMAL(10,2),
  type VARCHAR(20),
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create sensitive data table (simulating exposed PII)
CREATE TABLE IF NOT EXISTS customer_data (
  id INT PRIMARY KEY AUTO_INCREMENT,
  full_name VARCHAR(100),
  ssn VARCHAR(11),
  credit_card VARCHAR(16),
  address TEXT,
  phone VARCHAR(15)
);

-- Insert sensitive test data
INSERT INTO customer_data (full_name, ssn, credit_card, address, phone) VALUES
('Alice Johnson', '123-45-6789', '4532123456789012', '123 Main St', '555-0100'),
('Bob Smith', '987-65-4321', '5425233430109903', '456 Oak Ave', '555-0200');

-- Grant excessive privileges (vulnerability)
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' IDENTIFIED BY 'admin123';
FLUSH PRIVILEGES;
