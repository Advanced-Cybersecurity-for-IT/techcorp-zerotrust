-- ============================================================================
-- TechCorp Enterprise Database - Zero Trust Architecture
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS enterprise;

-- DEPARTMENTS
CREATE TABLE enterprise.departments (
    id SERIAL PRIMARY KEY,
    code VARCHAR(10) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    budget DECIMAL(15,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO enterprise.departments (code, name, budget) VALUES
('EXEC', 'Executive', 500000.00),
('IT', 'Information Technology', 850000.00),
('HR', 'Human Resources', 250000.00),
('SALES', 'Sales & Marketing', 600000.00),
('FIN', 'Finance', 300000.00),
('OPS', 'Operations', 450000.00);

-- EMPLOYEES
CREATE TABLE enterprise.employees (
    id SERIAL PRIMARY KEY,
    employee_code VARCHAR(20) UNIQUE NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20),
    department VARCHAR(50),
    position VARCHAR(100),
    hire_date DATE,
    salary DECIMAL(10,2),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO enterprise.employees (employee_code, first_name, last_name, email, phone, department, position, hire_date, salary) VALUES
('TC001', 'Marco', 'Rossi', 'm.rossi@techcorp.local', '+39 02 1234001', 'Executive', 'CEO', '2018-01-15', 180000.00),
('TC002', 'Laura', 'Bianchi', 'l.bianchi@techcorp.local', '+39 02 1234002', 'Technology', 'CTO', '2018-03-01', 150000.00),
('TC003', 'Giuseppe', 'Ferrari', 'g.ferrari@techcorp.local', '+39 02 1234003', 'Human Resources', 'HR Manager', '2019-06-15', 75000.00),
('TC004', 'Anna', 'Romano', 'a.romano@techcorp.local', '+39 02 1234004', 'Sales', 'Sales Manager', '2019-09-01', 80000.00),
('TC005', 'Francesco', 'Colombo', 'f.colombo@techcorp.local', '+39 02 1234005', 'IT', 'Senior Developer', '2020-02-01', 65000.00),
('TC006', 'Sofia', 'Ricci', 's.ricci@techcorp.local', '+39 02 1234006', 'Analytics', 'Data Analyst', '2020-05-15', 55000.00),
('TC007', 'Paolo', 'Marino', 'p.marino@techcorp.local', '+39 02 1234007', 'IT', 'Junior Developer', '2021-09-01', 38000.00),
('TC008', 'Elena', 'Greco', 'e.greco@techcorp.local', '+39 02 1234008', 'Sales', 'Sales Representative', '2021-03-15', 42000.00);

-- CUSTOMERS
CREATE TABLE enterprise.customers (
    id SERIAL PRIMARY KEY,
    customer_code VARCHAR(20) UNIQUE NOT NULL,
    company_name VARCHAR(200) NOT NULL,
    contact_name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(30),
    city VARCHAR(100),
    country VARCHAR(50),
    credit_limit DECIMAL(15,2),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO enterprise.customers (customer_code, company_name, contact_name, email, phone, city, country, credit_limit) VALUES
('CL001', 'Innovatech Solutions S.r.l.', 'Giovanni Verdi', 'g.verdi@innovatech.it', '+39 02 9876001', 'Milano', 'Italy', 150000.00),
('CL002', 'Global Systems S.p.A.', 'Maria Neri', 'm.neri@globalsys.it', '+39 06 9876002', 'Roma', 'Italy', 300000.00),
('CL003', 'Digital Factory GmbH', 'Hans Mueller', 'h.mueller@digitalfactory.de', '+49 89 1234567', 'Munich', 'Germany', 250000.00),
('CL004', 'Smart Solutions Ltd', 'John Smith', 'j.smith@smartsol.co.uk', '+44 20 12345678', 'London', 'UK', 200000.00),
('CL005', 'TechVenture S.A.', 'Pierre Dupont', 'p.dupont@techventure.fr', '+33 1 23456789', 'Paris', 'France', 180000.00);

-- PRODUCTS
CREATE TABLE enterprise.products (
    id SERIAL PRIMARY KEY,
    product_code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    category VARCHAR(50),
    unit_price DECIMAL(10,2) NOT NULL,
    stock_quantity INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true
);

INSERT INTO enterprise.products (product_code, name, category, unit_price, stock_quantity) VALUES
('PRD001', 'Enterprise Security Suite', 'Software', 15000.00, 999),
('PRD002', 'Cloud Infrastructure Pack', 'Cloud Services', 8500.00, 999),
('PRD003', 'Data Analytics Platform', 'Analytics', 12000.00, 999),
('PRD004', 'API Gateway Pro', 'Software', 6500.00, 999),
('PRD005', 'DevOps Automation Suite', 'DevOps', 9000.00, 999);

-- ORDERS
CREATE TABLE enterprise.orders (
    id SERIAL PRIMARY KEY,
    order_number VARCHAR(20) UNIQUE NOT NULL,
    customer_id INTEGER REFERENCES enterprise.customers(id),
    order_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    total_amount DECIMAL(15,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO enterprise.orders (order_number, customer_id, order_date, status, total_amount) VALUES
('ORD-2024-001', 1, '2024-01-15', 'delivered', 45000.00),
('ORD-2024-002', 2, '2024-01-20', 'delivered', 78000.00),
('ORD-2024-003', 3, '2024-02-01', 'delivered', 52000.00),
('ORD-2024-004', 4, '2024-02-15', 'shipped', 38000.00),
('ORD-2024-005', 5, '2024-03-01', 'processing', 67000.00),
('ORD-2024-006', 1, '2024-03-10', 'pending', 93000.00),
('ORD-2024-007', 2, '2024-03-20', 'pending', 28500.00);

-- PROJECTS
CREATE TABLE enterprise.projects (
    id SERIAL PRIMARY KEY,
    project_code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    client_id INTEGER REFERENCES enterprise.customers(id),
    start_date DATE,
    end_date DATE,
    budget DECIMAL(15,2),
    status VARCHAR(20) DEFAULT 'planning',
    completion_percentage INTEGER DEFAULT 0
);

INSERT INTO enterprise.projects (project_code, name, client_id, start_date, end_date, budget, status, completion_percentage) VALUES
('PRJ-001', 'Cloud Migration Initiative', 2, '2024-01-01', '2024-06-30', 250000.00, 'active', 72),
('PRJ-002', 'Security Audit Program', 4, '2024-02-01', '2024-04-30', 85000.00, 'active', 92),
('PRJ-003', 'ERP Integration', 1, '2024-01-15', '2024-08-31', 320000.00, 'active', 45),
('PRJ-004', 'Mobile App Development', 3, '2024-03-01', '2024-09-30', 180000.00, 'planning', 23),
('PRJ-005', 'Data Warehouse Modernization', 5, '2024-02-15', '2024-07-31', 150000.00, 'completed', 100);

-- AUDIT LOG
CREATE TABLE enterprise.audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(100),
    action VARCHAR(20),
    table_name VARCHAR(50),
    record_id INTEGER,
    ip_address VARCHAR(45),
    trust_score DECIMAL(5,2)
);

-- INDEXES
CREATE INDEX idx_employees_department ON enterprise.employees(department);
CREATE INDEX idx_orders_status ON enterprise.orders(status);
CREATE INDEX idx_projects_status ON enterprise.projects(status);
CREATE INDEX idx_audit_timestamp ON enterprise.audit_log(timestamp);

-- GRANTS
GRANT ALL PRIVILEGES ON SCHEMA enterprise TO techcorp_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA enterprise TO techcorp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA enterprise TO techcorp_user;
