from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Blueprint
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import mysql.connector
from datetime import datetime, timedelta
from decimal import Decimal
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key in production

# Create admin blueprint
admin = Blueprint('admin', __name__, url_prefix='/admin')

# MySQL Configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'neeraj',  # Updated password
    'database': 'bank_system'
}

# Admin credentials (in production, these should be in a secure configuration file)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = '1234'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

class User(UserMixin):
    def __init__(self, id, username=None, account_number=None, name=None, balance=None, is_admin=False, is_customer=False):
        self.id = id
        self.username = username
        self.account_number = account_number
        self.name = name
        self.balance = balance
        self.is_admin = is_admin
        self.is_customer = is_customer

@login_manager.user_loader
def load_user(user_id):
    if user_id == 'admin':
        return User('admin', username='admin', is_admin=True)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM customers WHERE account_number = %s', (user_id,))
        customer = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if customer:
            return User(
                id=customer['account_number'],
                account_number=customer['account_number'],
                name=customer['name'],
                balance=float(customer['balance']),
                is_customer=True
            )
    except Exception as e:
        print(f"Error loading user: {e}")
    return None

def get_db_connection():
    # First try to connect without database
    try:
        conn = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password']
        )
        cursor = conn.cursor()
        # Create database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS bank_system")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error creating database: {e}")
    
    # Now connect with database
    return mysql.connector.connect(**db_config)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Create database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS bank_system")
        cursor.execute("USE bank_system")
        
        # Create customers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                account_number VARCHAR(10) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                pin VARCHAR(255) NOT NULL,
                balance DECIMAL(15, 2) DEFAULT 0.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        
        # Create transactions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                account_number VARCHAR(10) NOT NULL,
                transaction_type ENUM('deposit', 'withdrawal', 'transfer') NOT NULL,
                amount DECIMAL(15, 2) NOT NULL,
                recipient_account VARCHAR(10),
                notes TEXT,
                transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (account_number) REFERENCES customers(account_number)
            )
        """)
        
        # Create admin table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Drop and recreate loans table to ensure it has all required columns
        cursor.execute("DROP TABLE IF EXISTS loans")
        
        # Create loans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS loans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                account_number VARCHAR(10) NOT NULL,
                amount DECIMAL(15, 2) NOT NULL,
                interest_rate DECIMAL(5, 2) NOT NULL,
                term_months INT NOT NULL,
                status ENUM('pending', 'approved', 'rejected', 'completed') DEFAULT 'pending',
                application_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approval_date TIMESTAMP NULL,
                monthly_payment DECIMAL(15, 2) NOT NULL,
                remaining_amount DECIMAL(15, 2) NOT NULL,
                purpose TEXT,
                monthly_income DECIMAL(15, 2) NOT NULL,
                employment_type VARCHAR(50) NOT NULL,
                FOREIGN KEY (account_number) REFERENCES customers(account_number)
            )
        """)
        
        # Insert default admin account if not exists
        cursor.execute("""
            INSERT IGNORE INTO admin (username, password) 
            VALUES ('admin', '1234')
        """)
        
        conn.commit()
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

# Initialize database when app starts
init_db()

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    user_type = request.form.get('user_type')
    
    if user_type == 'admin':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Get admin credentials from database
            cursor.execute('SELECT * FROM admin WHERE username = %s', (username,))
            admin = cursor.fetchone()
            
            if admin and admin['password'] == password:
                user = User('admin', username='admin', is_admin=True)
                login_user(user)
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('Invalid admin credentials!', 'error')
                return redirect(url_for('index'))
                
        except Exception as e:
            app.logger.error(f"Error during admin login: {str(e)}")
            flash('Error during login. Please try again.', 'error')
            return redirect(url_for('index'))
        finally:
            cursor.close()
            conn.close()
    
    elif user_type == 'customer':
        account_number = request.form.get('account_number')
        pin = request.form.get('pin')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT * FROM customers WHERE account_number = %s', (account_number,))
            customer = cursor.fetchone()
            
            if customer and bcrypt.checkpw(pin.encode('utf-8'), customer['pin'].encode('utf-8')):
                user = User(
                    id=customer['account_number'],
                    account_number=customer['account_number'],
                    name=customer['name'],
                    balance=float(customer['balance']),
                    is_customer=True
                )
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('customer_dashboard'))
            else:
                flash('Invalid account number or PIN!', 'error')
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')
        finally:
            cursor.close()
            conn.close()
            
        return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        account_number = request.form.get('account_number')
        pin = request.form.get('pin')
        confirm_pin = request.form.get('confirm_pin')
        initial_deposit = float(request.form.get('initial_deposit'))

        # Validate input
        if len(account_number) != 10:
            flash('Account number must be 10 digits!', 'error')
            return redirect(url_for('register'))

        if len(pin) != 4 or not pin.isdigit():
            flash('PIN must be 4 digits!', 'error')
            return redirect(url_for('register'))

        if pin != confirm_pin:
            flash('PINs do not match!', 'error')
            return redirect(url_for('register'))

        if initial_deposit < 500:
            flash('Initial deposit must be at least ₹500!', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Check if account number already exists
            cursor.execute('SELECT COUNT(*) FROM customers WHERE account_number = %s', (account_number,))
            if cursor.fetchone()[0] > 0:
                flash('Account number already exists!', 'error')
                return redirect(url_for('register'))

            # Hash the PIN
            hashed_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt())

            # Insert new customer
            cursor.execute('''
                INSERT INTO customers (account_number, name, pin, balance)
                VALUES (%s, %s, %s, %s)
            ''', (account_number, full_name, hashed_pin, initial_deposit))

            # Insert initial deposit transaction
            cursor.execute('''
                INSERT INTO transactions (account_number, transaction_type, amount)
                VALUES (%s, %s, %s)
            ''', (account_number, 'deposit', initial_deposit))

            conn.commit()
            flash('Account created successfully! You can now login.', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            conn.rollback()
            flash('An error occurred while creating your account. Please try again.', 'error')
            return redirect(url_for('register'))

        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')

@admin.route('/create_account', methods=['POST'])
@login_required
def create_account():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    name = request.form.get('name')
    initial_deposit = float(request.form.get('initial_deposit'))
    pin = request.form.get('pin')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Generate a unique 10-digit account number
        while True:
            account_number = ''.join([str(random.randint(0, 9)) for _ in range(10)])
            cursor.execute('SELECT COUNT(*) FROM customers WHERE account_number = %s', (account_number,))
            if cursor.fetchone()[0] == 0:
                break
        
        # Hash the PIN
        hashed_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt())
        
        # Insert new customer
        cursor.execute('''
            INSERT INTO customers (account_number, name, pin, balance)
            VALUES (%s, %s, %s, %s)
        ''', (account_number, name, hashed_pin, initial_deposit))
        
        # Record initial deposit transaction
        if initial_deposit > 0:
            cursor.execute('''
                INSERT INTO transactions (account_number, transaction_type, amount, notes)
                VALUES (%s, %s, %s, %s)
            ''', (account_number, 'deposit', initial_deposit, 'Initial deposit'))
        
        conn.commit()
        flash(f'Account created successfully! Account number: {account_number}', 'success')
        
    except Exception as e:
        conn.rollback()
        flash('Failed to create account. Please try again.', 'error')
    
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin.dashboard'))

@admin.route('/process_transaction', methods=['POST'])
@login_required
def process_transaction():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    account_number = request.form.get('account_number')
    amount = float(request.form.get('amount'))
    transaction_type = request.form.get('transaction_type')
    description = request.form.get('description', '')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Verify account exists
        cursor.execute('SELECT balance FROM customers WHERE account_number = %s', (account_number,))
        customer = cursor.fetchone()
        
        if not customer:
            flash('Account number does not exist! Please check the account number and try again.', 'error')
            return redirect(url_for('admin.dashboard', tab='overview'))
        
        current_balance = float(customer['balance'])
        
        # Check for sufficient balance for withdrawals
        if transaction_type == 'withdrawal' and amount > current_balance:
            flash(f'Insufficient balance! The account has only ₹{current_balance:,.2f} available.', 'error')
            return redirect(url_for('admin.dashboard', tab='overview'))
        
        # Update balance
        new_balance = current_balance + amount if transaction_type == 'deposit' else current_balance - amount
        cursor.execute('UPDATE customers SET balance = %s WHERE account_number = %s',
                      (new_balance, account_number))
        
        # Record transaction
        cursor.execute('''
            INSERT INTO transactions (account_number, transaction_type, amount, notes)
            VALUES (%s, %s, %s, %s)
        ''', (account_number, transaction_type, amount, description))
        
        conn.commit()
        flash(f'{transaction_type.title()} of ₹{amount:,.2f} processed successfully!', 'success')
        
    except Exception as e:
        conn.rollback()
        flash('Transaction failed! Please try again.', 'error')
    
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin.dashboard', tab='overview'))

@admin.route('/view_customer/<account_number>')
@login_required
def view_customer(account_number):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get customer details
        cursor.execute('SELECT * FROM customers WHERE account_number = %s', (account_number,))
        customer = cursor.fetchone()
        
        if not customer:
            flash('Customer not found!', 'error')
            return redirect(url_for('admin.dashboard'))
        
        # Get customer's transactions
        cursor.execute('''
            SELECT * FROM transactions 
            WHERE account_number = %s 
            ORDER BY transaction_date DESC
        ''', (account_number,))
        transactions = cursor.fetchall()
        
        # Convert Decimal to float for JSON serialization
        customer['balance'] = float(customer['balance'])
        for transaction in transactions:
            transaction['amount'] = float(transaction['amount'])
            transaction['transaction_date'] = transaction['transaction_date'].strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template('view_customer.html', 
                            customer=customer, 
                            transactions=transactions)
        
    except Exception as e:
        flash('Error viewing customer details: ' + str(e), 'error')
        return redirect(url_for('admin.dashboard'))
    
    finally:
        cursor.close()
        conn.close()

@admin.route('/edit_customer/<account_number>', methods=['GET', 'POST'])
@login_required
def edit_customer(account_number):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        if request.method == 'POST':
            name = request.form.get('name')
            new_pin = request.form.get('pin')
            
            if name:
                cursor.execute('''
                    UPDATE customers 
                    SET name = %s 
                    WHERE account_number = %s
                ''', (name, account_number))
            
            if new_pin:
                hashed_pin = bcrypt.hashpw(new_pin.encode('utf-8'), bcrypt.gensalt())
                cursor.execute('''
                    UPDATE customers 
                    SET pin = %s 
                    WHERE account_number = %s
                ''', (hashed_pin, account_number))
            
            conn.commit()
            flash('Customer details updated successfully!', 'success')
            return redirect(url_for('admin.dashboard'))
        
        # GET request - show edit form
        cursor.execute('SELECT * FROM customers WHERE account_number = %s', (account_number,))
        customer = cursor.fetchone()
        
        if not customer:
            flash('Customer not found!', 'error')
            return redirect(url_for('admin.dashboard'))
        
        # Convert Decimal to float for display
        customer['balance'] = float(customer['balance'])
        
        return render_template('edit_customer.html', customer=customer)
        
    except Exception as e:
        conn.rollback()
        flash('Error updating customer details: ' + str(e), 'error')
        return redirect(url_for('admin.dashboard'))
    
    finally:
        cursor.close()
        conn.close()

@admin.route('/delete_customer/<account_number>', methods=['POST'])
@login_required
def delete_customer(account_number):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if customer exists
        cursor.execute('SELECT * FROM customers WHERE account_number = %s', (account_number,))
        if not cursor.fetchone():
            return jsonify({'error': 'Customer not found'}), 404
        
        # Start transaction
        cursor.execute('START TRANSACTION')
        
        # Delete customer's transactions
        cursor.execute('DELETE FROM transactions WHERE account_number = %s', (account_number,))
        
        # Delete customer
        cursor.execute('DELETE FROM customers WHERE account_number = %s', (account_number,))
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Customer deleted successfully'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    
    finally:
        cursor.close()
        conn.close()

@admin.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))

    # Get the active tab from the request
    active_tab = request.args.get('tab', 'overview')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get total customers
        cursor.execute('SELECT COUNT(*) as count FROM customers')
        total_customers = cursor.fetchone()['count']

        # Get total balance
        cursor.execute('SELECT COALESCE(SUM(balance), 0) as total FROM customers')
        total_balance = cursor.fetchone()['total']

        # Get today's transactions
        cursor.execute('''
            SELECT COUNT(*) as count 
            FROM transactions 
            WHERE DATE(transaction_date) = CURDATE()
        ''')
        todays_transactions = cursor.fetchone()['count']

        # Get new accounts today
        cursor.execute('''
            SELECT COUNT(*) as count 
            FROM customers 
            WHERE DATE(created_at) = CURDATE()
        ''')
        new_accounts = cursor.fetchone()['count']

        # Get recent activities
        cursor.execute('''
            SELECT t.*, c.name 
            FROM transactions t
            JOIN customers c ON t.account_number = c.account_number
            ORDER BY t.transaction_date DESC
            LIMIT 10
        ''')
        recent_activities = cursor.fetchall()

        # Get all customers with their last transaction
        cursor.execute('''
            SELECT 
                c.*,
                COALESCE(MAX(t.transaction_date), 'Never') as last_transaction
            FROM customers c
            LEFT JOIN transactions t ON c.account_number = t.account_number
            GROUP BY c.account_number, c.name, c.balance, c.created_at, c.pin
            ORDER BY c.created_at DESC
        ''')
        customers = cursor.fetchall()

        # Convert Decimal objects to float for JSON serialization
        for customer in customers:
            if isinstance(customer['balance'], Decimal):
                customer['balance'] = float(customer['balance'])
            if isinstance(customer['last_transaction'], datetime):
                customer['last_transaction'] = customer['last_transaction'].strftime('%Y-%m-%d %H:%M:%S')

        # Get recent transactions
        cursor.execute('''
            SELECT t.*, c.name 
            FROM transactions t
            JOIN customers c ON t.account_number = c.account_number
            ORDER BY t.transaction_date DESC
            LIMIT 50
        ''')
        transactions = cursor.fetchall()

        # Convert amounts to float and format dates
        for transaction in transactions:
            if isinstance(transaction['amount'], Decimal):
                transaction['amount'] = float(transaction['amount'])
            if isinstance(transaction['transaction_date'], datetime):
                transaction['transaction_date'] = transaction['transaction_date'].strftime('%Y-%m-%d %H:%M:%S')

        # Get pending loans
        cursor.execute("""
            SELECT l.*, c.name as customer_name
            FROM loans l
            JOIN customers c ON l.account_number = c.account_number
            WHERE l.status = 'pending'
            ORDER BY l.application_date DESC
        """)
        pending_loans = cursor.fetchall()

        return render_template('admin_dashboard.html',
                             total_customers=total_customers,
                             total_balance=float(total_balance),
                             todays_transactions=todays_transactions,
                             new_accounts=new_accounts,
                             recent_activities=recent_activities,
                             customers=customers,
                             transactions=transactions,
                             pending_loans=pending_loans,
                             active_tab=active_tab)

    except Exception as e:
        print(f"Error loading admin dashboard: {e}")
        flash('Error loading dashboard data!', 'error')
        return redirect(url_for('index'))

    finally:
        cursor.close()
        conn.close()

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/admin/transaction', methods=['POST'])
@login_required
def admin_transaction():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied!'})

    account_number = request.form.get('account_number')
    amount = float(request.form.get('amount'))
    transaction_type = request.form.get('type')
    notes = request.form.get('notes', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verify account exists
        cursor.execute('SELECT balance FROM customers WHERE account_number = %s', (account_number,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'Account not found!'})

        current_balance = float(result[0])
        
        if transaction_type == 'withdrawal' and amount > current_balance:
            return jsonify({'success': False, 'message': 'Insufficient balance!'})

        # Update balance
        new_balance = current_balance + amount if transaction_type == 'deposit' else current_balance - amount
        cursor.execute('UPDATE customers SET balance = %s WHERE account_number = %s',
                      (new_balance, account_number))

        # Record transaction
        cursor.execute('''
            INSERT INTO transactions (account_number, transaction_type, amount, notes)
            VALUES (%s, %s, %s, %s)
        ''', (account_number, transaction_type, amount, notes))

        conn.commit()
        return jsonify({
            'success': True,
            'message': f'{transaction_type.title()} processed successfully!',
            'new_balance': "{:,.2f}".format(new_balance)
        })

    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': 'Transaction failed! Please try again.'})

    finally:
        cursor.close()
        conn.close()

@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    if not current_user.is_customer:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get customer details
        cursor.execute('SELECT * FROM customers WHERE account_number = %s', (current_user.account_number,))
        customer = cursor.fetchone()

        # Get total deposits
        cursor.execute('''
            SELECT COALESCE(SUM(amount), 0) as total 
            FROM transactions 
            WHERE account_number = %s AND transaction_type = 'deposit'
        ''', (current_user.account_number,))
        total_deposits = cursor.fetchone()['total']

        # Get total withdrawals
        cursor.execute('''
            SELECT COALESCE(SUM(amount), 0) as total 
            FROM transactions 
            WHERE account_number = %s AND transaction_type = 'withdrawal'
        ''', (current_user.account_number,))
        total_withdrawals = cursor.fetchone()['total']

        # Get total transfers
        cursor.execute('''
            SELECT COALESCE(SUM(amount), 0) as total 
            FROM transactions 
            WHERE account_number = %s AND transaction_type = 'transfer'
        ''', (current_user.account_number,))
        total_transfers = cursor.fetchone()['total']

        # Get customer's loans
        cursor.execute('SELECT * FROM loans WHERE account_number = %s ORDER BY application_date DESC', (current_user.account_number,))
        loans = cursor.fetchall()

        # Get recent transactions
        cursor.execute('''
            SELECT * FROM transactions 
            WHERE account_number = %s 
            ORDER BY transaction_date DESC 
            LIMIT 5
        ''', (current_user.account_number,))
        transactions = cursor.fetchall()

        return render_template('customer_dashboard.html', 
                             customer=customer,
                             total_deposits=float(total_deposits),
                             total_withdrawals=float(total_withdrawals),
                             total_transfers=float(total_transfers),
                             transactions=transactions,
                             loans=loans)
    finally:
        cursor.close()
        conn.close()

@app.route('/customer/transfer', methods=['POST'])
@login_required
def transfer_money():
    if not current_user.is_customer:
        return jsonify({'error': 'Unauthorized'}), 403

    recipient_account = request.form.get('recipient_account')
    amount = float(request.form.get('amount'))
    description = request.form.get('description', '')

    # Validate amount
    if amount <= 0:
        flash('Amount must be greater than 0!', 'error')
        return redirect(url_for('customer_dashboard'))

    # Validate recipient account
    if recipient_account == current_user.account_number:
        flash('Cannot transfer to your own account!', 'error')
        return redirect(url_for('customer_dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if recipient exists
        cursor.execute('SELECT * FROM customers WHERE account_number = %s', (recipient_account,))
        recipient = cursor.fetchone()

        if not recipient:
            flash('Recipient account number does not exist! Please check the account number and try again.', 'error')
            return redirect(url_for('customer_dashboard'))

        # Check if sender has sufficient balance
        cursor.execute('SELECT balance FROM customers WHERE account_number = %s', (current_user.account_number,))
        sender_balance = cursor.fetchone()['balance']

        if float(sender_balance) < amount:
            flash(f'Insufficient balance! Your current balance is ₹{float(sender_balance):,.2f}', 'error')
            return redirect(url_for('customer_dashboard'))

        # Start transaction
        cursor.execute('START TRANSACTION')

        # Update sender's balance
        cursor.execute('''
            UPDATE customers 
            SET balance = balance - %s 
            WHERE account_number = %s
        ''', (amount, current_user.account_number))

        # Update recipient's balance
        cursor.execute('''
            UPDATE customers 
            SET balance = balance + %s 
            WHERE account_number = %s
        ''', (amount, recipient_account))

        # Record transfer transaction for sender
        cursor.execute('''
            INSERT INTO transactions (account_number, transaction_type, amount, recipient_account, notes)
            VALUES (%s, %s, %s, %s, %s)
        ''', (current_user.account_number, 'transfer', amount, recipient_account, description))

        # Record deposit transaction for recipient
        cursor.execute('''
            INSERT INTO transactions (account_number, transaction_type, amount, recipient_account, notes)
            VALUES (%s, %s, %s, %s, %s)
        ''', (recipient_account, 'deposit', amount, current_user.account_number, description))

        # Commit transaction
        conn.commit()
        flash('Transfer successful!', 'success')

    except Exception as e:
        conn.rollback()
        print(f"Error processing transfer: {e}")
        flash('Error processing transfer. Please try again.', 'error')

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('customer_dashboard'))

@app.route('/customer/profile/update', methods=['POST'])
@login_required
def update_profile():
    if not current_user.is_customer:
        return jsonify({'error': 'Unauthorized'}), 403

    full_name = request.form.get('full_name')
    current_pin = request.form.get('current_pin')
    new_pin = request.form.get('new_pin')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Verify current PIN
        cursor.execute('SELECT pin FROM customers WHERE account_number = %s', (current_user.account_number,))
        stored_pin = cursor.fetchone()['pin']

        if not bcrypt.checkpw(current_pin.encode('utf-8'), stored_pin.encode('utf-8')):
            flash('Current PIN is incorrect!', 'error')
            return redirect(url_for('customer_dashboard'))

        # Update name
        cursor.execute('''
            UPDATE customers 
            SET name = %s 
            WHERE account_number = %s
        ''', (full_name, current_user.account_number))

        # Update PIN if provided
        if new_pin:
            hashed_pin = bcrypt.hashpw(new_pin.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('''
                UPDATE customers 
                SET pin = %s 
                WHERE account_number = %s
            ''', (hashed_pin, current_user.account_number))

        conn.commit()
        flash('Profile updated successfully!', 'success')

    except Exception as e:
        conn.rollback()
        print(f"Error updating profile: {e}")
        flash('Error updating profile. Please try again.', 'error')

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('customer_dashboard'))

@app.route('/customer/loan/apply', methods=['GET', 'POST'])
@login_required
def apply_loan():
    if not current_user.is_customer:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
            term_months = int(request.form.get('term_months'))
            purpose = request.form.get('purpose')
            monthly_income = float(request.form.get('monthly_income'))
            employment_type = request.form.get('employment_type')

            # Calculate monthly payment (simple interest calculation)
            interest_rate = 12.0  # 12% annual interest rate
            monthly_interest_rate = interest_rate / 12 / 100
            monthly_payment = (amount * monthly_interest_rate * (1 + monthly_interest_rate) ** term_months) / ((1 + monthly_interest_rate) ** term_months - 1)

            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            try:
                cursor.execute('''
                    INSERT INTO loans (account_number, amount, interest_rate, term_months, monthly_payment, 
                    remaining_amount, purpose, monthly_income, employment_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (current_user.account_number, amount, interest_rate, term_months, monthly_payment, 
                     amount, purpose, monthly_income, employment_type))
                
                # Get the newly created loan
                loan_id = cursor.lastrowid
                cursor.execute('SELECT * FROM loans WHERE id = %s', (loan_id,))
                new_loan = cursor.fetchone()
                
                conn.commit()
                return jsonify({
                    'success': True,
                    'message': 'Loan application submitted successfully!',
                    'loan': {
                        'id': new_loan['id'],
                        'amount': float(new_loan['amount']),
                        'term_months': new_loan['term_months'],
                        'monthly_payment': float(new_loan['monthly_payment']),
                        'remaining_amount': float(new_loan['remaining_amount']),
                        'status': new_loan['status'],
                        'application_date': new_loan['application_date'].strftime('%Y-%m-%d %H:%M:%S'),
                        'purpose': new_loan['purpose']
                    }
                })
            except Exception as e:
                conn.rollback()
                print(f"Database error: {str(e)}")  # Log the error
                return jsonify({
                    'success': False,
                    'message': f'Database error: {str(e)}'
                }), 500
            finally:
                cursor.close()
                conn.close()
        except Exception as e:
            print(f"Application error: {str(e)}")  # Log the error
            return jsonify({
                'success': False,
                'message': f'Application error: {str(e)}'
            }), 500

    return render_template('loan_application.html')

@app.route('/customer/loan/cancel/<int:loan_id>', methods=['POST'])
@login_required
def cancel_loan(loan_id):
    if not current_user.is_customer:
        return jsonify({'success': False, 'message': 'Access denied!'}), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if the loan belongs to the current user and is pending
        cursor.execute('''
            SELECT * FROM loans 
            WHERE id = %s AND account_number = %s AND status = 'pending'
        ''', (loan_id, current_user.account_number))
        
        loan = cursor.fetchone()
        
        if not loan:
            return jsonify({
                'success': False,
                'message': 'Loan not found or cannot be cancelled!'
            }), 404

        # Delete the loan
        cursor.execute('DELETE FROM loans WHERE id = %s', (loan_id,))
        
        conn.commit()
        return jsonify({
            'success': True,
            'message': 'Loan application cancelled successfully!'
        })

    except Exception as e:
        conn.rollback()
        print(f"Error cancelling loan: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error cancelling loan application. Please try again.'
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/admin/loans/pending')
@login_required
def pending_loans():
    if not current_user.is_admin:
        return redirect(url_for('customer_dashboard'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get all pending loans with customer details
        cursor.execute("""
            SELECT l.*, c.name as customer_name
            FROM loans l
            JOIN customers c ON l.account_number = c.account_number
            WHERE l.status = 'pending'
            ORDER BY l.application_date DESC
        """)
        pending_loans = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('admin_dashboard.html', pending_loans=pending_loans)
    except Exception as e:
        app.logger.error(f"Error fetching pending loans: {str(e)}")
        flash('Error fetching pending loans', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/loan/approve/<int:loan_id>', methods=['POST'])
@login_required
def approve_loan(loan_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get loan details
        cursor.execute("""
            SELECT l.*, c.account_number
            FROM loans l
            JOIN customers c ON l.account_number = c.account_number
            WHERE l.id = %s AND l.status = 'pending'
        """, (loan_id,))
        loan = cursor.fetchone()
        
        if not loan:
            return jsonify({'success': False, 'message': 'Loan not found or already processed'})
        
        # Start transaction
        cursor.execute("START TRANSACTION")
        
        try:
            # Update loan status
            cursor.execute("""
                UPDATE loans 
                SET status = 'approved', 
                    approval_date = NOW()
                WHERE id = %s
            """, (loan_id,))
            
            # Credit the loan amount to customer's account
            cursor.execute("""
                UPDATE customers 
                SET balance = balance + %s
                WHERE account_number = %s
            """, (loan['amount'], loan['account_number']))
            
            # Add transaction record
            cursor.execute("""
                INSERT INTO transactions (
                    account_number, 
                    transaction_type, 
                    amount, 
                    notes
                ) VALUES (%s, %s, %s, %s)
            """, (loan['account_number'], 'deposit', loan['amount'], 
                  f'Loan disbursement - Loan ID: {loan_id}'))
            
            # Commit transaction
            conn.commit()
            
            app.logger.info(f"Loan {loan_id} approved successfully. Amount: {loan['amount']}, Account: {loan['account_number']}")
            
            return jsonify({
                'success': True, 
                'message': 'Loan approved successfully'
            })
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error in loan approval transaction: {str(e)}")
            raise e
            
    except Exception as e:
        app.logger.error(f"Error approving loan: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'Error approving loan'
        })
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/loan/reject/<int:loan_id>', methods=['POST'])
@login_required
def reject_loan(loan_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Update loan status to rejected
        cursor.execute("""
            UPDATE loans 
            SET status = 'rejected', 
                approval_date = NOW()
            WHERE id = %s AND status = 'pending'
        """, (loan_id,))
        
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({
                'success': False, 
                'message': 'Loan not found or already processed'
            })
            
        return jsonify({
            'success': True, 
            'message': 'Loan rejected successfully'
        })
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error rejecting loan: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'Error rejecting loan'
        })
    finally:
        cursor.close()
        conn.close()

# Register admin blueprint (moved to end of file)
app.register_blueprint(admin)

if __name__ == '__main__':
    app.run(debug=True) 