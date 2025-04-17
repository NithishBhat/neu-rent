import pymysql
from tabulate import tabulate
import os
from getpass import getpass
import hashlib
import uuid
from datetime import datetime, timedelta
import re

def signup(cursor, conn):
    print("\n=== Signup ===")
    email = input("Enter your email: ").strip()
    # Verify that the email is unique by checking the user table.
    cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
    if cursor.fetchone() is not None:
        print("An account with this email already exists. Please log in instead or use a different email.\n")
        return None

    password = getpass("Enter your password: ")
    confirm_password = getpass("Confirm your password: ")
    if password != confirm_password:
        print("Passwords do not match. Please try again.\n")
        return None

    first_name = input("Enter your first name: ").strip()
    last_name = input("Enter your last name: ").strip()
    phone = input("Enter your phone number: ").strip()

    # Generate a salt and hash the password using SHA-256.
    salt = uuid.uuid4().hex
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()

    # Insert authentication record into user_auth (using email as username).
    cursor.execute(
        "INSERT INTO user_auth (username, password_hash, salt) VALUES (%s, %s, %s)",
        (email, password_hash, salt)
    )
    auth_id = cursor.lastrowid

    # Insert into the user table.
    cursor.execute(
        "INSERT INTO user (auth_id, first_name, last_name, phone, email) VALUES (%s, %s, %s, %s, %s)",
        (auth_id, first_name, last_name, phone, email)
    )
    conn.commit()
    print("Signup successful! You can now log in.\n")
    return email

def login(cursor):
    print("\n=== Login ===")
    email = input("Enter your email: ").strip()
    password = getpass("Enter your password: ")

    # Retrieve the user record using the email.
    cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
    user_record = cursor.fetchone()
    if user_record is None:
        print("No account found with that email. Please sign up first.\n")
        return None

    # The user table is expected to have: user_id, auth_id, first_name, last_name, phone, email.
    auth_id = user_record[1]
    cursor.execute("SELECT * FROM user_auth WHERE auth_id = %s", (auth_id,))
    auth_record = cursor.fetchone()
    stored_password_hash = auth_record[2]
    salt = auth_record[3]
    
    # Hash the provided password with the retrieved salt.
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    if password_hash == stored_password_hash:
        # Update last login timestamp
        cursor.execute("UPDATE user_auth SET last_login = NOW() WHERE auth_id = %s", (auth_id,))
        print("Login successful!\n")
        return user_record[0]  # Return user_id instead of email
    else:
        print("Incorrect password. Please try again.\n")
        return None

def get_user_info(cursor, user_id):
    """Get comprehensive user information."""
    cursor.execute("""
        SELECT u.user_id, u.first_name, u.last_name, u.email, u.phone, 
               ua.username, ua.last_login
        FROM user u
        JOIN user_auth ua ON u.auth_id = ua.auth_id
        WHERE u.user_id = %s
    """, (user_id,))
    return cursor.fetchone()

def check_tenant_status(cursor, user_id):
    """Check if the user is registered as a tenant."""
    cursor.execute("SELECT * FROM tenant WHERE user_id = %s", (user_id,))
    return cursor.fetchone() is not None

def check_landlord_status(cursor, user_id):
    """Check if the user is registered as a landlord."""
    cursor.execute("SELECT * FROM landlord WHERE user_id = %s", (user_id,))
    return cursor.fetchone() is not None

def register_as_tenant(cursor, conn, user_id):
    """Register the user as a tenant if not already registered."""
    if not check_tenant_status(cursor, user_id):
        cursor.execute("INSERT INTO tenant (user_id) VALUES (%s)", (user_id,))
        conn.commit()
        print("You have been registered as a tenant.")
        return True
    return False

def validate_ssn(ssn):
    """Validate Social Security Number format."""
    # Check for XXX-XX-XXXX format
    if re.match(r'^\d{3}-\d{2}-\d{4}$', ssn):
        return True
    # Check for XXXXXXXXX format
    elif re.match(r'^\d{9}$', ssn):
        return True
    else:
        print("Invalid SSN format. Please use XXX-XX-XXXX or XXXXXXXXX format.")
        return False

def validate_email(email):
    """Validate email format."""
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return True
    else:
        print("Invalid email format. Please enter a valid email address.")
        return False

def view_profile(cursor, user_id):
    """View user profile information."""
    if not user_id:
        print("You need to login first.")
        return
    
    try:
        # Get basic user information
        cursor.execute("""
        SELECT u.user_id, u.first_name, u.last_name, u.phone, u.email, 
               ua.username, ua.last_login
        FROM user u
        JOIN user_auth ua ON u.auth_id = ua.auth_id
        WHERE u.user_id = %s
        """, (user_id,))
        user_info = cursor.fetchone()
        
        if not user_info:
            print("User information not found.")
            return
        
        print("\n===== USER PROFILE =====")
        print(f"Name: {user_info[1]} {user_info[2]}")
        print(f"Username: {user_info[5]}")
        print(f"Email: {user_info[4]}")
        print(f"Phone: {user_info[3]}")
        print(f"Last Login: {user_info[6]}")
        
        # Check for landlord status
        cursor.execute("SELECT * FROM landlord WHERE user_id = %s", (user_id,))
        landlord_data = cursor.fetchone()
        
        if landlord_data:
            print("Registered as: Landlord")
        
        # Check for tenant status
        cursor.execute("SELECT * FROM tenant WHERE user_id = %s", (user_id,))
        tenant_data = cursor.fetchone()
        
        if tenant_data:
            print("Registered as: Tenant")
        
        # Check for US Citizen status
        cursor.execute("SELECT ssn FROM us_citizen WHERE user_id = %s", (user_id,))
        us_citizen = cursor.fetchone()
        
        if us_citizen:
            print("Status: US Citizen")
            print(f"SSN: {us_citizen[0]}")
        
        # Check for International Student status
        cursor.execute("SELECT passport_id FROM international_student WHERE user_id = %s", (user_id,))
        intl_student = cursor.fetchone()
        
        if intl_student:
            print("Status: International Student")
            print(f"Passport ID: {intl_student[0]}")
        
        # Check for Student status
        cursor.execute("SELECT * FROM student WHERE user_id = %s", (user_id,))
        student = cursor.fetchone()
        
        if student:
            print("Status: Student")
            
    except Exception as e:
        print(f"Error retrieving profile: {e}")

def update_personal_info(cursor, conn, user_id):
    """Update personal information."""
    if not user_id:
        print("You need to login first.")
        return
    
    try:
        # Get current user information
        cursor.execute("""
        SELECT u.user_id, u.first_name, u.last_name, u.phone, u.email, ua.username
        FROM user u
        JOIN user_auth ua ON u.auth_id = ua.auth_id
        WHERE u.user_id = %s
        """, (user_id,))
        user_info = cursor.fetchone()
        
        if not user_info:
            print("User information not found.")
            return
        
        print("\n===== UPDATE PERSONAL INFORMATION =====")
        print(f"Current Name: {user_info[1]} {user_info[2]}")
        print(f"Current Phone: {user_info[3]}")
        print(f"Current Email: {user_info[4]}")
        
        print("\nWhich field would you like to update?")
        print("1. Name")
        print("2. Phone")
        print("3. Email")
        
        # Check for additional user statuses
        # Check for US Citizen status
        cursor.execute("SELECT * FROM us_citizen WHERE user_id = %s", (user_id,))
        us_citizen_data = cursor.fetchone()
        
        if us_citizen_data:
            print("4. SSN (US Citizen)")
        
        # Check for International Student status
        cursor.execute("SELECT * FROM international_student WHERE user_id = %s", (user_id,))
        intl_student_data = cursor.fetchone()
        
        if intl_student_data:
            print("5. Passport ID (International Student)")
        
        # Check for Student status
        cursor.execute("SELECT * FROM student WHERE user_id = %s", (user_id,))
        student_data = cursor.fetchone()
        
        if student_data:
            print("6. Transcript (Student)")
            
        # Offer additional registration options
        if not us_citizen_data and not intl_student_data:
            print("7. Register as US Citizen or International Student")
        
        if not student_data:
            print("8. Register as Student")
        
        while True:
            field_choice = input("Enter your choice (or 0 to cancel): ")
            if field_choice.isdigit() and 0 <= int(field_choice) <= 8:
                field_choice = int(field_choice)
                
                # Check if choice is valid for the user's status
                if field_choice == 4 and not us_citizen_data:
                    print("You are not registered as a US Citizen.")
                    continue
                if field_choice == 5 and not intl_student_data:
                    print("You are not registered as an International Student.")
                    continue
                if field_choice == 6 and not student_data:
                    print("You are not registered as a Student.")
                    continue
                if field_choice == 7 and (us_citizen_data or intl_student_data):
                    print("You are already registered as a US Citizen or International Student.")
                    continue
                if field_choice == 8 and student_data:
                    print("You are already registered as a Student.")
                    continue
                
                break
            else:
                print("Invalid choice. Please enter a valid number.")
        
        if field_choice == 0:
            return
        elif field_choice == 1:
            while True:
                first_name_input = input(f"First Name [{user_info[1]}]: ")
                if not first_name_input:
                    first_name = user_info[1]
                    break
                elif first_name_input.strip() and all(c.isalpha() or c.isspace() for c in first_name_input):
                    first_name = first_name_input
                    break
                else:
                    print("Invalid first name. Please use only letters and spaces.")
            
            while True:
                last_name_input = input(f"Last Name [{user_info[2]}]: ")
                if not last_name_input:
                    last_name = user_info[2]
                    break
                elif last_name_input.strip() and all(c.isalpha() or c.isspace() or c == '-' for c in last_name_input):
                    last_name = last_name_input
                    break
                else:
                    print("Invalid last name. Please use only letters, spaces, and hyphens.")
            
            update_query = """
            UPDATE user 
            SET first_name = %s, last_name = %s
            WHERE user_id = %s
            """
            cursor.execute(update_query, (first_name, last_name, user_id))
            
        elif field_choice == 2:
            while True:
                phone_input = input(f"Phone [{user_info[3]}]: ")
                if not phone_input:
                    phone = user_info[3]
                    break
                else:
                    # Simple validation - could be enhanced
                    phone = phone_input
                    break
            
            # Check if phone already exists
            cursor.execute("SELECT * FROM user WHERE phone = %s AND user_id != %s", (phone, user_id))
            if cursor.fetchone():
                print("This phone number is already in use by another user.")
                return
            
            update_query = "UPDATE user SET phone = %s WHERE user_id = %s"
            cursor.execute(update_query, (phone, user_id))
            
        elif field_choice == 3:
            while True:
                email_input = input(f"Email [{user_info[4]}]: ")
                if not email_input:
                    email = user_info[4]
                    break
                elif validate_email(email_input):
                    email = email_input
                    break
            
            # Check if email already exists
            cursor.execute("SELECT * FROM user WHERE email = %s AND user_id != %s", (email, user_id))
            if cursor.fetchone():
                print("This email is already in use by another user.")
                return
            
            update_query = "UPDATE user SET email = %s WHERE user_id = %s"
            cursor.execute(update_query, (email, user_id))
            
        elif field_choice == 4 and us_citizen_data:
            while True:
                ssn_input = input(f"SSN [{us_citizen_data[1]}]: ")
                if not ssn_input:
                    ssn = us_citizen_data[1]
                    break
                elif validate_ssn(ssn_input):
                    ssn = ssn_input
                    break
            
            # Check if SSN already exists
            cursor.execute("SELECT * FROM us_citizen WHERE ssn = %s AND user_id != %s", (ssn, user_id))
            if cursor.fetchone():
                print("This SSN is already in use by another user.")
                return
            
            update_query = "UPDATE us_citizen SET ssn = %s WHERE user_id = %s"
            cursor.execute(update_query, (ssn, user_id))
            
        elif field_choice == 5 and intl_student_data:
            while True:
                passport_id_input = input(f"Passport ID [{intl_student_data[1]}]: ")
                if not passport_id_input:
                    passport_id = intl_student_data[1]
                    break
                elif passport_id_input.strip():
                    passport_id = passport_id_input
                    break
                else:
                    print("Passport ID cannot be empty.")
            
            # Check if passport ID already exists
            cursor.execute("SELECT * FROM international_student WHERE passport_id = %s AND user_id != %s", (passport_id, user_id))
            if cursor.fetchone():
                print("This passport ID is already in use by another user.")
                return
            
            update_query = "UPDATE international_student SET passport_id = %s WHERE user_id = %s"
            cursor.execute(update_query, (passport_id, user_id))
            
        elif field_choice == 6 and student_data:
            # In a real application, you would have a file upload mechanism
            # For this example, we'll just update a placeholder
            update_query = "UPDATE student SET transcript = 'UPDATED_PDF' WHERE user_id = %s"
            cursor.execute(update_query, (user_id,))
            print("Transcript updated. (In a real application, you would upload a file.)")
            
        elif field_choice == 7 and not us_citizen_data and not intl_student_data:
            print("\nRegister as:")
            print("1. US Citizen")
            print("2. International Student")
            
            while True:
                citizen_choice = input("Enter your choice (or 0 to cancel): ")
                if citizen_choice in ['0', '1', '2']:
                    break
                else:
                    print("Invalid choice. Please enter 0, 1, or 2.")
            
            if citizen_choice == '0':
                return
            elif citizen_choice == '1':
                while True:
                    ssn = input("Enter your SSN (XXX-XX-XXXX or XXXXXXXXX): ")
                    if validate_ssn(ssn):
                        break
                
                # Check if SSN already exists
                cursor.execute("SELECT * FROM us_citizen WHERE ssn = %s", (ssn,))
                if cursor.fetchone():
                    print("This SSN is already in use by another user.")
                    return
                
                # Insert US citizen record
                insert_query = "INSERT INTO us_citizen (user_id, ssn) VALUES (%s, %s)"
                cursor.execute(insert_query, (user_id, ssn))
                print("Registered as US Citizen successfully.")
                
            elif citizen_choice == '2':
                while True:
                    passport_id = input("Enter your Passport ID: ")
                    if passport_id.strip():
                        break
                    else:
                        print("Passport ID cannot be empty.")
                
                # Check if passport ID already exists
                cursor.execute("SELECT * FROM international_student WHERE passport_id = %s", (passport_id,))
                if cursor.fetchone():
                    print("This passport ID is already in use by another user.")
                    return
                
                # Insert international student record
                insert_query = "INSERT INTO international_student (user_id, passport_id) VALUES (%s, %s)"
                cursor.execute(insert_query, (user_id, passport_id))
                
                # Also insert student record if not already student
                cursor.execute("SELECT * FROM student WHERE user_id = %s", (user_id,))
                if not cursor.fetchone():
                    insert_query = "INSERT INTO student (user_id, transcript) VALUES (%s, 'PDF')"
                    cursor.execute(insert_query, (user_id,))
                
                print("Registered as International Student successfully.")
        
        elif field_choice == 8 and not student_data:
            # In a real application, you would have a file upload mechanism
            # For this example, we'll just insert a placeholder
            insert_query = "INSERT INTO student (user_id, transcript) VALUES (%s, 'PDF')"
            cursor.execute(insert_query, (user_id,))
            print("Registered as Student successfully.")
            print("Transcript placeholder added. (In a real application, you would upload a file.)")
        
        conn.commit()
        print("Information updated successfully!")
            
    except Exception as e:
        print(f"Error updating information: {e}")

def view_available_properties(cursor):
    """View properties available for rent."""
    try:
        # Prepare filters
        print("\n===== PROPERTY SEARCH FILTERS =====")
        print("(Leave blank to skip filter)")
        
        city = input("City: ")
        state = input("State: ")
        
        min_price = None
        max_price = None
        min_sqft = None
        min_rooms = None
        
        min_price_input = input("Minimum Price: ")
        if min_price_input:
            try:
                min_price = float(min_price_input)
                if min_price < 0:
                    print("Minimum price cannot be negative. Using 0 instead.")
                    min_price = 0
            except ValueError:
                print("Invalid input for minimum price. Skipping this filter.")
        
        max_price_input = input("Maximum Price: ")
        if max_price_input:
            try:
                max_price = float(max_price_input)
                if max_price < 0:
                    print("Maximum price cannot be negative. Skipping this filter.")
                    max_price = None
                elif min_price is not None and max_price < min_price:
                    print("Maximum price cannot be less than minimum price. Skipping this filter.")
                    max_price = None
            except ValueError:
                print("Invalid input for maximum price. Skipping this filter.")
        
        min_sqft_input = input("Minimum Square Footage: ")
        if min_sqft_input:
            try:
                min_sqft = float(min_sqft_input)
                if min_sqft < 0:
                    print("Minimum square footage cannot be negative. Using 0 instead.")
                    min_sqft = 0
            except ValueError:
                print("Invalid input for minimum square footage. Skipping this filter.")
        
        min_rooms_input = input("Minimum Number of Rooms: ")
        if min_rooms_input:
            try:
                min_rooms = int(min_rooms_input)
                if min_rooms < 1:
                    print("Minimum rooms cannot be less than 1. Using 1 instead.")
                    min_rooms = 1
            except ValueError:
                print("Invalid input for minimum rooms. Skipping this filter.")
        
        # Build query with filters
        query = """
        SELECT p.property_id, p.street_number, p.street_name, p.city, p.state, 
               p.room_number, p.square_foot, p.price, p.room_amount,
               u.first_name AS landlord_first_name, u.last_name AS landlord_last_name,
               n.name AS neighborhood_name
        FROM properties p
        JOIN landlord l ON p.landlord_id = l.user_id
        JOIN user u ON l.user_id = u.user_id
        LEFT JOIN property_neighborhood pn ON p.property_id = pn.property_id
        LEFT JOIN neighborhood n ON pn.neighborhood_id = n.neighborhood_id
        WHERE p.for_rent = 1
        """
        
        # Add filters to query
        params = []
        
        if city:
            query += " AND p.city = %s"
            params.append(city)
        
        if state:
            query += " AND p.state = %s"
            params.append(state)
        
        if min_price is not None:
            query += " AND p.price >= %s"
            params.append(min_price)
        
        if max_price is not None:
            query += " AND p.price <= %s"
            params.append(max_price)
        
        if min_sqft is not None:
            query += " AND p.square_foot >= %s"
            params.append(min_sqft)
        
        if min_rooms is not None:
            query += " AND p.room_amount >= %s"
            params.append(min_rooms)
            
        # Order by price
        query += " ORDER BY p.price"
        
        cursor.execute(query, params)
        properties = cursor.fetchall()
        
        if not properties:
            print("No available properties found matching your criteria.")
            return
        
        print(f"\n===== AVAILABLE PROPERTIES ({len(properties)}) =====")
        
        for prop in properties:
            print(f"\nProperty ID: {prop[0]}")
            print(f"Address: {prop[1]} {prop[2]}, {prop[3]}, {prop[4]}")
            print(f"Room: {prop[5]}")
            print(f"Square Footage: {prop[6]} sq ft")
            print(f"Price: ${prop[7]}")
            print(f"Number of Rooms: {prop[8]}")
            print(f"Landlord: {prop[9]} {prop[10]}")
            
            if prop[11]:
                print(f"Neighborhood: {prop[11]}")
        
    except Exception as e:
        print(f"Error retrieving available properties: {e}")

def view_my_rentals(cursor, user_id):
    """View properties rented by the current user."""
    if not user_id:
        print("You need to login first.")
        return
    
    try:
        # Check if user is a tenant
        cursor.execute("SELECT * FROM tenant WHERE user_id = %s", (user_id,))
        is_tenant = cursor.fetchone()
        
        if not is_tenant:
            print("You are not registered as a tenant.")
            while True:
                register = input("Do you want to register as a tenant? (y/n): ").lower()
                if register in ['y', 'n']:
                    if register == 'y':
                        cursor.execute("INSERT INTO tenant (user_id) VALUES (%s)", (user_id,))
                        conn.commit()
                        print("You have been registered as a tenant.")
                    else:
                        return
                    break
                else:
                    print("Invalid input. Please enter 'y' or 'n'.")
        
        query = """
        SELECT r.rent_id, r.property_id, r.start_date, r.end_date, r.price, r.broker_fee,
               p.street_number, p.street_name, p.city, p.state, p.room_number, p.square_foot,
               u.first_name AS landlord_first_name, u.last_name AS landlord_last_name, 
               u.phone AS landlord_phone, u.email AS landlord_email,
               b.first_name AS broker_first_name, b.last_name AS broker_last_name
        FROM rent r
        JOIN properties p ON r.property_id = p.property_id
        JOIN landlord l ON p.landlord_id = l.user_id
        JOIN user u ON l.user_id = u.user_id
        LEFT JOIN broker b ON r.broker_id = b.broker_id
        WHERE r.tenant_id = %s
        ORDER BY r.end_date DESC
        """
        cursor.execute(query, (user_id,))
        rentals = cursor.fetchall()
        
        if not rentals:
            print("You don't have any property rentals.")
            return
        
        print("\n===== MY RENTALS =====")
        
        today = datetime.now().date()
        
        # Separate current and past rentals
        current_rentals = [r for r in rentals if r[3] >= today]
        past_rentals = [r for r in rentals if r[3] < today]
        
        if current_rentals:
            print("\nCURRENT RENTALS:")
            for rental in current_rentals:
                print(f"\nRental ID: {rental[0]}")
                print(f"Property: {rental[6]} {rental[7]}, "
                      f"{rental[8]}, {rental[9]}, Room {rental[10]}")
                print(f"Square Footage: {rental[11]} sq ft")
                print(f"Rental Period: {rental[2]} to {rental[3]}")
                print(f"Monthly Rent: ${rental[4]}")
                
                if rental[5] and rental[16]:
                    print(f"Broker: {rental[16]} {rental[17]}")
                    print(f"Broker Fee: ${rental[5]}")
                
                print(f"Landlord: {rental[12]} {rental[13]}")
                print(f"Landlord Contact: {rental[14]} / {rental[15]}")
        
        if past_rentals:
            print("\nPAST RENTALS:")
            for rental in past_rentals:
                print(f"\nRental ID: {rental[0]}")
                print(f"Property: {rental[6]} {rental[7]}, "
                      f"{rental[8]}, {rental[9]}, Room {rental[10]}")
                print(f"Rental Period: {rental[2]} to {rental[3]}")
                print(f"Monthly Rent: ${rental[4]}")
        
    except Exception as e:
        print(f"Error retrieving rentals: {e}")

def rent_property(cursor, conn, user_id):
    """Rent a property."""
    if not user_id:
        print("You need to login first.")
        return
    
    try:
        # Check if user is a tenant
        tenant_status = check_tenant_status(cursor, user_id)
        if not tenant_status:
            register_as_tenant(cursor, conn, user_id)
        
        property_id = input("Enter the Property ID you want to rent: ")
        if not property_id.isdigit():
            print("Invalid property ID. Please enter a number.")
            return
        
        property_id = int(property_id)
        
        # Check if property exists and is available for rent
        query = """
        SELECT p.*, u.first_name, u.last_name
        FROM properties p
        JOIN landlord l ON p.landlord_id = l.user_id
        JOIN user u ON l.user_id = u.user_id
        WHERE p.property_id = %s AND p.for_rent = 1
        """
        cursor.execute(query, (property_id,))
        property_data = cursor.fetchone()
        
        if not property_data:
            print("Property not found or not available for rent.")
            return
        
        # Check if property is already rented by this tenant
        query = """
        SELECT * FROM rent 
        WHERE property_id = %s AND tenant_id = %s AND end_date >= CURRENT_DATE
        """
        cursor.execute(query, (property_id, user_id))
        existing_rental = cursor.fetchone()
        
        if existing_rental:
            print("You are already renting this property.")
            return
        
        print("\n===== RENT PROPERTY =====")
        print(f"Property: {property_data[1]} {property_data[2]}, "
              f"{property_data[3]}, {property_data[4]}, Room {property_data[5]}")
        print(f"Landlord: {property_data[11]} {property_data[12]}")
        print(f"Monthly Rent: ${property_data[8]}")
        
        # Ask for rental details with validation
        while True:
            contract_length_input = input("Contract Length (months): ")
            if contract_length_input.isdigit() and int(contract_length_input) > 0:
                contract_length = int(contract_length_input)
                break
            else:
                print("Please enter a positive number for contract length.")
        
        # Ask if using a broker
        while True:
            use_broker_input = input("Do you want to use a broker for this rental? (y/n): ").lower()
            if use_broker_input in ['y', 'n']:
                use_broker = use_broker_input == 'y'
                break
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
        
        broker_id = None
        broker_fee = None
        
        if use_broker:
            # Show available brokers
            cursor.execute("SELECT broker_id, first_name, last_name FROM broker")
            brokers = cursor.fetchall()
            
            if not brokers:
                print("No brokers available in the system.")
                use_broker = False
            else:
                print("\nAvailable Brokers:")
                for broker in brokers:
                    print(f"{broker[0]}. {broker[1]} {broker[2]}")
                
                while True:
                    broker_choice = input("Enter Broker ID (or 0 to skip): ")
                    if broker_choice.isdigit():
                        broker_id = int(broker_choice)
                        if broker_id == 0:
                            broker_id = None
                            break
                            
                        # Verify broker exists
                        broker_exists = False
                        for broker in brokers:
                            if broker[0] == broker_id:
                                broker_exists = True
                                break
                        
                        if broker_exists:
                            while True:
                                broker_fee_input = input("Broker Fee ($): ")
                                if broker_fee_input.replace('.', '', 1).isdigit():
                                    broker_fee = float(broker_fee_input)
                                    if broker_fee < 0:
                                        print("Broker fee cannot be negative.")
                                    else:
                                        break
                                else:
                                    print("Please enter a valid number for broker fee.")
                            break
                        else:
                            print("Invalid broker ID. Please select from the list.")
                    else:
                        print("Invalid input. Please enter a number.")
        
        # Calculate dates
        start_date = datetime.now().date()
        end_date = start_date + timedelta(days=30 * contract_length)
        
        # Confirm rental
        print("\nRental Summary:")
        print(f"Property: {property_data[1]} {property_data[2]}, "
              f"{property_data[3]}, {property_data[4]}, Room {property_data[5]}")
        print(f"Monthly Rent: ${property_data[8]}")
        print(f"Contract Length: {contract_length} months")
        print(f"Start Date: {start_date}")
        print(f"End Date: {end_date}")
        
        if broker_id:
            print(f"Broker ID: {broker_id}")
            print(f"Broker Fee: ${broker_fee}")
        
        while True:
            confirm = input("Confirm rental (y/n): ").lower()
            if confirm in ['y', 'n']:
                if confirm != 'y':
                    print("Rental cancelled.")
                    return
                break
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
        
        # Insert rental
        insert_query = """
        INSERT INTO rent (tenant_id, property_id, contract_length, price, broker_fee, broker_id, start_date, end_date)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (user_id, property_id, contract_length, 
                                     property_data[8], broker_fee, broker_id, start_date, end_date))
        
        # Insert broker-tenant relationship if not exists and broker is used
        if broker_id:
            query = """
            SELECT * FROM broker_tenant 
            WHERE broker_id = %s AND tenant_id = %s
            """
            cursor.execute(query, (broker_id, user_id))
            if not cursor.fetchone():
                query = """
                INSERT INTO broker_tenant (broker_id, tenant_id)
                VALUES (%s, %s)
                """
                cursor.execute(query, (broker_id, user_id))
        
        # Update property availability
        query = "UPDATE properties SET for_rent = 0 WHERE property_id = %s"
        cursor.execute(query, (property_id,))
        
        conn.commit()
        print("Property rented successfully!")
        
    except Exception as e:
        print(f"Error renting property: {e}")

def display_menu():
    """Display the main menu."""
    print("\n===== RENTAL SYSTEM MENU =====")
    print("1. View My Profile")
    print("2. Update My Profile Information")
    print("3. View Available Properties")
    print("4. View My Rentals")
    print("5. Rent a Property")
    print("0. Logout")
    
    while True:
        choice = input("Enter your choice: ")
        if choice in ['0', '1', '2', '3', '4', '5']:
            return choice
        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

def main():
    try:
        # Connect to the database
        conn = pymysql.connect(
            host='localhost',
            database='rental_system',
            user='root',
            password='red',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.Cursor
        )
        print("Connected to MySQL database")
        
        cursor = conn.cursor()
        user_id = None
        
        while True:
            if user_id is None:
                print("\n=== Welcome to Rental System ===")
                print("1. Login")
                print("2. Sign Up")
                print("0. Exit")
                
                choice = input("Enter your choice: ")
                
                if choice == '1':
                    user_id = login(cursor)
                    if user_id:
                        # Update last login time
                        cursor.execute("UPDATE user_auth ua JOIN user u ON ua.auth_id = u.auth_id SET ua.last_login = NOW() WHERE u.user_id = %s", (user_id,))
                        conn.commit()
                elif choice == '2':
                    email = signup(cursor, conn)
                    if email:
                        print("Please log in with your new account.")
                elif choice == '0':
                    print("Thank you for using the Rental System. Goodbye!")
                    break
                else:
                    print("Invalid choice. Please try again.")
            else:
                # User is logged in, show the main menu
                choice = display_menu()
                
                if choice == '0':
                    user_id = None
                    print("Logged out successfully.")
                elif choice == '1':
                    view_profile(cursor, user_id)
                elif choice == '2':
                    update_personal_info(cursor, conn, user_id)
                elif choice == '3':
                    view_available_properties(cursor)
                elif choice == '4':
                    view_my_rentals(cursor, user_id)
                elif choice == '5':
                    rent_property(cursor, conn, user_id)
        
        # Close the database connection
        cursor.close()
        conn.close()
        print("Database connection closed.")
        
    except Exception as e:
        print(f"Error: {e}")
        return

if __name__ == "__main__":
    main()
