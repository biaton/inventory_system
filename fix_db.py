import mysql.connector
import os

# Kunin natin ang details sa settings mo (o i-type mo manually dito)
db_config = {
    "host": "localhost",
    "user": "root",        # Palitan mo kung iba ang username mo
    "password": "password",    # Palitan mo ng actual MySQL password mo
    "database": "inventory_system_db" # Siguraduhin na tama ang DB name mo
}

try:
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    
    # Ito ang command na magdadagdag ng missing column
    sql = "ALTER TABLE Inventory_customerorder ADD COLUMN order_type VARCHAR(20) DEFAULT 'Standard';"
    
    cursor.execute(sql)
    conn.commit()
    print("✅ Success! 'order_type' column added to MySQL.")
    
except Exception as e:
    print(f"❌ Error: {e}")
finally:
    if 'conn' in locals() and conn.is_connected():
        cursor.close()
        conn.close()