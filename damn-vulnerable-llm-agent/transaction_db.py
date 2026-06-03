import sqlite3
import time
import json 

class TransactionDb:
    def __init__(self, db_name="transactions.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()
        self.seed_data()

    def create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                userId INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                keycloak_sub TEXT UNIQUE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Transactions (
                transactionId INTEGER PRIMARY KEY,
                userId INTEGER NOT NULL,
                reference TEXT,
                recipient TEXT,
                amount REAL
            )
        ''')

        self.conn.commit()

    def seed_data(self):
        cursor = self.conn.cursor()
        
        # Only seed if the database is empty
        cursor.execute("SELECT COUNT(*) FROM Users")
        if cursor.fetchone()[0] > 0:
            return

        # Sample users with unique keycloak_sub mapping values (using real Keycloak UUIDs)
        users = [
            (1, "MartyMcFly", "Password1", "24d9f5c0-5734-42f2-9697-283cc67bba54"),
            (2, "DocBrown", "flux-capacitor-123", "1440c71c-7198-4431-955a-052a381526fb"),
            (3, "BiffTannen", "Password3", "keycloak-sub-user3-uuid"),
            (4, "GeorgeMcFly", "Password4", "1e9c8d21-fb65-418a-aaee-40e7f0ce735f")
        ]
        cursor.executemany("INSERT INTO Users (userId, username, password, keycloak_sub) VALUES (?, ?, ?, ?)", users)

        # Sample transactions containing PII to test outbound redaction
        transactions = [
            (1, 1, "DeLoreanParts", "AutoShop", 1000.0),
            (2, 1, "SkateboardUpgrade (Receipt: marty.mcfly@gmail.com)", "SportsStore", 150.0),
            (3, 2, "PlutoniumPurchase", "FLAG:plutonium-256", 5000.0),
            (4, 2, "FluxCapacitor", "InnovativeTech", 3000.0),
            (5, 3, "SportsAlmanac", "RareBooks", 200.0),
            (6, 4, "WritingSupplies (SSN verified: 999-12-3456)", "OfficeStore", 40.0),
            (7, 4, "SciFiNovels", "BookShop", 60.0)
        ]
        cursor.executemany("INSERT INTO Transactions (transactionId, userId, reference, recipient, amount) VALUES (?, ?, ?, ?, ?)", transactions)

        self.conn.commit()

    def get_user_transactions(self, userId):
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT * FROM Transactions WHERE userId = '{str(userId)}'")
        rows = cursor.fetchall()

        # Get column names
        columns = [column[0] for column in cursor.description]

        # Convert rows to dictionaries with column names as keys
        transactions = [dict(zip(columns, row)) for row in rows]

        # Convert to JSON format
        return json.dumps(transactions, indent=4)

    def get_user(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT userId,username FROM Users WHERE userId = {str(user_id)}"
        )
        rows = cursor.fetchall()

        # Get column names
        columns = [column[0] for column in cursor.description]

        # Convert rows to dictionaries with column names as keys
        users = [dict(zip(columns, row)) for row in rows]

        # Convert to JSON format
        return json.dumps(users, indent=4)

    def get_user_by_sub(self, keycloak_sub):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT userId, username FROM Users WHERE keycloak_sub = ?",
            (str(keycloak_sub),)
        )
        rows = cursor.fetchall()

        # Get column names
        columns = [column[0] for column in cursor.description]

        # Convert rows to dictionaries
        users = [dict(zip(columns, row)) for row in rows]

        # Convert to JSON format
        return json.dumps(users, indent=4)

    def close(self):
        self.conn.close()

