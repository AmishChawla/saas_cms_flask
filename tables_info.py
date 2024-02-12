from flask_datatables import DataTables, ColumnDT

class UsersTable:
    def __init__(self):
        self.columns = [
            ColumnDT('id', label='Sr. No.'),
            ColumnDT('id', label='User ID'),
            ColumnDT('username', label='Name'),
            ColumnDT('email', label='Email'),
            ColumnDT('role', label='Role'),
            ColumnDT('created_datetime', label='Creation Date'),
            ColumnDT('status', label='Status'),
            ColumnDT('action', label='Action')
        ]