-- Run in Visual Studio: SQL Server Object Explorer -> (localdb)\mssqllocaldb -> Databases -> AceJobAgencyDB -> Right-click -> New Query
-- Then execute (Ctrl+Shift+E). Creates UserPasswordHistory for "cannot reuse last 2 passwords" feature.

USE AceJobAgencyDB;
GO

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.UserPasswordHistories') AND type in (N'U'))
BEGIN
    CREATE TABLE dbo.UserPasswordHistories (
        Id int NOT NULL IDENTITY(1,1) PRIMARY KEY,
        UserId nvarchar(450) NOT NULL,
        PasswordHash nvarchar(max) NOT NULL,
        CreatedAtUtc datetime2 NOT NULL
    );

    CREATE INDEX IX_UserPasswordHistories_UserId ON dbo.UserPasswordHistories(UserId);

    PRINT 'UserPasswordHistories table created.';
END
ELSE
    PRINT 'UserPasswordHistories table already exists.';
GO
