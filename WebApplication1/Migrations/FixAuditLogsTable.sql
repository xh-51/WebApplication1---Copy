-- Run this in SQL Server Object Explorer: right-click AceJobAgencyDB -> New Query
-- Use database: AceJobAgencyDB (check dropdown at top of query window)

USE AceJobAgencyDB;
GO

-- Drop existing AuditLogs table if it has wrong schema
IF OBJECT_ID('dbo.AuditLogs', 'U') IS NOT NULL
    DROP TABLE dbo.AuditLogs;
GO

-- Create AuditLogs without foreign key (works even if AspNetUsers missing or in different state)
CREATE TABLE dbo.AuditLogs (
    Id int NOT NULL IDENTITY(1,1) PRIMARY KEY,
    UserId nvarchar(450) NOT NULL,
    UserEmail nvarchar(max) NOT NULL,
    [Action] nvarchar(50) NOT NULL,
    Description nvarchar(500) NULL,
    IpAddress nvarchar(max) NOT NULL,
    UserAgent nvarchar(500) NULL,
    SessionId nvarchar(100) NULL,
    Timestamp datetime2 NOT NULL
);
GO

CREATE INDEX IX_AuditLogs_UserId ON AuditLogs(UserId);
CREATE INDEX IX_AuditLogs_SessionId ON AuditLogs(SessionId);
CREATE INDEX IX_AuditLogs_Timestamp ON AuditLogs(Timestamp);
GO
